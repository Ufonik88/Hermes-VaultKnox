# VaultKnox Development Roadmap

**Author:** Entropy (via Hermes Agent)  
**Date:** 2026-04-24  
**Context:** Code review commissioned by Ufonik for GitHub Copilot implementation

---

## Executive Summary

VaultKnox is an alpha-stage encrypted secrets vault for Hermes Agent. It provides AES-256-GCM encryption with Argon2id key derivation, SQLite-backed storage, masked secret references, one-time tokens, and an audit log — all protecting plaintext secrets from ever appearing in chat logs or memory files.

**Current state (v0.1.0 alpha):** Core vault operations work correctly. Security posture is reasonable for personal use. The critical gaps are in operational robustness (SQLite crash safety, atomicity), developer experience (CLI ergonomics), and Hermes integration depth.

---

## Recommended Improvements

### Category 1 — Security Hardening

---

#### P0-1: Fix `zeroize()` — CPython Memory Exposure

**Description:**  
The `zeroize()` function in `core.py` writes `0` into each `bytearray` index, but CPython's string interning and memory allocator mean the underlying UTF-8 byte buffers for decrypted plaintext are not reliably cleared from heap memory. CPython's `bytearray` indexing modifies the object but does not guarantee the allocator returns zeroed memory to the OS or that the memory is reclaimed in a zeroed state.

**Technical Details:**  
Current implementation:
```python
def zeroize(buffer: bytearray) -> None:
    for index in range(len(buffer)):
        buffer[index] = 0
```
This only modifies the byte values in the Python object. CPython may have already copied these bytes to internal malloc'd buffers. On CPython 3.11+, `bytearray` does zero-fill on allocation, but `memoryview` slices, `bytes` objects created from `bytearray`, and substrings captured by the JSON decoder can all hold references to the original heap memory beyond the lifetime of the `bytearray` object.

**Implementation:**  
Replace with a proper memory-secured buffer using `ctypes` to force overwrite of the underlying C memory:

```python
import ctypes

def zeroize(buffer: bytearray) -> None:
    """Overwrite the underlying C memory to prevent residual data."""
    length = len(buffer)
    ctypes.memset(ctypes.addressof(ctypes.c_char.from_buffer(buffer)), 0, length)
    for index in range(length):
        buffer[index] = 0
```

Additionally, after `decrypt_payload()` returns, explicitly zero the plaintext `bytearray` reference before passing it to `json.loads()`. Consider using `ctypes` to wipe memory before Python's GC can retain references.

**Dependencies:** `ctypes` (stdlib only)  
**Complexity:** Low  
**Priority:** P0 (memory exposure is the most severe current flaw)

---

#### P0-2: Enable SQLite WAL Mode + Integrity Pragmas

**Description:**  
The `VaultDatabase` opens SQLite connections without any durability or safety pragmas. Without WAL mode, SQLite uses a rollback journal that can be corrupted on unclean shutdown. Without `PRAGMA integrity_check`, silent page-level corruption can go undetected. Without `PRAGMA secure_delete`, deleted rows leave residual data on disk.

**Technical Details:**  
In `db.py`, `connection()` should enable:
```python
conn.execute("PRAGMA journal_mode = WAL")
conn.execute("PRAGMA synchronous = NORMAL")
conn.execute("PRAGMA foreign_keys = ON")
conn.execute("PRAGMA integrity_check")
conn.execute("PRAGMA secure_delete = ON")
```
WAL mode prevents corruption from unclean exits and improves concurrent read performance.

**Dependencies:** None (SQLite built-in)  
**Complexity:** Low (1 file, add 4 lines in `connection()`)  
**Priority:** P0 (silent data corruption is unacceptable for a secrets vault)

---

#### P1-3: Token Revocation List

**Description:**  
The current token system issues single-use tokens but has no revocation mechanism. If a token's TTL is 300 seconds and the consumer crashes or the token is intercepted mid-flight, the token remains valid for its full lifetime. A revocation list stored in the DB allows immediate invalidation.

**Technical Details:**  
Add a `vault_tokens_revoked` table:
```sql
CREATE TABLE vault_tokens_revoked (
    token TEXT PRIMARY KEY,
    revoked_at TEXT NOT NULL,
    reason TEXT
);
```
On `consume_token()`, check the revoked list first. Add a `revoke_token(password, token)` method and CLI command. This is a DB migration — version the schema.

**Dependencies:** None  
**Complexity:** Medium (DB migration + new method + CLI command + test)  
**Priority:** P1

---

#### P1-4: Backup Encryption Uses Separate KDF Chain

**Description:**  
In `export_vault()`, the backup is encrypted with `derive_master_key(password, backup_salt)` scoped to `vaultknox-backup`, not the vault's actual master key. This means the backup's security is functionally independent of the vault's key — if the vault's Argon2 salt/params are compromised, the backup still requires a separate brute-force attack. However, this also means changing the vault password does NOT re-encrypt backups — old backups remain decryptable with the old password. This is arguably a feature, but it's not documented.

**Implementation:**  
1. Document this behavior clearly in the backup documentation.
2. Optionally add a `backup_key_derivation` config option to allow users to choose between:
   - `independent` (current): separate salt, brute-forceable independently
   - `derived`: derive backup key from vault's master key (changing password invalidates old backups)

Document the security trade-off explicitly.

**Dependencies:** None  
**Complexity:** Low  
**Priority:** P1

---

#### P2-5: Hermes Tool — Eliminate Password from Call Traces

**Description:**  
In `hermes_tool.py`, actions like `add`, `update`, and `delete` pass `kwargs["master_password"]` directly to vault methods. If Hermes Agent logs tool calls at DEBUG level or if the agent loop emits trace output, the password can appear in logs. The `allow_write` gate reduces risk but doesn't eliminate it.

**Technical Details:**  
Refactor so the password is NEVER passed through kwargs. Instead:
1. The vault session (unlocked via `unlock()`) creates a short-lived session key stored in the session store, protected by the session file permissions.
2. Write operations during an unlocked session use the session key directly — no password needed after unlock.
3. The Hermes tool's `add`/`update`/`delete` actions check `vault.sessions.is_unlocked()` and use the in-session key material instead of requiring the password each time.

This requires a session-key derivation path in `core.py` or `session.py` that write operations can use without re-verifying the password.

**Dependencies:** Session redesign  
**Complexity:** Medium  
**Priority:** P2

---

### Category 2 — Operational Robustness

---

#### P1-6: Atomic Audit Log Rotation

**Description:**  
In `audit.py`, `_rotate_audit_log_if_needed()` renames files sequentially (`audit.log → audit.log.1`, `audit.log.1 → audit.log.2`, etc.). This is a multi-step non-atomic operation — if the process is killed mid-rotation, the log chain can be left in a corrupted state. The rename operations are not coordinated.

**Technical Details:**  
Replace with atomic rename using `os.replace()` (guaranteed atomic on POSIX) and rotate in a single pass using a temporary sentinel file:

```python
def _rotate_audit_log_if_needed(audit_log_path: Path) -> None:
    if not audit_log_path.exists():
        return
    if audit_log_path.stat().st_size < AUDIT_MAX_BYTES:
        return

    # Remove oldest backup atomically
    oldest = audit_log_path.with_name(f"{audit_log_path.name}.{AUDIT_MAX_BACKUPS}")
    if oldest.exists():
        oldest.unlink()

    # Rotate chain using atomic os.replace
    for i in range(AUDIT_MAX_BACKUPS - 1, 0, -1):
        src = audit_log_path.with_name(f"{audit_log_path.name}.{i}")
        dst = audit_log_path.with_name(f"{audit_log_path.name}.{i + 1}")
        if src.exists():
            os.replace(src, dst)  # atomic on POSIX

    # Rename current log atomically
    new_log = audit_log_path.with_name(f"{audit_log_path.name}.1")
    os.replace(audit_log_path, new_log)

    # Create new empty log
    audit_log_path.touch()
    os.chmod(audit_log_path, 0o600)
```

Note: `os.replace()` is atomic for single-file renames within the same filesystem.

**Dependencies:** None  
**Complexity:** Low (rewrite 1 function)  
**Priority:** P1

---

#### P2-7: Session Advisory Lock → Mandatory Lock + Stale Lock Detection

**Description:**  
`session.py` uses `fcntl.flock()` for advisory locking only. A process crash leaves the session file locked indefinitely, but since locking is advisory, other processes can still read/write the session file, defeating the purpose. Additionally, if the vault is unlocked and the process crashes, the session file remains on disk with the expiry time — a restart can re-read the same session file and incorrectly believe the vault is still unlocked.

**Technical Details:**  
1. **Stale lock detection:** When `is_unlocked()` reads the session file, check if the expiry has passed. If the session file exists but is expired, clear it. This is already implemented (line 64 in `session.py`), but only if `is_unlocked()` is called. The issue is the session file persists across crashes.

2. **Mandatory lock file:** Use `fcntl.LOCK_EX | LOCK_NB` on the lock file when writing the session, and verify the lock is held when reading. On Linux, `fcntl.flock()` advisory locks are sufficient for single-user local scenarios.

3. **Process PID binding:** Write the PID to the session file and verify the process is still alive when reading the session (on Unix: `os.kill(pid, 0)`). If the PID is gone, clear the session.

**Dependencies:** None  
**Complexity:** Medium (add PID verification + optional mandatory lock)  
**Priority:** P2

---

#### P2-8: Vault Password Strength Meter + Validator

**Description:**  
`initialize()` and `change_password()` accept any non-empty password. Weak passwords undermine the Argon2id cost model. An interactive strength meter (reachable via CLI) and a configurable minimum entropy threshold would improve the security baseline.

**Technical Details:**  
Add a `validate_password_strength(password: str) -> tuple[bool, str]` function that:
- Checks minimum length (recommend 12+ characters)
- Estimates entropy based on character class coverage (lowercase, uppercase, digits, symbols)
- Rejects entropy below a configurable threshold (default: ~40 bits)
- Returns `(passed, reason)` tuple

Integrate into `initialize()` and `change_password()`. Add a `--no-password-check` CLI flag for automation use cases.

**Dependencies:** None (can estimate entropy without external libs)  
**Complexity:** Low  
**Priority:** P2

---

#### P2-9: WAL Checkpoint + DB Vacuum Cron ✅ COMPLETED (2026-04-25)

**Description:**  
SQLite's WAL mode accumulates `.db-wal` and `.db-shm` files that grow over time. Without periodic `VACUUM`, the main `.db` file retains deleted row pages. No automatic checkpoint/vacuum is triggered.

**Implemented:**
- `db.vacuum()` method runs `PRAGMA wal_checkpoint(TRUNCATE)` then `VACUUM` outside any transaction
- CLI: `vaultknox vacuum` — reports before/after byte size
- Idempotent `ALTER TABLE` migration for `expires_at` column

**Technical Details:**  
Note: `PRAGMA wal_checkpoint(TRUNCATE)` must run outside a transaction (SQLite requires exclusive access). Current implementation opens a dedicated connection for the checkpoint and vacuum operations.

**Bugs found (to fix):**
- `vacuum` CLI command does not require password authentication — inconsistent with other mutating commands
- WAL checkpoint runs inside `self.connection()` context which wraps it in a transaction; may silently fall back to passive mode instead of truncating — should open a dedicated connection for the checkpoint

**Dependencies:** None  
**Complexity:** Low  
**Priority:** P2

---

### Category 3 — Developer Experience

---

#### P1-10: CLI — Interactive Add/Update Prompts

**Description:**  
The current `vaultknox add` requires `--data '{"key":"value"}'` as a single JSON blob on the command line. This is error-prone, requires shell escaping, and forces the user to remember the JSON structure for each secret type.

**Technical Details:**  
Add an interactive mode when `--data` is omitted:
```bash
vaultknox add --id my_api_key --type api_key --label "My API Key"
```
Prompts for each required field based on secret type:
```
service: openai
key: ••••••••••••••••
scope (optional): 
```
Uses `click.prompt()` with `hide_input=True` for `key` and `password` fields.

Same for `update` — pre-fill current values as defaults.

**Dependencies:** `click` (already in deps)  
**Complexity:** Low-Medium  
**Priority:** P1

---

#### P2-11: CLI — Bulk Import from JSON/YAML File ✅ COMPLETED (2026-04-25)

**Description:**
Adding many secrets via repeated CLI calls is tedious. A `vaultknox bulk-import` command that reads a YAML or JSON file of secrets and imports them in one transaction would dramatically improve onboarding.

**Implemented:**
- `vaultknox bulk-import --file secrets.yaml` command
- Auto-detects format from `.yaml`/`.yml` vs `.json` extension, overridable via `--format`
- Fail-fast validation: all entries validated before any writes
- Duplicate IDs silently skipped (reported as `skipped` in result)
- `pyyaml` added as runtime dependency

**Note:** Duplicate handling (silent skip) is a design choice — caller gets `{"imported": [...], "skipped": [...]}` so it's observable, but no warning is emitted for duplicates.

**Dependencies:** `pyyaml` (added)  
**Complexity:** Medium  
**Priority:** P2

---

#### P2-12: Secret Type — `connection_string` First-Class Support ✅ COMPLETED (2026-04-25)

**Description:**
Databases, message queues, and Redis all use connection strings. Currently these would have to go into a `note` type with no structured validation. A `connection_string` type with regex-based URI parsing validates and safely stores connection strings.

**Implemented:**
- `connection_string` added to `ALLOWED_TYPES`
- Validator: requires `value` field, parses with `urllib.parse.urlsplit`, scheme must be in allowlist (`postgresql`, `postgres`, `mysql`, `mongodb`, `redis`, `amqp`, `sqlite`, `mssql`, `mariadb`), host required unless scheme is `sqlite`
- Metadata stores: `scheme`, `host`, `port`, `has_credentials` — never the password
- Interactive CLI prompts with `hide_input=True` for the connection string value

**Bug found (to fix):**
- `has_credentials` uses `bool(parsed.username)` — returns `True` even for `postgresql://user:@host/db` (empty password). Should be `bool(parsed.username and parsed.password)`.

**Dependencies:** None
**Complexity:** Low
**Priority:** P2

---

#### P2-13: Configurable KDF Parameters via CLI

**Description:**  
KDF params (time_cost, memory_cost, parallelism) are hardcoded in `core.py`'s `DEFAULT_KDF_PARAMS`. Advanced users may want higher memory/cost for stronger protection at the expense of unlock latency.

**Technical Details:**  
Add to `initialize()`:
```python
@click.option("--kdf-memory-mb", default=64, show_default=True, type=int)
@click.option("--kdf-time-cost", default=3, show_default=True, type=int)
@click.option("--kdf-parallelism", default=4, show_default=True, type=int)
```
Store in `vault_config` as `kdf_params`. Read in `derive_master_key()` and `_verify_password()`.

**Dependencies:** None  
**Complexity:** Low  
**Priority:** P2

---

### Category 4 — Feature Gaps

---

#### P0-14: Vault → Environment Variable Auto-Injection

**Description:**  
This was the original motivation for VaultKnox — Hermes needs API keys as environment variables at runtime, but they must not appear in `.env` or config files in plaintext. VaultKnox currently stores secrets but cannot inject them into the running process's environment.

**Technical Details:**  
Add a `vault.inject_to_env(secret_id, env_var_name)` method:
1. Retrieves the decrypted secret using the unlocked session key
2. Sets `os.environ[env_var_name] = value`
3. Optionally registers a `atexit` handler to clear the variable on exit
4. Logs the injection event (not the value)

```python
import os
import atexit

def inject_to_env(self, password: str, secret_id: str, env_var: str) -> dict[str, Any]:
    secret = self.get_secret(password, secret_id)
    os.environ[env_var] = secret["payload"]["key"]
    atexit.register(lambda: os.environ.pop(env_var, None))
    write_audit_event(self.paths.audit_log_path, "inject_env", "success", 
                      secret_id=secret_id, details={"env_var": env_var})
    return {"injected": env_var}
```

For `credential` type: `payload["password"]` → `os.environ[env_var]`.

**Dependencies:** None  
**Complexity:** Low  
**Priority:** P0 (core use case)

---

#### P1-15: Encrypted Search — Query by Metadata Fields

**Description:**  
VaultKnox stores secrets as fully encrypted blobs. Listing secrets requires a full vault unlock. There is no ability to search secrets by label, type, or metadata fields (e.g., "find my Redis credentials") without decrypting everything.

**Technical Details:**  
This is architecturally difficult because encrypted search requires deterministic or order-preserving encryption, which is incompatible with the current AEAD model. Options:

**Option A (Recommended):** Encrypted search index
- Maintain a separate `search_index` table with rows: `(secret_id, encrypted_label, encrypted_type_tag)`
- The label is encrypted with a dedicated search key derived from the master key
- Search: encrypt the query term with the search key, do a prefix/equality match in the index
- Only decrypt `secret_id` for matches, then decrypt full secret
- Trade-off: search index reveals search patterns (how many secrets match "bank")

**Option B:** Encrypted Bloom filter
- Each secret gets a Bloom filter of its metadata keywords (encrypted)
- Probabilistic search — may have false positives
- Privacy-preserving (no deterministic leakage)

**Dependencies:** `cryptography` (already in deps)  
**Complexity:** High  
**Priority:** P1

---

#### P1-16: Secret Expiry / TTL ✅ COMPLETED (2026-04-25)

**Description:**
API keys, certificates, and tokens expire. Currently there's no way to track when a secret becomes stale. Secrets should optionally carry an expiry date, and the vault should surface warnings when retrieving expired secrets.

**Implemented:**
- `expires_at` nullable TEXT column added to `secrets` table via idempotent `ALTER TABLE` migration
- `add_secret` and `update_secret` accept `expires_at` param (ISO 8601 format)
- `get_secret` and `get_masked` return `{"expired": true, "expires_at": "..."}` and block payload return for expired secrets
- CLI: `vaultknox list --expired` filters secrets where `expires_at <= now` (timezone-aware)
- Audit events fire on expired secret access

**Bug found (to fix):**
- No validation that `expires_at` is a future date at entry time — past dates are accepted silently and immediately treated as expired

**Dependencies:** None
**Complexity:** Medium
**Priority:** P1

---

#### P2-17: Multiple Vault Profiles

**Description:**  
Currently only one vault at `~/.hermes/vaultknox`. Power users may want separate vaults for work/personal or for different projects.

**Technical Details:**  
Support named profiles:
```bash
vaultknox --profile work init
vaultknox --profile personal init
vaultknox --profile work add ...
```
Store at `~/.hermes/vaultknox.<profile>/`. Default profile is `default` (no suffix). Config stored in `~/.hermes/vaultknox.<profile>/config.json`.

**Dependencies:** None  
**Complexity:** Medium  
**Priority:** P2

---

#### P2-18: Secret Sharing — Encrypted Export of Individual Secrets

**Description:**  
Users may want to share a single secret (e.g., a team API key) without exposing the entire vault. An "export secret" feature exports one secret as an encrypted blob readable by a password-derived key, suitable for sending via email or chat.

**Technical Details:**  
Add `export_secret(password, secret_id, export_file)`:
1. Derive a share key from the password using a fresh salt and `vaultknox-share` context
2. Encrypt the full secret payload with the share key
3. Write: `{version: 1, salt, nonce, ciphertext, metadata}` (metadata is the plain masked view — safe to share)
4. Share recipient: `vaultknox import-secret --file share.vault --password <password>`

Does NOT touch the vault DB — creates a standalone `.vlt` file.

**Dependencies:** None  
**Complexity:** Medium  
**Priority:** P2

---

#### P2-19: `credential` Type — Accept Raw String, Not Just Structured JSON ✅ COMPLETED (2026-04-25)

**Description:**
Currently the `credential` type requires `{username, password}` structure. When storing a simple password (e.g., a server SSH key passphrase) with no username, there's no appropriate type. A `password` type accepting a plain string closes this gap.

**Implemented:**
- `password` added to `ALLOWED_TYPES`
- Payload: `{value: str}` — simple key-value, no structure required
- Metadata: `{}` (empty — no hints, no last4, nothing)
- Validator: requires `value` to be a non-empty string
- Interactive CLI prompt with `hide_input=True`

**Dependencies:** None
**Complexity:** Low
**Priority:** P2

---

### Category 5 — Hermes Integration

---

#### P0-20: Hermes Tool — Password Never in Kwarg

**Description:** (Same as P0-5, Hermes-specific framing)

**Technical Details:**  
Refactor `vault_tool()` so write actions don't require the master password in kwargs. After a successful `unlock()` call:
1. Vault session is valid for `auto_lock_minutes`
2. All subsequent calls (read and write) check `vault.sessions.is_unlocked()` — if True, the session key is used implicitly
3. If the session has expired, return error `"Vault is locked. Run unlock first."`

Remove `master_password` parameter from `add`, `update`, `delete` in the Hermes tool entirely.

**Dependencies:** Session redesign (see P0-5)  
**Complexity:** Medium  
**Priority:** P0

---

#### P1-21: Hermes — `consume_token` Action

**Description:**  
The `consume_token` action exists in `vault.py` but is not exposed through `hermes_tool.py`. Automations that receive a one-time token cannot currently exchange it for the raw secret through the Hermes tool.

**Technical Details:**  
Add to `vault_tool()`:
```python
if action == "consume_token":
    return vault.consume_token(kwargs["master_password"], kwargs["token"])
```
After adding P0-20, remove `master_password` requirement here too.

**Dependencies:** None  
**Complexity:** Low  
**Priority:** P1

---

#### P2-22: Hermes — Secret Access Audit in Tool

**Description:**  
Currently `hermes_tool.py` does not log tool-level access events. When Hermes calls `vault_tool("get_masked", ...)`, there is no corresponding audit entry in the vault's audit log. The vault's own methods log events, but the Hermes tool wrapper acts as a pass-through without its own audit trail.

**Technical Details:**  
In `vault_tool()`, add a thin audit wrapper:
```python
write_audit_event(expand_runtime_path(runtime_dir).audit_log_path, f"tool_{action}", status, ...)
```
This creates a unified audit log of all Hermes tool invocations, giving operators visibility into which secrets Hermes accessed and when.

**Dependencies:** None  
**Complexity:** Low  
**Priority:** P2

---

### Category 6 — Testing & CI

---

#### P1-23: Property-Based Testing for Crypto Operations

**Description:**  
The current test suite (`tests/test_vault.py`) uses deterministic inputs. Property-based testing (via `hypothesis`) would find edge cases: non-ASCII passwords, empty strings, max-length secrets, unicode in labels, zero-length nonces (should never happen but confirms the implementation rejects it), etc.

**Technical Details:**  
Add `hypothesis` to dev dependencies:
```python
from hypothesis import given, strategies as st

@given(password=st.text(min_size=1), salt=st.binary(min_size=16, max_size=32))
def test_derive_master_key_deterministic(password, salt):
    key1 = derive_master_key(password, salt)
    key2 = derive_master_key(password, salt)
    assert key1 == key2

@given(password=st.text(), salt=st.binary(min_size=16, max_size=32))
def test_different_salts_different_keys(password, salt):
    key1 = derive_master_key(password, salt)
    key2 = derive_master_key(password, bytes([b ^ 0xFF for b in salt]))
    assert key1 != key2
```

**Dependencies:** `hypothesis` (dev)  
**Complexity:** Low  
**Priority:** P1

---

#### P2-24: GitHub Actions CI — Lint + Test + Security Scan

**Description:**  
The repo has no CI pipeline. Every PR should run ruff lint, pytest, and a basic security scan.

**Technical Details:**  
Add `.github/workflows/ci.yml`:
```yaml
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: {python-version: "3.12"}
      - run: pip install -e .[dev]
      - run: ruff check .
      - run: PYTHONPATH=src python -m pytest -q
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pypa/pip-audit@latest
        with: {pip_audit_requirements: "pyproject.toml"}
```

**Dependencies:** GitHub Actions (free for open repos)  
**Complexity:** Low  
**Priority:** P2

---

## Implementation Order

### Phase 1 — Critical Security & Data Safety (Do First)
1. **P0-1** — Fix zeroize (memory exposure)
2. **P0-2** — Enable SQLite WAL + pragmas (corruption prevention)
3. **P0-14** — Vault → env auto-injection (core use case)
4. **P0-20** — Hermes tool: remove password from kwargs (operational safety)

### Phase 2 — Operational Hardening (Do Before Production Use)
5. **P1-6** — Atomic audit log rotation
6. **P1-3** — Token revocation list
7. **P1-10** — CLI interactive add/update
8. **P1-21** — Hermes `consume_token` action
9. **P1-23** — Property-based testing

### Phase 3 — Feature Completeness
10. **P1-16** — Secret expiry/TTL
11. **P1-15** — Encrypted search
12. **P2-11** — Bulk import from YAML
13. **P2-12** — `connection_string` secret type
14. **P2-18** — Secret sharing (individual export)
15. **P2-24** — GitHub Actions CI

### Phase 4 — polish & Hardening
16. **P2-7** — Session stale lock detection
17. **P2-8** — Password strength validator
18. **P2-9** — WAL checkpoint + vacuum
19. **P2-13** — Configurable KDF params
20. **P2-17** — Multiple vault profiles
21. **P2-22** — Hermes tool audit wrapper
22. **P2-4** — Backup KDF documentation
23. **P2-19** — `password` type (raw string)

---

## Summary Table

| ID | Title | Complexity | Priority |
|----|-------|-----------|----------|
| P0-1 | Fix `zeroize()` CPython memory exposure | Low | P0 |
| P0-2 | Enable SQLite WAL mode + safety pragmas | Low | P0 |
| P0-14 | Vault → env auto-injection | Low | P0 |
| P0-20 | Hermes tool: remove password from kwargs | Medium | P0 |
| P1-3 | Token revocation list | Medium | P1 |
| P1-6 | Atomic audit log rotation | Low | P1 |
| P1-10 | CLI interactive add/update prompts | Low-Medium | P1 |
| P1-15 | Encrypted search index | High | P1 |
| P1-16 | Secret expiry/TTL | Medium | P1 |
| P1-21 | Hermes `consume_token` action | Low | P1 |
| P1-23 | Property-based testing (hypothesis) | Low | P1 |
| P2-4 | Backup KDF behavior documentation | Low | P2 |
| P2-5 | Hermes tool: eliminate password trace | Medium | P2 |
| P2-7 | Session stale lock detection | Medium | P2 |
| P2-8 | Password strength validator | Low | P2 |
| P2-9 | WAL checkpoint + vacuum | Low | P2 |
| P2-11 | Bulk import from YAML | Medium | P2 |
| P2-12 | `connection_string` type | Low | P2 |
| P2-13 | Configurable KDF parameters | Low | P2 |
| P2-17 | Multiple vault profiles | Medium | P2 |
| P2-18 | Individual secret sharing export | Medium | P2 |
| P2-19 | `password` type (raw string) | Low | P2 |
| P2-22 | Hermes tool audit wrapper | Low | P2 |
| P2-24 | GitHub Actions CI | Low | P2 |
