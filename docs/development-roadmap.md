# VaultKnox Development Roadmap

> **Status:** Alpha — Not yet intended for audited production deployment
> **Author:** Ufonik
> **Audience:** Development team using GitHub Copilot

This document is a living development roadmap for VaultKnox. Each improvement is categorised, prioritised, and structured so you can pick one up and start building. Items within the same priority tier are unordered.

---

## Priority Tiers

| Tier | Label | Meaning |
|------|-------|---------|
| P0 | Security | Must-fix before any production use |
| P1 | Correctness | Real bugs or data-loss risks |
| P2 | Reliability | Hardening against edge cases |
| P3 | Developer Experience | Tooling, ergonomics, API polish |
| P4 | Future | Non-blocking enhancements |

---

## P0 — Security

### VK-001: `zeroize` provides no meaningful memory protection in CPython

**Description**

`core.zeroize()` zeroes a `bytearray`'s contents in-place:

```python
def zeroize(buffer: bytearray) -> None:
    for index in range(len(buffer)):
        buffer[index] = 0
```

CPython's memory allocator keeps the underlying buffer alive after the bytearray goes out of scope. Python's garbage collector may also have copied the data elsewhere. Zeroing the buffer in CPython is effectively cosmetic — an attacker with a process dump or ColdBoot attack can recover the data regardless.

**Why it matters**

If an attacker can read a Hermes process core dump or do memory forensics on a locked vault, plaintext secrets could be recovered even after `decrypt_payload` returns.

**Implementation approach**

Real memory zeroing in Python requires either `ctypes` + `libc.msyclear` (POSIX `mlock` equivalent) or keeping plaintext in a `ctypes` array and calling the platform memset directly. This is the approach used by serious crypto libs (keyring, keepassxc).

A pragmatic, partial mitigation is to use `secrets.compare_digest` for the verifier check so timing side-channels don't leak password equality — but this doesn't address the memory image problem.

**Recommended fix**

Create a `src/vaultknox/_memory.py` module:

```python
import ctypes, ctypes.util, os

_libc = ctypes.CDLL(ctypes.util.find_library("c"))

def secure_zero(ctypes_array: ctypes.Array) -> None:
    """Zero a ctypes array in a way the compiler won't elide."""
    memset = _libc.memset
    memset.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_size_t]
    memset(ctypes_array, 0, ctypes.sizeof(ctypes_array))

# For the argon2 / AES payloads — keep plaintext in ctypes buffers
# only for the brief window between decrypt and use.
```

This is the minimum defensible approach. Full memory locking (`mlock`) requires `os.setpdeathsig` and POSIX — add it only where available.

**Dependencies:** `ctypes` (stdlib)
**Complexity:** Low — ~30 lines

---

### VK-002: No protection against offline master-password enumeration

**Description**

`derive_master_key` uses Argon2id (good), but the KDF parameters are hardcoded in `core.py`:

```python
DEFAULT_KDF_PARAMS = {
    "time_cost": 3,
    "memory_cost": 65536,  # 64 MiB
    "parallelism": 4,
    ...
}
```

These parameters are fixed. An attacker who steals a copy of `secrets.db` can mount an offline dictionary attack. With a modern GPU (RTX 4090), Argon2id at 64 MiB runs at ~0.3 kH/s per GPU — slow but not infeasible for weak passwords.

**Why it matters**

If the vault database is ever exfiltrated (backup file left on a USB drive, stolen disk image, etc.), weak master passwords can be cracked.

**Implementation approach**

Three layers of defence:

1. **Expose KDF params in `initialize()`** so operators can set higher costs. Default should remain the same for UX but be documented.
2. **Argon2id cost estimator** — on first init, run a benchmark and auto-tune `time_cost` so one KDF derivation takes ≥0.5s on the host CPU. This makes GPU-based cracking significantly less effective.
3. **Argon2id p=3 (three separate hashes)** is the correct profile for a password verifier — already correct in code.

Add to `vault.py`:

```python
def _benchmark_kdf(target_seconds: float = 0.5) -> dict[str, int]:
    """Auto-tune KDF params so one derivation hits target_seconds."""
    import time
    for time_cost in range(1, 10):
        start = time.perf_counter()
        derive_master_key("benchmark", generate_salt(), {"time_cost": time_cost, "memory_cost": 65536, "parallelism": 4})
        elapsed = time.perf_counter() - start
        if elapsed >= target_seconds:
            return {"time_cost": time_cost}
    return {"time_cost": 3}
```

**Dependencies:** None (uses existing `derive_master_key`)
**Complexity:** Medium — requires testing across hardware

---

### VK-003: No integrity protection for individual stored secrets

**Description**

Each secret's ciphertext+tag is stored directly in the `secrets` table. If an attacker with write access to `secrets.db` (but without the master key) modifies a ciphertext block, decryption will fail — but there is no mechanism to detect whether the failure is due to corruption or deliberate tampering, nor any HMAC over the stored record.

The `audit.log` is not cryptographically integrity-protected either — a root-level attacker could delete or modify audit entries.

**Why it matters**

VaultKnox's threat model explicitly acknowledges "casual disk access" as a risk. An attacker who can write to the SQLite file could selectively corrupt secrets without the operator noticing.

**Implementation approach**

Store a per-secret HMAC-SHA256 alongside `ciphertext`, `nonce`, `tag` in the `secrets` table. The HMAC key is derived from the entry key + secret ID, making each record independently verifiable:

```python
# In vault.py add_secret / update_secret
hmac_key = derive_scoped_key(entry_key, secret_id.encode())
record_mac = hmac.new(hmac_key, ciphertext + nonce, hashlib.sha256).hexdigest()
self.db.insert_secret(..., mac=record_mac)
```

On `get_secret`, recompute and compare. This adds ~32 bytes per secret and one HKDF derivation per read — negligible cost.

For the audit log, append-only HMAC chain (like a simple blockchain) prevents retroactive entry deletion. Each entry's HMAC covers the previous entry's HMAC, forming a chain. Truncate detection is trivial (chain break = tampering).

**Dependencies:** `hmac`, `hashlib` (stdlib)
**Complexity:** Medium — requires DB migration (add column)

---

## P1 — Correctness

### VK-004: `add_secret` does not check for duplicate IDs before attempting insert

**Description**

`db.insert_secret` will raise `sqlite3.IntegrityError` ("UNIQUE constraint failed") if a secret with the same ID already exists. The `vault.add_secret` method does not catch this — the error propagates as an opaque SQLite exception rather than a user-friendly message.

**Why it matters**

Operator attempts to `add` a secret that already exists fail with a raw database error. No distinction between "secret already exists" and "something went wrong."

**Implementation approach**

In `db.py`, wrap the insert in a check:

```python
def insert_secret(self, ...):
    existing = self.get_secret_row(secret_id)  # raises KeyError if not found
    if existing:
        raise KeyError(f"Secret already exists: {secret_id}")
    ...
```

Or catch the `IntegrityError` in `vault.py` and re-raise as `VaultError(f"Secret already exists: {secret_id}")`.

**Dependencies:** None
**Complexity:** Low

---

### VK-005: `consume_token` returns the full plaintext secret to the caller

**Description**

`consume_token` is the only operation that decrypts and returns the full secret payload (not just a masked view). This is by design for automation use cases — but the returned dict is a live Python object in memory. Any logging, error tracing, or accidental stringification of this object could dump the plaintext.

**Why it matters**

If Hermes is running with verbose logging, a crash dump, or a memory profiler attached, the plaintext secret could appear in logs or a core file.

**Implementation approach**

1. Log the `consume_token` event in audit BEFORE decrypting, with a note that the secret was returned (without the value).
2. Document clearly that `consume_token` is for machine-to-machine automation only and should never be called in a context where the result could be logged.
3. Consider adding a `consume_token_masked` that returns a one-time decrypted view valid for a short window (e.g., 60 seconds), after which the in-memory copy is zeroed. This would require VK-001 (secure zeroize) first.

**Dependencies:** VK-001 (secure memory zeroing)
**Complexity:** Low (logging) / Medium (masked window)

---

### VK-006: `change_password` loads all secrets into process memory unencrypted

**Description**

`vault.change_password` decrypts every secret with the old key, then re-encrypts with the new key. During this window, every secret's plaintext exists in a Python list:

```python
decrypted_payloads: list[tuple[str, str, dict[str, Any]]] = []
for row in rows:
    payload = decrypt_payload(old_key, EncryptedPayload(...))
    decrypted_payloads.append((row["id"], row["type"], payload))
```

For an operator with 100 secrets, all plaintexts are in memory simultaneously. The list is then iterated to re-encrypt and the list reference goes out of scope — but not zeroed.

**Why it matters**

Same root cause as VK-001. Until secure zeroize is in place, `change_password` is the highest-risk operation because it creates the largest in-memory plaintext corpus.

**Implementation approach**

Process one secret at a time in a streaming fashion — decrypt, re-encrypt, write to DB, then discard before moving to the next. This keeps the in-memory plaintext window bounded to one secret at a time:

```python
for row in rows:
    payload = decrypt_payload(old_key, EncryptedPayload(...))
    reencrypted = encrypt_payload(new_entry_key, payload)
    metadata = build_metadata(row["type"], payload)
    self.db.update_secret_crypto(row["id"], reencrypted.ciphertext, reencrypted.nonce, reencrypted.tag, metadata)
    # payload goes out of scope here — will be GC'd (not securely zeroed yet, but window is minimal)
```

This is a one-line change in the `for` loop in `vault.py`.

**Dependencies:** None (immediate improvement), VK-001 (long-term)
**Complexity:** Low

---

## P2 — Reliability

### VK-007: No automatic expired-token cleanup

**Description**

Tokens accumulate in `vault_tokens` indefinitely. An expired, unused token row stays in the DB forever. While expired tokens are rejected at consumption time, the table grows unbounded.

**Why it matters**

Long-running vault instances accumulate dead rows. Minor issue, but indicates missing maintenance hygiene.

**Implementation approach**

Two options:

1. **Eager cleanup** — every `unlock` call runs a background cleanup deleting expired tokens. Add to `vault.unlock()`:

```python
with self.connection() as conn:
    conn.execute("DELETE FROM vault_tokens WHERE expires_at < ?", (utc_now(),))
```

2. **Lazy cleanup** — run a periodic vacuum. Add a `vacuum` CLI command and a cron note in docs.

Option 1 is simpler and costs one DELETE per unlock. Implement both.

**Dependencies:** None
**Complexity:** Low

---

### VK-008: No SQLite WAL mode — concurrent access may corrupt data

**Description**

The `VaultDatabase` uses default SQLite rollback journal mode. If two processes try to write simultaneously (e.g., two `hermes-vault` CLI invocations racing), SQLite's default journal mode can cause `SQLITE_BUSY` errors or, in rare cases, corruption. WAL mode allows concurrent reads with a single writer.

**Why it matters**

VaultKnox is designed to be accessed by both a long-running Hermes agent (the primary consumer) and occasional CLI commands. These can collide.

**Implementation approach**

Enable WAL mode and set busy timeout in `db.py`:

```python
@contextmanager
def connection(self) -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(self.db_path, timeout=10.0)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=10000")  # 10s
    ...
```

WAL mode also enables `PRAGMA synchronous=NORMAL` for better performance without sacrificing safety.

**Dependencies:** None
**Complexity:** Low — 3-line change in `db.py`

---

### VK-009: No DB integrity check command

**Description**

SQLite databases can develop corruption from crashes, disk errors, or hardware failures. VaultKnox has no command to verify DB integrity.

**Why it matters**

An operator may not know their vault DB is subtly corrupted until they try to access a specific secret and it fails.

**Implementation approach**

Add a `check` CLI command and `vault.check()` method:

```python
def check(self) -> dict[str, Any]:
    with self.connection() as conn:
        result = conn.execute("PRAGMA integrity_check").fetchone()
    return {"integrity": result[0], "ok": result[0] == "ok"}
```

Also add `PRAGMA quick_check` option for a faster scan.

**Dependencies:** None
**Complexity:** Low

---

### VK-010: Session file is not written atomically

**Description**

`SessionStore.write()` writes the session JSON directly to disk. If the process crashes or loses power between `write_text` and `os.chmod`, the file may be corrupted or partially written.

**Why it matters**

A corrupted session file could cause `is_unlocked()` to incorrectly return `False` even when the vault is legitimately unlocked, locking the user out of their own vault.

**Implementation approach**

Write to a temp file, then atomically rename:

```python
temp = self.session_path.with_suffix(".tmp")
temp.write_text(json.dumps(asdict(state), ...))
os.chmod(temp, PRIVATE_FILE_MODE)
temp.rename(self.session_path)  # atomic on POSIX
```

This requires importing `tempfile` or using a manual `.tmp` path.

**Dependencies:** `tempfile` (stdlib)
**Complexity:** Low

---

### VK-011: `import_vault` has no dry-run validation before replacing DB

**Description**

`import_vault` validates the backup integrity (HMAC check, SQLite header check) but if validation passes and `force=True`, it immediately overwrites the vault DB. If the backup is valid but from a different vault configuration, the operator has no way to preview contents before committing.

**Why it matters**

A mistaken `force` flag could wipe the current vault with no warning.

**Implementation approach**

Add a `--dry-run` / `dry_run=True` option to `import_vault`:

```python
def import_vault(self, password: str, import_file: str, force: bool = False, dry_run: bool = False) -> dict[str, Any]:
    # ... full validation first ...
    if dry_run:
        return {
            "dry_run": True,
            "secret_count": self._count_backup_secrets(decrypted_db),
            "valid": True,
        }
    if not force and self.paths.db_path.exists():
        raise VaultError("Vault already exists. Use force mode to replace.")
    ...
```

**Dependencies:** None
**Complexity:** Low

---

## P3 — Developer Experience

### VK-012: No `--json` output mode for machine consumption

**Description**

The CLI outputs human-readable formatted JSON via `click.echo(json.dumps(..., indent=2))`. For scripting and piping, `--json` flag that outputs compact single-line JSON would be more useful.

**Why it matters**

CI/CD pipelines, shell scripts, and automation tools that consume `hermes-vault` output benefit from machine-readable JSON.

**Implementation approach**

Add a `--json` flag to the root command group and propagate it via context:

```python
@main.command()
@click.option("--json", "json_output", is_flag=True, help="Output compact JSON.")
@click.pass_context
def main(ctx, json_output, runtime_dir):
    ctx.obj["json_output"] = json_output
```

Then in each command:

```python
def _echo(obj, data):
    indent = None if obj.get("json_output") else 2
    click.echo(json.dumps(data, indent=indent))
```

**Dependencies:** `click`
**Complexity:** Low

---

### VK-013: Secret IDs cannot be renamed

**Description**

There is no `rename` or `mv` command. Changing a secret's ID requires:
1. Reading the secret
2. Adding a new secret with the desired ID
3. Deleting the old secret

This is a multi-step manual process with risk of error.

**Why it matters**

Secret IDs become outdated or inconsistent with naming conventions over time. Operators need a safe rename operation.

**Implementation approach**

Add a `rename` command that:
1. Verifies the old secret exists
2. Verifies the new ID does not already exist
3. Creates a new row with the new ID and same encrypted data
4. Deletes the old row

```python
@main.command("rename")
@click.argument("old_id")
@click.argument("new_id")
@click.pass_obj
def rename(obj, old_id, new_id):
    vault = obj["vault"]
    result = vault.rename_secret(_prompt_password(), old_id, new_id)
    ...
```

**Dependencies:** None
**Complexity:** Low

---

### VK-014: No secret search / filter by label or type

**Description**

`list` returns all secrets. There is no way to filter by type (`--type card`), search by label (fuzzy match), or filter by creation date.

**Why it matters**

Operators with many secrets struggle to find specific entries.

**Implementation approach**

Extend the `list` CLI command with filter options:

```python
@main.command("list")
@click.option("--type", "secret_type", help="Filter by secret type.")
@click.option("--search", help="Fuzzy search in labels.")
@click.pass_obj
def list_command(obj, secret_type, search):
    secrets = vault.list_secrets()
    if secret_type:
        secrets = [s for s in secrets if s["type"] == secret_type]
    if search:
        secrets = [s for s in secrets if search.lower() in s["label"].lower()]
    ...
```

Also add `list_secret_rows(filter=...)` to `db.py` for SQL-level filtering when the list grows large.

**Dependencies:** None
**Complexity:** Low

---

### VK-015: No interactive TTY prompt for sensitive data (avoids shell history)

**Description**

The `add` and `update` CLI commands take `--data` as a JSON string argument. This means the secret payload appears in `ps aux`, shell history (`~/.bash_history`), and potentially `/proc/PID/cmdline`.

**Why it matters**

Anyone with access to the shell history file can extract all secret payloads that were added via CLI.

**Implementation approach**

Change `--data` to accept either a JSON string OR a `-` to read from stdin (which can be piped from `/dev/null` to avoid the argument appearing in cmdline):

```python
@click.option("--data", "data_input", required=True,
    help="Secret payload as JSON, or - to read from stdin.")
def add(obj, data_input):
    if data_input == "-":
        import sys
        data_input = sys.stdin.read()
    payload = json.loads(data_input)
```

Better yet, use `click's` `prompt` with `hide_input=True` for the full payload — but JSON makes this complex. The stdin approach is a good middle ground.

**Dependencies:** `click`
**Complexity:** Low

---

### VK-016: No verbose / debug mode

**Description**

CLI commands produce no output on success (besides the result JSON). If something goes wrong, the operator has no way to diagnose what happened without reading source code.

**Why it matters**

During development and debugging, operators need to understand whether the vault is initialized, whether the session is active, what the session expiry time is, etc.

**Implementation approach**

Add `--verbose` / `-v` flag:

```python
@main.command()
@click.option("-v", "--verbose", is_flag=True)
@click.pass_obj
def status(obj, verbose):
    vault = obj["vault"]
    state = vault.status()
    if verbose:
        # Show session details, config values, etc.
    ...
```

**Dependencies:** `click`
**Complexity:** Low

---

### VK-017: `change-password` has no confirmation prompt

**Description**

The `change-password` command immediately prompts for current and new passwords, then proceeds. If the operator mistypes the new password confirmation, the process exits with an error — but there is no "are you sure?" confirmation step.

**Why it matters**

Password change is irreversible. A mis-typed new password means losing access to the vault if it's the only copy.

**Implementation approach**

The current `click.prompt(..., confirmation_prompt=True)` already handles password confirmation — but only within the new-password prompt. Consider adding an explicit confirmation step at the start:

```python
@click.command("change-password")
def change_password(obj):
    if not click.confirm("This will re-encrypt all secrets with a new key. Continue?"):
        return
    ...
```

**Dependencies:** `click`
**Complexity:** Low

---

### VK-018: Secret type system is a flat allowlist — no custom types

**Description**

`ALLOWED_TYPES = {"card", "credential", "api_key", "note"}` is hardcoded. Adding a new type (e.g., `wire_transfer`, `crypto_wallet`) requires a code change and a new validator.

**Why it matters**

The vault is tightly coupled to the code. Operators cannot extend the type system without forking.

**Implementation approach**

Replace the hardcoded `ALLOWED_TYPES` with a plugin-like registration system:

```python
# In types.py
_SECRET_VALIDATORS: dict[str, callable] = {}

def register_type(name: str, validator: callable, metadata_builder: callable | None = None):
    _SECRET_VALIDATORS[name] = (validator, metadata_builder)

# Built-ins
register_type("card", _validate_card, _build_card_metadata)
register_type("credential", _validate_credential, _build_credential_metadata)
# ...

def validate_secret(secret_type: str, payload: dict):
    if secret_type not in _SECRET_VALIDATORS:
        raise ValidationError(f"Unsupported secret type: {secret_type}. "
                              f"Registered types: {list(_SECRET_VALIDATORS)}")
    validator, _ = _SECRET_VALIDATORS[secret_type]
    validator(payload)
```

This keeps backward compatibility while enabling extension.

**Dependencies:** None
**Complexity:** Medium — requires refactoring `types.py`

---

### VK-019: No structured logging / machine-readable audit export

**Description**

Audit log is a newline-delimited JSON file. There is no way to export it as CSV, search it programmatically, or stream it to a SIEM (Security Information and Event Management) tool.

**Why it matters**

Compliance or security auditing requires structured access to the audit trail, not just manual `cat audit.log | grep`.

**Implementation approach**

Add an `audit` CLI subcommand:

```python
@main.command("audit")
@click.option("--format", "fmt", type=click.Choice(["json", "csv", "summary"]), default="json")
@click.option("--action", help="Filter by action type.")
@click.option("--since", help="ISO timestamp filter.")
def audit(obj, fmt, action, since):
    """Export audit log in various formats."""
    events = _read_audit_events(vault.paths.audit_log_path)
    if action:
        events = [e for e in events if e["action"] == action]
    if since:
        since_dt = datetime.fromisoformat(since)
        events = [e for e in events if datetime.fromisoformat(e["timestamp"]) >= since_dt]
    if fmt == "csv":
        import csv, io
        output = io.StringIO()
        if events:
            writer = csv.DictWriter(output, fieldnames=events[0].keys())
            writer.writeheader()
            writer.writerows(events)
        click.echo(output.getvalue())
    ...
```

**Dependencies:** `click`, `csv` (stdlib)
**Complexity:** Medium

---

### VK-020: No `vault history` — secret modification history

**Description**

`updated_at` is tracked per secret but there is no command to show the history of changes across all secrets, or to see when a particular secret was last modified.

**Why it matters**

Operators may want to audit which secrets were modified recently, for compliance or security review.

**Implementation approach**

Add a `history` command:

```python
@main.command("history")
@click.option("--secret-id", help="Show history for a specific secret.")
@click.option("--limit", default=50, help="Maximum events to show.")
def history(obj, secret_id, limit):
    rows = vault.db.list_secrets_history(secret_id=secret_id, limit=limit)
    ...
```

The query becomes:

```sql
SELECT id, type, label, updated_at, created_at FROM secrets
ORDER BY updated_at DESC LIMIT ?
```

**Dependencies:** None
**Complexity:** Low

---

## P4 — Future / Nice-to-Have

### VK-021: Backup versioning and incremental backups

**Description**

All backups are full snapshots. For large vaults, repeated full backups waste storage. A backup versioning scheme (full + delta patches) would be more efficient.

**Why it matters**

Storage efficiency for large vaults, and faster backup restoration.

**Implementation approach**

After `export_vault` is stable, add an optional `--incremental` flag that computes a delta against the last backup. Use `jsonpatch` or a similar diff library to store only the changed rows. This requires a versioned backup format.

**Dependencies:** `jsonpatch` or custom diff
**Complexity:** High

---

### VK-022: Vault clustering / sync (future)

**Description**

VaultKnox is strictly single-node. There is no mechanism to sync secrets across multiple machines or allow concurrent multi-operator access.

**Why it matters**

If Ufonik wants to use VaultKnox across multiple machines (laptop + desktop), there's no path to keep them in sync.

**Implementation approach**

Postpone until core is stable. If pursued, consider:
- CRDT-based sync for conflict resolution
- Or a simple "last-write-wins" server using a central SQLite (via Litestream for replication)
- Or age + encrypt for the vault DB

This is a significant architecture decision — do not pursue without a concrete multi-device use case.

---

### VK-023: Secret expiration / TTL

**Description**

Secrets are stored indefinitely. There is no TTL mechanism — a secret could be marked as "temporary" and auto-deleted after a date.

**Why it matters**

For time-limited credentials (temporary API keys, short-lived tokens), manual deletion is error-prone.

**Implementation approach**

Add an `expires_at` column to `secrets` table (nullable). On `add` / `update`, accept `--expires-at ISO8601`. Add a background cleanup step to `unlock` that deletes expired secrets (similar to VK-007).

```sql
ALTER TABLE secrets ADD COLUMN expires_at TEXT;
```

The CLI adds `--expires-at` to `add` and `update`.

**Dependencies:** None
**Complexity:** Medium — requires DB migration

---

### VK-024: FIDO2 / WebAuthn passwordless unlock

**Description**

Master password is the only authentication factor. For high-security environments, a hardware key (YubiKey, Touch ID) could supplement or replace the password.

**Why it matters**

If the master password is compromised, all secrets are exposed. Hardware-backed authentication significantly raises the bar.

**Implementation approach**

Use `py_webauthn` to register a FIDO2 credential on initialize/unlock. The WebAuthn assertion proves possession of the hardware key without transmitting the secret. This is a significant undertaking — defer to post-alpha.

**Dependencies:** `py_webauthn`
**Complexity:** High

---

### VK-025: Secret sharing (future)

**Description**

VaultKnox secrets are single-user. There's no mechanism to share a secret with another VaultKnox operator (e.g., sharing a公司 card with a colleague) without exposing the plaintext.

**Why it matters**

Real-world teams need to share credentials securely.

**Implementation approach**

Postpone indefinitely — secret sharing with end-to-end encryption and proper key management is a research problem (seeage: VaultKnox-as-a-service vs. peer-to-peer). Not compatible with the single-user local-vault design goals.

---

### VK-026: YubiKey / hardware key support for master password

**Description**

Hardware keys can store the Argon2id derived key or the vault's master key in a protected enclave, making offline cracking infeasible even with leaked database.

**Why it matters**

Raises the bar significantly for physical access attacks.

**Implementation approach**

Store an encrypted copy of the entry key on a YubiKey PIV slot. On unlock, require both the YubiKey (possession factor) AND the master password (knowledge factor). This is Two-Factor Nothing-Knows (2FNK) — the YubiKey never sees the password and the host never holds the raw key.

Requires `ykman` CLI or `python-piv` library.

**Dependencies:** `python-piv` or `ykman`
**Complexity:** Medium-High

---

## Implementation Order

This is the recommended order for implementing the items above, accounting for dependencies:

```
Phase 1 (Low-hanging fruit, high impact)
├── VK-004  Duplicate ID handling
├── VK-007  Expired token cleanup
├── VK-010  Atomic session file writes
├── VK-012  --json output mode
├── VK-019  Audit export CLI
└── VK-020  Secret history command

Phase 2 (Correctness + Reliability)
├── VK-006  Streaming re-encryption in change_password
├── VK-008  SQLite WAL mode
├── VK-009  DB integrity check command
├── VK-011  import --dry-run
├── VK-013  Secret rename
├── VK-014  Secret search/filter
└── VK-015  Stdin input for sensitive data

Phase 3 (Security hardening)
├── VK-002  Auto-tune KDF params (with benchmark)
├── VK-001  Secure memory zeroing
├── VK-003  Per-secret HMAC integrity
└── VK-005  consume_token documentation + guard

Phase 4 (Ergonomics + polish)
├── VK-016  Verbose mode
├── VK-017  change-password confirmation
├── VK-018  Extensible secret type registry
└── VK-023  Secret TTL / expiration

Phase 5 (Future)
├── VK-021  Incremental backups
├── VK-024  FIDO2 / WebAuthn
└── VK-026  YubiKey support
```

---

## Not Recommended

The following were considered but are explicitly deferred or not recommended:

| Item | Reason |
|------|--------|
| Secret sharing (VK-025) | Incompatible with single-user local-vault design |
| Vault clustering (VK-022) | Requires significant architecture change; defer until multi-device need is concrete |
| Backup versioning | Low urgency; full backups are sufficient for alpha |

---

*Document version: 1.0 — 2026-04-24*
*Next review: After Phase 1 completion*
