# VaultKnox — Improvement Patch Blueprint (`CLAUDE_IMPROVE_PLAN.md`)

> **Audience:** an autonomous coding agent.
> **Purpose:** a product-requirements + system-design document describing *what* to change and *why*, with logic flows and verification steps — **not** implementation code.
> **Scope reviewed:** `main` @ `4932aa2` (v0.6.1), `MASTER_TODO.md` (on `docs-improvements`), README, CHANGELOG, full `src/vaultknox/` tree, 283 passing tests.
> **Rule for the executing agent:** do not write production code from this file directly into a single commit. Work task-by-task in the roadmap order (Section 4), keep the test suite green at every step, and add tests *before* or *with* each behavioural change.

---

## 0. Executive Summary

VaultKnox is a well-tested (283 tests green), feature-rich local secrets vault for the Hermes Agent. The cryptographic primitives for the **master-password vault** (Argon2id → HKDF context separation → AES-256-GCM) are sound and correctly implemented in `core.py` and `vault.py`. However, the project has accumulated a set of **architectural contradictions between what the documentation promises and what the code enforces**, plus several **latent security and robustness defects**. The most important themes:

1. **The master password crosses the agent boundary.** The single biggest design contradiction: the vault exists to keep secrets out of agent context/logs, yet `vault_tool(...)` accepts `master_password` as a tool kwarg for every write/decrypt action. (Tracked internally as P2-5 / P0-20.)
2. **Advertised controls are not wired in.** The `PolicyEngine` (per-agent/per-service policy) is implemented but never invoked on any access path. OAuth "auto-refresh" exists as functions but is never called. The dashboard claims a 1-hour token expiry that is never enforced.
3. **Crypto claims don't match crypto used.** The README states the autonomous store uses "AES-256-GCM"; it actually uses **Fernet (AES-128-CBC + HMAC-SHA256)**.
4. **Two destructive operations are unsafe.** `change_password` is non-atomic with no backup; rotation's documented rollback helper is a `NotImplementedError` stub and the backup format is not self-contained.

None of these are reasons for alarm about the core encryption, but all of them should be closed before the README's "stable" claim is defensible. This document specifies each fix conceptually.

---

## 1. Gap Analysis & Alignment

This section maps **documentation promises** (README / CHANGELOG / MASTER_TODO) to **actual code behaviour**, and lists the discrepancies an implementer must reconcile.

### 1.1 Documentation-vs-Code Discrepancy Table

| # | Documentation claim | Code reality | Severity | Resolution direction |
|---|---|---|---|---|
| G1 | README "Key Design" + "Autonomous Secrets → Encryption: AES-256-GCM"; CHANGELOG repeats "AES-256-GCM (Fernet)" | `autonomous_secrets.py` uses `cryptography.fernet.Fernet` = **AES-128-CBC + HMAC-SHA256**, not AES-256-GCM | High (truthfulness of a security product) | Either (a) correct the docs to state Fernet/AES-128-CBC honestly, **or** (b) migrate the autonomous store to AES-256-GCM with an HKDF-derived key to match the master vault. Recommended: (b) + doc fix. |
| G2 | README "Hermes never sees plaintext secrets" + "Safety Rules #1" | `vault_tool` requires `master_password=` kwarg for `unlock/add/update/delete/inject_env/consume_token/revoke_token`. The password transits the LLM tool-call channel (context, traces, transcripts) | **Critical (defeats core premise)** | Introduce a session-derived key path so the agent never passes the master password through the tool. (Section 2.1 / 3.A) |
| G3 | README "issuing short-lived tokens for automation without exposing plaintext"; Booking-Flow "exchange for a one-time token" | `issue_token`/`get_masked` need only an unlocked session, but `consume_token` **requires the master password**. So a token cannot deliver plaintext to automation without the password anyway | High (feature does not achieve its stated goal) | Re-design token consumption to use the session-derived key (depends on G2). Define the token contract precisely. (Section 3.A / 3.C) |
| G4 | CHANGELOG v0.5.0 "Policy Engine v2: per-agent, per-service action policies" | `PolicyEngine.check_access()` / `can_get_raw_secret()` are **never called** by `vault_tool` or `mcp_server`. No `agent_id` is threaded into any access path. Only `skills/__init__.py` reads the policy (to print a SKILL.md) | High (advertised security control is inert) | Thread `agent_id` through `vault_tool`/MCP and enforce policy before every action. (Section 3.B) |
| G5 | README "Secret type: `oauth` with auto-refresh tokens" | `refresh_access_token()`, `StoredOAuth.needs_refresh`, `is_expired` exist but are **never invoked** by any retrieval path. Stored OAuth tokens silently expire | Medium | Wire auto-refresh into OAuth secret retrieval. (Section 3.E) |
| G6 | Dashboard footer "Token expires in 1 hour" | `_verify_token` does constant-time compare only; **no expiry is ever checked**. Token is valid for the process lifetime | Medium | Add real token TTL + move token out of URL. (Section 2.5 / 3.D) |
| G7 | README "Architecture" tree | Tree omits the v0.5.0 modules actually present: `dashboard.py`, `mcp_server.py`, `policy.py`, `oauth/`, `skills/`. Doc is stale | Low | Regenerate the architecture tree from the real package. |
| G8 | README "Status: VaultKnox v0.6.1 is stable" | `pyproject.toml` declares `Development Status :: 3 - Alpha` | Low | Pick one. Given the open critical items, "Beta/Alpha" is more honest until G2–G4 close. |
| G9 | MCP server docstring: "Tool calls are brokered through VaultKnox for policy enforcement" | No policy enforcement occurs in `mcp_server.call_tool`; `vaultknox_verify` always returns `requires_master_password` and is non-functional over MCP | Medium | Enforce policy (G4) and either remove or redesign `vaultknox_verify` for MCP. |
| G10 | SKILL.md template example: `os.environ["OPENAI_API_KEY"] = result["token"]` | The `token` is a one-time *vault* token (`vlt_…`), **not** the provider API key. Following the template produces a non-working integration and reflects the token-model confusion in G3 | Medium | Rewrite the generated guidance after the token contract is fixed (G3). |

### 1.2 Open Roadmap Items (from `MASTER_TODO.md`) — Status Reconciliation

The implementer should treat these as the planned backlog. Current real status verified against code:

| Item | Description | Verified status |
|---|---|---|
| P2-5 / P0-20 | Remove `master_password` from Hermes write kwargs via session-derived key | **Open** — still required everywhere (G2). Highest priority. |
| P2-8 | `validate_password_strength()` for `initialize()` / `change_password()` + `--no-password-check` | **Open** — no strength check exists. |
| P2-7 | Reintroduce PID binding in `session.py` with `--skip-pid-check` | **Open** — session has no PID/owner binding. |
| P2-13 | Configurable KDF params via CLI; unify `DEFAULT_KDF_PARAMS` reference | **Open** — `initialize()` hard-codes a second copy of the params inline in `vault.py` instead of referencing `core.DEFAULT_KDF_PARAMS`. |
| P2-22 | Tool-level audit wrapper in `vault_tool()` | **Partially done** — `vault_tool` already writes `tool_<action>` success/failure events, but without `agent_id`/policy context. Extend rather than re-add. |
| P1-15 | Encrypted search index (HKDF search key + AES-SIV) | **Open** — deferred; high complexity. |
| P2-17 | Multiple vault profiles via `--profile` | **Open.** |
| "Always Open" | Initial setup must require a strong master password (never stored) | **Open** — ties to P2-8. |
| "Always Open" | Verify GitHub Actions on first remote run | Two workflows exist (`ci.yml`, `test.yml`); confirm both pass and de-duplicate. |

### 1.3 Missing / Half-Implemented Features (conceptual)

- **Session-derived key cache** — the keystone missing feature. Without it, G2/G3/Q1 cannot be solved.
- **Policy enforcement layer** — engine exists, enforcement does not (G4).
- **OAuth refresh-on-read** — half implemented (G5).
- **Self-contained rotation backup + working rollback** — `_restore_from_pre_rotation_backup` is a `NotImplementedError` stub; backup payload (version 1) omits its own salt (Section 2.7).
- **Atomic `change_password`** — current implementation can corrupt the vault (Section 2.6).
- **Password strength gate** — none (P2-8).
- **Repo hygiene** — stray tracked file `=1.1.0` (captured `pip install >=1.1.0` stdout), committed `.pr-body.md`, `MASTER_TODO.md` not on `main`.

---

## 2. Security & Performance Enhancements

Each finding below has an ID (`S#` security, `Q#` quality/perf), a severity, the concrete weakness, and a conceptual mitigation. Implementation tasks for these live in Section 4.

### 2.1 S1 — Master password crosses the agent boundary *(Critical)*

**Weakness.** `hermes_tool.vault_tool()` accepts `master_password` and forwards it to `vault.unlock/add/update/delete/inject_to_env/consume_token/revoke_token`. In a Hermes deployment, tool arguments are produced/observed by the LLM and frequently persisted (session transcripts, tool-call traces, debug logs). The vault's entire reason to exist is to keep secret material out of exactly those channels. Passing the master password through them re-introduces the leak the product claims to prevent.

**Mitigation — Session-Derived Key (SDK-cache) architecture.**

```
                       ┌─────────────────────────────────────────┐
  operator (human) ───▶│ CLI: hermes-vault unlock (password STDIN)│
                       └───────────────┬─────────────────────────┘
                                       │ derive master_key (Argon2id)
                                       │ derive entry_key (HKDF)
                                       ▼
                  ┌──────────────────────────────────────────────┐
                  │ Session key store (OS-protected, chmod 600):  │
                  │  ~/.hermes/vaultknox/session.key (wrapped)     │
                  │  - holds the *entry sub-key*, NOT the password │
                  │  - bound to: expiry, uid, optional PID set     │
                  └───────────────┬──────────────────────────────┘
                                  │ read by same-user process only
                                  ▼
        Hermes agent ─── vault_tool(action=..., NO master_password) ──▶ vault
                                  │ vault loads entry_key from session store
                                  ▼ decrypts / encrypts without the password
```

Conceptual rules:

- On `unlock`, derive the master key and the scoped **entry key** once, then persist *only the entry key* (and any other needed sub-keys) into a session key file that is `chmod 600`, owned by the operator UID, and carries an expiry. The master password is never written and never returned.
- All agent-facing read/decrypt/write actions resolve the key from the session store via a new internal method (e.g. `VaultKnox._entry_key_from_session()`), **never** from a password argument.
- `vault_tool` removes `master_password` from its signature for agent use. Password entry is restricted to operator CLI paths that read from a TTY/STDIN (`click hide_input`), never from tool kwargs.
- Provide an escape hatch for non-interactive operator scripts (e.g. an env var read only by the CLI process), clearly documented as operator-only.

**Trade-off to document:** the session key file is now a sensitive artifact (like an unlocked SSH agent). Mitigate with short default TTL, `chmod 600`, optional UID/PID binding (P2-7), and `lock` wiping it.

### 2.2 S2 — Autonomous store crypto mismatch *(High — truthfulness + strength)*

**Weakness.** `autonomous_secrets.py` uses `Fernet` (AES-128-CBC + HMAC-SHA256). Docs claim AES-256-GCM. The store also keeps `master.key` in the same directory as `secrets.enc` (documented trade-off, but it means one read compromises everything).

**Mitigation (recommended).** Migrate the autonomous store to the same primitive family as the master vault: a 256-bit key file → HKDF context separation → AES-256-GCM per-record (or per-blob) with random nonces. Keep a versioned on-disk format (`"v": 1` = legacy Fernet, `"v": 2` = AES-256-GCM) and a one-time, idempotent migration that reads v1 with Fernet and rewrites v2. Offer optional OS-keyring storage of the key (e.g. `keyring`) as an alternative to the co-located key file. **If migration is out of scope**, the minimum acceptable fix is to correct every doc reference to say "Fernet (AES-128-CBC + HMAC-SHA256)".

### 2.3 S3 — Policy engine not enforced *(High)*

**Weakness.** Per-agent/per-service authorization is advertised but inert (G4). Any caller with an unlocked session and (for writes) the password can do anything; `agent_id` is not even captured.

**Mitigation.** See Section 3.B — thread `agent_id` into `vault_tool`/MCP, load `PolicyEngine` from `~/.hermes/vaultknox/policy.yaml`, and call `check_access(agent_id, service, action)` (deny-by-default) before executing any action. Map vault actions → policy actions, and derive `service` from the secret's metadata (e.g. `api_key.service`) rather than guessing from `id.split("-")[0]` (the current `PolicyDoctor` heuristic, which is fragile).

### 2.4 S4 — `change_password` is non-atomic, no backup *(High robustness)*

**Weakness.** `VaultKnox.change_password()` calls `set_config("argon2_salt", …)` and `set_config("verifier", …)` in separate transactions, then re-encrypts each secret in its own transaction, with **no pre-change backup**. A crash/exception after the salt+verifier are updated but before all secrets are re-encrypted leaves the vault permanently unreadable (new key cannot decrypt old-key secrets; old key no longer verifies).

**Mitigation.** Delete the bespoke logic and route `change_password` through the already-safe `rotation.rotate_master_key()` (pre-rotation backup + single-transaction re-encryption + rollback). One code path for "re-key the vault."

### 2.5 S5 — Rotation rollback is a stub; backup not self-contained *(Medium)*

**Weakness.** `_restore_from_pre_rotation_backup()` raises `NotImplementedError`. The working rollback (`_rollback_from_backup`) reads the salt from the **live DB**, so if the live DB is replaced/corrupted the backup cannot be opened. Backup payload `version: 1` omits the salt.

**Mitigation.** Make the pre-rotation backup self-contained: store the (old) `argon2_salt` inside the signed backup payload, bump to `version: 2`, and implement a single recovery function that derives the key from the embedded salt + old password (independent of the live DB). Remove the dead `_restore_from_pre_rotation_backup` stub. Note `delete_pre_rotation_backup`'s single-pass zero-overwrite is not a guaranteed secure-erase on CoW/SSD/WAL filesystems — document this limitation rather than implying secure deletion.

### 2.6 S6 — Dashboard token in URL + false expiry *(Medium)*

**Weakness.** Access token is passed as `?token=` (leaks via browser history, `Referer`, and any proxy/log), and the advertised 1-hour expiry is never enforced. Single-threaded `TCPServer`, no `Cache-Control: no-store`.

**Mitigation.** Issue the token as an HTTP-only cookie set by a one-time bootstrap URL (or require an `Authorization: Bearer` header for `/api/*`), store an issued-at timestamp, and reject expired tokens. Add `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`. Keep binding to `127.0.0.1`. Keep constant-time comparison.

### 2.7 S7 — File-creation permission window (TOCTOU) *(Low–Medium)*

**Weakness.** `secrets.db`, `session.json`, exports, and `master.key` are created with the default umask and *then* `chmod 600`. Between creation and chmod the file may be world/group-readable (umask-dependent). The vault directory itself is created with default mode (not `700`).

**Mitigation.** Create sensitive files atomically with restrictive mode from the start (e.g. `os.open(path, O_CREAT|O_WRONLY|O_EXCL, 0o600)` semantics, or set process umask around creation), and create the vault dir with mode `700`. Apply consistently in `config.py`, `db.py`, `session.py`, `autonomous_secrets.py`, `vault.export_vault`, and `rotation.py`.

### 2.8 S8 — Plaintext metadata at rest *(Low)*

**Weakness.** The `metadata` column is **unencrypted** JSON. `build_metadata` stores the full `username` (mislabeled `username_hint`), full `url`, card `last4`/`expiry`/`bank`, `service`/`scope`, and connection `host`/`port`. Anyone who can read `secrets.db` sees these even though payloads are encrypted.

**Mitigation.** Minimize metadata: store a true *hint* (e.g. first/last char + length) for usernames, drop full URLs in favour of host-only, and document that metadata is not encrypted. For high-sensitivity deployments, consider encrypting metadata under a dedicated HKDF sub-key (`vaultknox-metadata`). Coordinate with P1-15 (encrypted search index) so masked listing/search still works.

### 2.9 S9 — No master-password strength gate *(Medium, = P2-8)*

**Weakness.** `initialize()`/`change_password()` accept any password; `_validate_password` (the *secret type*) only checks non-empty.

**Mitigation.** Add `validate_password_strength()` (min length 12, ≥3 character classes, ≥40-bit estimated entropy) invoked by `initialize()` and the re-key path, with a `--no-password-check` CLI escape hatch. Never store or log the password.

### 2.10 S10 — Detector quality *(Low)*

**Weakness.** `sk-[A-Za-z0-9_-]{20,}` is broad and will false-positive on unrelated strings; no entropy gating, no allow-list for obvious test/example placeholders, and several common secret types are missing (Google API key `AIza…`, GCP service-account JSON, Azure connection strings, JWTs, generic high-entropy base64). Redaction is regex-only and bypassable by formatting (documented as defense-in-depth).

**Mitigation.** Add the missing patterns; add an optional Shannon-entropy threshold to the generic detectors to cut false positives; add an allow-list for documented placeholders (`your-key-here`, `sk-xxx`, etc.). Keep regex redaction but clearly scope it as best-effort.

### 2.11 Q1 — Argon2id on every operation *(Performance)*

**Weakness.** Every `add/get/update/delete/consume_token` re-derives the master key via Argon2id (memory_cost 64 MiB, time_cost 3) because the password is passed each call. Bulk imports and agent loops pay this repeatedly.

**Mitigation.** The Session-Derived Key cache (S1) eliminates this: derive once at unlock, reuse the cached entry key for the session's lifetime. This single change fixes the security boundary (S1) **and** the performance problem.

### 2.12 Q2 — Crypto code duplication *(Quality)*

**Weakness.** `rotation.py` re-implements AES-GCM encryption inline instead of calling `core.encrypt_payload`; `vault.initialize()` hard-codes a second copy of the KDF params dict instead of referencing `core.DEFAULT_KDF_PARAMS`; `change_password` duplicates rotation logic.

**Mitigation.** Centralize all encrypt/decrypt and KDF-param references in `core.py`; have `rotation.py` and `vault.py` call the shared helpers. Single source of truth reduces divergence/regression risk.

### 2.13 Q3 — Repo hygiene & doc drift *(Low)*

**Weakness.** Tracked junk file `=1.1.0` (pip stdout captured by a `> =1.1.0` redirection mistake); committed `.pr-body.md`; `MASTER_TODO.md` only on `docs-improvements`; stale architecture tree; "stable" vs "Alpha" mismatch; two CI workflows.

**Mitigation.** Remove stray files, add a `.gitignore` rule preventing `=*` and `*.pr-body.md` style artifacts, merge `MASTER_TODO.md` to `main`, regenerate the architecture section, reconcile the status badge, and de-duplicate CI.

---

## 3. New Feature Specifications

Each feature below is specified as **Objective → Functional Requirements → Technical Design (logic flow)**. No code — pseudocode/flows only.

### 3.A Session-Derived Key (the keystone) — closes G2, G3, Q1, partially S5/P2-7

**Objective.** Let the agent perform vault operations without ever transmitting the master password through the tool boundary, while keeping cryptographic strength.

**Functional Requirements.**
- Operator unlocks via interactive CLI once; the agent then calls `vault_tool` actions with **no** `master_password`.
- A session has a TTL (reuse `auto_lock_minutes`), survives across separate agent tool calls within that window, and is destroyed by `lock`, by expiry, or (optionally) by UID/PID mismatch.
- Compromise of the session key file exposes the vault contents but **not** the master password (so the password remains safe for re-key and for other machines).

**Technical Design (logic flow).**

1. **Define a `SessionKeyStore` (extend `session.py`).** It manages two artifacts in the vault dir:
   - `session.json` — non-secret metadata (unlocked_at, expires_at, refreshed_at, owner_uid, optional pid set). *Already exists; extend with owner_uid/pid.*
   - `session.key` — the **wrapped entry key** (32 bytes) plus any other needed sub-keys, `chmod 600`, created atomically (S7).
2. **On `unlock(password)`:** verify password (existing `_verify_password`), derive `master_key` (Argon2id) and `entry_key = derive_scoped_key(master_key)`; write `entry_key` to `session.key`; zeroize the master key buffer; record metadata. Return only `{unlocked_at, expires_at}` (no key material).
3. **New internal `VaultKnox._session_entry_key()`:** if session is unlocked and not expired and (if enabled) UID/PID match, read and return the entry key from `session.key`; else raise `VaultError("Vault is locked; run unlock first")`.
4. **Refactor read/decrypt/write methods** (`get_secret`, `add_secret`, `update_secret`, `delete_secret`, `consume_token`, `inject_to_env`) to obtain the key via `_session_entry_key()` instead of `password`. Keep password-based methods available **only** for operator CLI and for re-key flows.
5. **`vault_tool` signature change:** drop `master_password` for agent actions; actions that mutate still require `allow_write=True`. `delete`/`revoke_token` (which currently call `_verify_password`) instead require an unlocked session + write gate + policy (3.B).
6. **Escape hatch (operator-only):** the CLI may read a password from STDIN/TTY or an explicitly opted-in env var, never from tool kwargs.

**Security notes to encode in docs:** session key file is sensitive; short TTL; `lock` wipes it; recommend UID binding by default and PID binding behind `--skip-pid-check` (P2-7).

### 3.B Policy Enforcement Layer — closes G4, S3, G9

**Objective.** Make the existing `PolicyEngine` actually gate access, per agent and per service, deny-by-default.

**Functional Requirements.**
- `vault_tool` and MCP `call_tool` accept an `agent_id` (string identity of the calling agent/sub-agent).
- Before executing any action, the system maps `(action, secret)` → `(policy_action, service)` and calls `check_access(agent_id, service, policy_action)`. On deny, return a structured `{"error":"policy_denied", …}` and write an audit event — never the secret.
- Capabilities (`list_credentials`, `scan_secrets`, `export_backup`, `import_credentials`) gate the corresponding non-secret-specific actions.
- TTL caps: `get_masked`/`get_token` must clamp `token_ttl_seconds` to `min(requested, service.max_ttl_seconds or agent.max_ttl_seconds)`.

**Technical Design (logic flow).**

```
vault_tool(action, agent_id, allow_write, **kwargs)
  ├─ load PolicyEngine(~/.hermes/vaultknox/policy.yaml)   # deny-by-default if absent
  ├─ resolve service:
  │     - for secret-scoped actions: read secret metadata → service = metadata.service
  │       (api_key.service / oauth.provider_id / etc.); fall back to secret_id only if none
  ├─ map action → policy_action:
  │     get_masked|get_token → "get_metadata"
  │     consume_token|inject_env → "get_credential" (also gated by agent.raw_secret_access)
  │     add → "add"; update → "add"; delete → "delete"; verify → "verify"; rotate → "rotate"
  ├─ if not engine.check_access(agent_id, service, policy_action):
  │       audit("tool_<action>", "denied", agent_id, service); return {"error":"policy_denied"}
  ├─ enforce TTL cap for token-issuing actions
  ├─ execute action (Section 3.A key path)
  └─ audit success with agent_id + service (extends P2-22)
```

- **Fix the service-derivation heuristic:** `PolicyDoctor` currently uses `secret_id.split("-")[0]`. Replace with metadata-based service resolution so policies key off the real provider, not naming luck.
- **MCP parity:** apply the same gate in `mcp_server.call_tool` (read `agent_id` from a configured server identity or tool argument).

### 3.C One-Time Token Contract (re-design) — closes G3, G10

**Objective.** Make the "issue a short-lived token, consume it later for automation" story actually work without the password, and document the contract unambiguously.

**Functional Requirements.**
- A token references a specific secret + purpose + TTL, is single-use, revocable, and expires.
- `consume_token` returns the plaintext using the **session** key (3.A), not a password. If the session is locked, consumption fails closed.
- Define explicitly in docs what the token *is* (an opaque single-use handle to a vault secret) and what it is *not* (it is **not** the provider API key, contrary to the current generated SKILL.md example).

**Technical Design (logic flow).**
1. `issue_token(secret_id, purpose, ttl)` — unchanged storage, but TTL clamped by policy (3.B).
2. `consume_token(token)` — drop the `password` param; require unlocked session; check revoked → not-found → used → expired (existing order), then decrypt via `_session_entry_key()`, mark used, delete, audit.
3. Regenerate `skills/__init__.py` SKILL.md template so the example shows: get token → `consume_token` → receive plaintext → use transiently → never log. Remove the misleading `os.environ[...] = result["token"]` line.

### 3.D Dashboard Hardening — closes G6, S6

**Objective.** Remove token leakage via URL and enforce the advertised session expiry.

**Functional Requirements.** Token delivered out of the query string; expired tokens rejected; responses non-cacheable; localhost-only retained.

**Technical Design (logic flow).**
1. `DashboardServer.__init__` records `token` + `issued_at` + `ttl_seconds` (default 3600).
2. A one-time bootstrap path (`/?token=…`) sets an `HttpOnly` cookie, then `302`-redirects to `/` without the query param; thereafter the browser sends the cookie. `/api/*` validates the cookie (or an `Authorization: Bearer` header) and checks `now - issued_at < ttl` with constant-time compare.
3. Add `Cache-Control: no-store` + `X-Content-Type-Options: nosniff` to all responses. Footer text reflects the real remaining TTL.

### 3.E OAuth Auto-Refresh on Read — closes G5

**Objective.** Deliver the advertised "auto-refresh" so a retrieved `oauth` secret is never returned expired when a refresh token exists.

**Functional Requirements.** On retrieval of an `oauth` secret, if `needs_refresh` (5-min buffer) and a `refresh_token` is present and client creds are available, refresh, persist the new tokens (re-encrypt), and return fresh material. On refresh failure, return the existing (possibly expired) token with a clear `refresh_failed` flag rather than throwing.

**Technical Design (logic flow).**
```
get_oauth_secret(secret_id):
  payload = get_secret(secret_id)            # via session key (3.A)
  stored  = StoredOAuth.from_payload(...)
  if stored.needs_refresh and stored.refresh_token and client_creds_available:
      try:
          new = refresh_access_token(stored.refresh_token, client_id, client_secret, token_url)
          stored.access_token = new.access_token
          stored.expires_at   = now + new.expires_in
          stored.refresh_token= new.refresh_token or stored.refresh_token
          update_secret(secret_id, type="oauth", payload=stored.to_payload())   # re-encrypt
      except OAuthTokenError:
          mark result {"refresh_failed": True}
  return masked-or-token view
```
Store client_id/secret in the secret's metadata or a sibling config; never log tokens.

### 3.F Secondary features (lower priority, from MASTER_TODO)

- **P2-7 PID/UID binding** — add owner_uid (and optional pid set) to session metadata; reject foreign sessions; `--skip-pid-check` for daemons. (Naturally folds into 3.A.)
- **P2-13 Configurable KDF** — `init` flags `--kdf-memory-mb/--kdf-time-cost/--kdf-parallelism`; persist chosen params in `vault_config`; **reference `core.DEFAULT_KDF_PARAMS`** instead of the inline duplicate in `vault.initialize`.
- **P2-17 Vault profiles** — global `--profile NAME` → base dir `~/.hermes/vaultknox.<profile>/`; thread through `expand_runtime_path`.
- **P1-15 Encrypted search index** — HKDF-derived search key + deterministic (AES-SIV) encryption of searchable tokens, enabling masked search without plaintext metadata (coordinate with S8). High complexity; schedule last.

---

## 4. Step-by-Step Implementation Roadmap for the Coding Agent

Execute in order. Each task lists **Target Files**, **Exact Requirements**, and **Verification Steps**. Keep `PYTHONPATH=src python -m pytest -q` green after every task. Add/extend tests *in the same task* as the behaviour change.

> **Global guardrail:** never write the master password, derived keys, or secret payloads to logs, audit details, or exceptions. Every task that touches a secret path must include a test asserting no plaintext appears in the audit log.

### Phase 0 — Hygiene & Truthfulness (fast, low-risk)

**Task 0.1 — Remove stray/committed artifacts.**
- *Target files:* `=1.1.0` (delete), `.pr-body.md` (delete), `.gitignore` (add rules for `=*` and `*.pr-body.md`).
- *Requirements:* `git rm` the two files; extend `.gitignore`.
- *Verify:* `git ls-files | grep -E '^=|\.pr-body\.md$'` returns nothing; `pytest -q` still green.

**Task 0.2 — Correct crypto + status documentation.**
- *Target files:* `README.md`, `CHANGELOG.md`, `pyproject.toml`.
- *Requirements:* Replace every "AES-256-GCM (Fernet)" / autonomous-store "AES-256-GCM" claim with the accurate primitive ("Fernet = AES-128-CBC + HMAC-SHA256") **unless Task 2.1 migrates it** (then describe v2). Reconcile "stable" vs `Development Status :: 3 - Alpha`. Regenerate the Architecture tree to include `dashboard.py`, `mcp_server.py`, `policy.py`, `oauth/`, `skills/`.
- *Verify:* `grep -ri "AES-256-GCM" README.md CHANGELOG.md` only appears where genuinely true (master vault); architecture tree matches `ls src/vaultknox`.

**Task 0.3 — Promote `MASTER_TODO.md` to `main`; de-dup CI.**
- *Target files:* `MASTER_TODO.md` (bring from `docs-improvements`), `.github/workflows/ci.yml`, `.github/workflows/test.yml`.
- *Requirements:* Place roadmap on `main`; confirm exactly one canonical CI workflow runs ruff + pytest; remove redundancy.
- *Verify:* file present on `main`; CI config lints and tests on push/PR; no duplicate jobs.

### Phase 1 — Robustness Fixes (no API change)

**Task 1.1 — Make `change_password` safe by routing through rotation.**
- *Target files:* `src/vaultknox/vault.py`, `src/vaultknox/rotation.py`, `tests/test_rotation.py` (or new `test_change_password.py`).
- *Requirements:* `VaultKnox.change_password(current, new)` must delegate to `rotation.rotate_master_key(...)` (pre-rotation backup + single-transaction re-encryption + rollback). Remove the multi-transaction bespoke logic. Behaviour unchanged on success.
- *Verify:* New test simulates a failure injected mid-re-encryption (e.g. monkeypatch a single `UPDATE` to raise) and asserts the vault still opens with the **old** password afterward. All existing change-password tests pass.

**Task 1.2 — Self-contained rotation backup + real rollback.**
- *Target files:* `src/vaultknox/rotation.py`, `tests/test_rotation.py`.
- *Requirements:* Embed the (old) `argon2_salt` in the signed backup payload; bump `version` to 2; implement a single recovery function deriving the key from the embedded salt (independent of the live DB); delete the `_restore_from_pre_rotation_backup` `NotImplementedError` stub. Keep accepting v1 backups for read if any exist. Document that zero-overwrite delete is best-effort.
- *Verify:* Test: rotate → corrupt/replace the live DB → restore solely from the backup file + old password → vault opens. Signature-tamper test still raises. `pytest -q` green.

**Task 1.3 — Atomic restrictive file permissions (close TOCTOU).**
- *Target files:* `src/vaultknox/config.py`, `db.py`, `session.py`, `autonomous_secrets.py`, `vault.py` (export), `rotation.py`; `tests/test_permissions.py`.
- *Requirements:* Create sensitive files with mode `0600` atomically (open-with-mode or umask guard), and create vault/autonomous dirs with mode `0700`. No post-hoc-only chmod for newly created secret files.
- *Verify:* Extend `test_permissions.py` to assert mode `0600` on `secrets.db`, `session.json`, `master.key`, exports, and `0700` on the dirs immediately after creation. Green.

**Task 1.4 — Centralize crypto/KDF (DRY).**
- *Target files:* `src/vaultknox/rotation.py`, `vault.py`, `core.py`.
- *Requirements:* `rotation.py` uses `core.encrypt_payload`/`decrypt_payload`; `vault.initialize` references `core.DEFAULT_KDF_PARAMS` instead of an inline duplicate.
- *Verify:* `grep -n "AESGCM(" src/vaultknox/rotation.py` shows no inline encryption duplicating `core`; round-trip + rotation tests green.

### Phase 2 — Security Boundary (the keystone; API-affecting)

**Task 2.0 — Master-password strength gate (P2-8).**
- *Target files:* `src/vaultknox/core.py` (or new `passwords.py`), `vault.py`, `cli.py`, `tests/test_core.py`.
- *Requirements:* `validate_password_strength()` (≥12 chars, ≥3 classes, ≥40-bit entropy heuristic) called by `initialize()` and the re-key path; `--no-password-check` CLI flag bypasses. Never log the password.
- *Verify:* Tests for accept/reject cases and bypass flag. Green.

**Task 2.1 — (Recommended) Migrate autonomous store to AES-256-GCM with versioned format.**
- *Target files:* `src/vaultknox/autonomous_secrets.py`, `tests/test_*` (new `test_autonomous_migration.py`).
- *Requirements:* Versioned on-disk format (`v1`=Fernet legacy read-only, `v2`=AES-256-GCM); idempotent auto-migration on first write; optional OS-keyring key storage. If this task is skipped, Task 0.2's doc correction is mandatory instead.
- *Verify:* Test reads a v1 blob, migrates, reads back as v2; new stores are v2; round-trip + tamper tests pass.

**Task 2.2 — Session-Derived Key store (Section 3.A).**
- *Target files:* `src/vaultknox/session.py`, `config.py`, `vault.py`, `tests/test_vault.py`, new `tests/test_session_key.py`.
- *Requirements:* Implement `SessionKeyStore` managing `session.key` (wrapped entry key, `0600`, atomic) + extended `session.json` metadata (owner_uid, optional pid set). On `unlock`, derive and persist the entry key; zeroize master key; return no key material. Add `VaultKnox._session_entry_key()`. `lock` wipes `session.key`. Respect TTL/expiry; UID binding on by default, `--skip-pid-check` for PID (P2-7).
- *Verify:* Tests: unlock then `get_masked`/`get_secret` succeed with **no** password; after `lock` or expiry they fail closed; foreign-UID session rejected; `session.key` is `0600`; audit contains no key bytes.

**Task 2.3 — Refactor vault methods + `vault_tool` to the session key path (Section 3.A/3.C).**
- *Target files:* `src/vaultknox/vault.py`, `hermes_tool.py`, `mcp_server.py`, `cli.py`, `tests/test_hermes_tool.py`, `tests/test_mcp_server.py`.
- *Requirements:* `get_secret/add_secret/update_secret/delete_secret/consume_token/inject_to_env` resolve the key from the session (no `password` arg on the agent path). Remove `master_password` from `vault_tool` for agent actions; password entry only via operator CLI (TTY/STDIN) or an opt-in operator env var. `consume_token` no longer takes a password (3.C).
- *Verify:* `test_hermes_tool.py` asserts agent actions work **without** `master_password` after an operator unlock, and that no action accepts/forwards a password from tool kwargs. Booking-flow e2e test (get_masked → token → consume) passes with session only. Green.

**Task 2.4 — Token contract + SKILL.md correction (3.C / G10).**
- *Target files:* `src/vaultknox/skills/__init__.py`, `README.md`, `docs/AGENT_INTEGRATION.md`, `tests/test_*` for skills if present.
- *Requirements:* Rewrite generated SKILL.md so the example consumes the token to obtain plaintext and explicitly states the token is **not** the provider key. Update README token/booking sections to match the session-key reality.
- *Verify:* Generated SKILL.md no longer contains `os.environ[...] = result["token"]`; doc/test review.

### Phase 3 — Authorization & Integrations

**Task 3.1 — Enforce PolicyEngine on all access paths (Section 3.B).**
- *Target files:* `src/vaultknox/hermes_tool.py`, `mcp_server.py`, `policy.py`, `tests/test_permissions.py`/new `test_policy_enforcement.py`.
- *Requirements:* Thread `agent_id` into `vault_tool`/MCP; load policy from `~/.hermes/vaultknox/policy.yaml` (deny-by-default if absent); map action→policy_action and resolve `service` from secret **metadata** (not `id.split("-")`); deny → `{"error":"policy_denied"}` + audit; clamp token TTL by policy; gate capabilities. Update `PolicyDoctor` service resolution accordingly.
- *Verify:* Tests: agent with no policy is denied; agent with `get_metadata` on service X allowed for X, denied for Y; `get_credential` requires `raw_secret_access`; TTL clamps; denials never return secret data and are audited.

**Task 3.2 — OAuth auto-refresh on read (Section 3.E).**
- *Target files:* `src/vaultknox/oauth/__init__.py`, `vault.py` (oauth retrieval path), `tests/` new `test_oauth_refresh.py`.
- *Requirements:* On retrieving an `oauth` secret, refresh when `needs_refresh` + refresh_token + client creds; persist (re-encrypt) new tokens; on failure flag `refresh_failed` and return existing. Never log tokens. Verify the OpenAI provider endpoints are real or mark the provider experimental.
- *Verify:* Tests with a mocked token endpoint: near-expiry secret triggers refresh and re-store; refresh failure returns flagged result without throwing; no token in logs.

**Task 3.3 — Dashboard hardening (Section 3.D).**
- *Target files:* `src/vaultknox/dashboard.py`, `tests/` new `test_dashboard.py`.
- *Requirements:* Token via HttpOnly cookie or `Authorization` header (not query string after bootstrap); enforce real TTL (issued_at + ttl); add `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`; keep `127.0.0.1` + constant-time compare; footer shows true remaining TTL.
- *Verify:* Tests: request without/with expired token → 401; valid cookie within TTL → 200; `/api/*` not reachable via `?token=` after bootstrap; headers present.

**Task 3.4 — Detector improvements (S10).**
- *Target files:* `src/vaultknox/detectors.py`, `scanner.py`, `tests/test_scanner.py`/`test_chat_detection.py`.
- *Requirements:* Add Google API key, GCP service-account, Azure connection string, JWT, and generic high-entropy patterns; add optional Shannon-entropy gating for generic detectors; add a placeholder allow-list. Keep regex redaction scoped as best-effort.
- *Verify:* New positive/negative tests including false-positive reductions; existing detection tests green.

### Phase 4 — Optional / Deferred (schedule by value)

**Task 4.1 — Configurable KDF (P2-13):** `init` flags; persist params; reference `core.DEFAULT_KDF_PARAMS`. *Verify:* init with custom params → unlock works; params stored.

**Task 4.2 — Vault profiles (P2-17):** global `--profile`; per-profile base dir. *Verify:* two profiles isolate secrets; default unchanged.

**Task 4.3 — Encrypted search index (P1-15):** HKDF search key + AES-SIV deterministic tokens; coordinate with metadata minimization (S8). *Verify:* masked search returns hits without exposing plaintext; tamper/round-trip tests.

**Task 4.4 — Metadata minimization/encryption (S8):** store true username *hints*, host-only URLs; optionally encrypt metadata under `vaultknox-metadata` sub-key. *Verify:* listing still works; DB inspection shows no full usernames/URLs.

### Final Verification Gate (run before declaring the patch complete)

1. `PYTHONPATH=src python -m pytest -q` → all green (currently 283; expect growth).
2. `ruff check src tests` → clean (config: line-length 200, rules E/F/I/B).
3. **Leak audit:** grep the audit log and tool outputs in tests for any secret/password/derived-key material → none.
4. **Boundary assertion:** a test proving `vault_tool` agent actions succeed after operator `unlock` **without** any `master_password` kwarg, and that no agent action accepts one.
5. **Doc/code consistency:** every security claim in README/CHANGELOG is backed by an enforced code path (crypto names, policy enforcement, token semantics, dashboard expiry, OAuth refresh).
6. **Destructive-op safety:** re-key/rotation failure-injection tests prove the vault remains recoverable.
7. Consider running the bundled `security-review` skill on the final diff as an independent check.

---

## Appendix A — Module Map (verified against `src/vaultknox/`)

| Module | Role | Key issues found |
|---|---|---|
| `core.py` | Argon2id KDF, HKDF scoping, AES-256-GCM, tokens, zeroize | Sound. `zeroize` only clears bytearray (documented). |
| `vault.py` | Vault service: init/add/get/token/export/import/change_password | `change_password` non-atomic (S4); duplicates KDF params (Q2); password-on-every-op (Q1/S1). |
| `autonomous_secrets.py` | Key-file store for cron/scripts | **Fernet, not AES-256-GCM** (S2/G1); key co-located with ciphertext. |
| `db.py` | SQLite (WAL, secure_delete, integrity_check) | Solid; migrations idempotent. |
| `session.py` | Unlock session state + file lock | No key cache, no UID/PID binding (basis for 3.A/P2-7). |
| `hermes_tool.py` | Agent-facing `vault_tool` | Requires `master_password` (G2/S1); no policy/agent_id (G4). |
| `mcp_server.py` | MCP stdio tools | No policy enforcement (G9); `vaultknox_verify` non-functional over MCP. |
| `dashboard.py` | Local web console | Token in URL + false expiry (G6/S6). |
| `oauth/__init__.py` | PKCE flow + refresh | Refresh never wired (G5); OpenAI endpoints likely experimental. |
| `policy.py` | Per-agent/service policy | **Defined, never enforced** (G4/S3); fragile service heuristic. |
| `rotation.py` | Master-key rotation + backup | Rollback stub `NotImplementedError`; backup not self-contained (S5); inline crypto dup (Q2). |
| `types.py` | Secret validation + metadata | Unencrypted metadata stores full username/url (S8); no password strength (S9). |
| `detectors.py`/`scanner.py` | 21 regex detectors + file scan | Broad patterns, false positives, missing types (S10). |
| `hooks/secret_guard.py` | Inbound/outbound redaction | Correct span-merge; regex bypassable (defense-in-depth). |
| `skills/__init__.py` | SKILL.md generation | Misleading token-as-API-key example (G10). |
| `agent_guide/`, `health.py`, `verifier.py`, `audit.py`, `branding.py`, `cli.py` | Support | No blocking issues; `verifier` needs password (same boundary theme). |

## Appendix B — Priority Ordering (do-this-first)

1. **G2/S1** session-derived key (Tasks 2.2–2.3) — unblocks G3, Q1, and the product's core promise.
2. **S4/S5** destructive-op safety (Tasks 1.1–1.2) — prevents data-loss.
3. **G4/S3** policy enforcement (Task 3.1) — turns an advertised control from inert to real.
4. **G1/S2** crypto truthfulness/migration (Tasks 0.2/2.1).
5. **G6/S6** dashboard (Task 3.3), **G5** OAuth refresh (Task 3.2), then hardening/detectors/deferred.
