# VaultKnox Master TODO

## Active Tasks

### Phase 4 — Polish & Hardening (v0.4.0 — deferred pending review)
- [ ] P2-7: Reintroduce PID binding in session.py with --skip-pid-check escape hatch for daemon workflows (previously reverted).
- [ ] P2-8: Add validate_password_strength() (min 12 chars, 3+ char classes, 40+ bit entropy); integrate into initialize() and change_password(); add --no-password-check CLI flag.
- [ ] P2-13: Make KDF params configurable via --kdf-memory-mb, --kdf-time-cost, --kdf-parallelism on init; unify DEFAULT_KDF_PARAMS reference in vault.py.
- [ ] P2-22: Add Hermes tool-level audit wrapper in vault_tool() so every tool invocation writes an audit event.
- [ ] P2-5/P0-20: Remove master_password from Hermes write kwargs by introducing session-derived key path in vault.py and session.py.
- [ ] P1-15: Add encrypted search index using HKDF-derived search key and AES-SIV deterministic encryption (high complexity, deferred last).
- [ ] P2-17: Add multiple vault profiles via --profile global flag; store each profile at ~/.hermes/vaultknox.<profile>/.

### Always Open
- [ ] Add an initial setup step that requires setting a Master Password for VaultKnox, with a warning that it is never stored and should be strong.
- [ ] Verify GitHub Actions passes on the first remote run after publication.

## Decisions And Ideas

- [ ] Rule: every meaningful feature, bug, change, decision, and new idea must be recorded in this file.
- [ ] Rule: incomplete items stay at the top of the document; completed items move to the bottom.
- [ ] Decision: implement VaultKnox as a source project in this repository and deploy it into ~/.hermes/vault as an install step.
- [ ] Decision: use Argon2id-derived key material plus HKDF context separation instead of the XOR key derivation from the original draft.
- [ ] Decision: ship a password-driven CLI first and defer true cross-process unlock caching until a safe session mechanism is implemented.
- [ ] Decision (2026-04-24): implement Phase 1 + Phase 2 first; review before proceeding to Phase 3 and 4.
- [ ] Decision (2026-04-24): PID binding (P2-7) reintroduced in Phase 4 with --skip-pid-check guard to avoid breaking daemon workflows.
- [ ] Decision (2026-04-24): pyyaml added as runtime dependency in Phase 3 (bulk import); hypothesis added as dev dependency in Phase 2 (property tests).
- [ ] Decision (2026-04-24): P2-24 (GitHub Actions CI) is already complete; excluded from roadmap.
- [ ] Idea: provide a dedicated token resolver contract for browser automation before building the resolver itself.

## Completed Tasks And Change Log

- [x] 2026-04-19 Added packaged VaultKnox branding asset, CLI logo display command, and README logo embedding.
- [x] 2026-04-18 Bootstrapped the Python package with setuptools, console entrypoint, test config, and runtime artifact ignores.
- [x] 2026-04-18 Added initial crypto primitives using Argon2id, HKDF, AES-256-GCM, secure salts, and token generation.
- [x] 2026-04-18 Added secret validation and masked metadata generation for card, credential, api_key, and note records.
- [x] 2026-04-18 Added SQLite storage for encrypted secrets, vault config, and one-time tokens.
- [x] 2026-04-18 Added an initial VaultKnox service layer with initialization, password verification, add/update/delete, masked retrieval, token issue/consume, and basic audit logging.
- [x] 2026-04-18 Added a baseline CLI with init, status, unlock, lock, list, add, get, delete, issue-token, and consume-token commands.
- [x] 2026-04-18 Added baseline tests covering crypto round-trips, validation, masking, failed password tracking, and single-use tokens.
- [x] 2026-04-18 Added session lock coordination with stale PID cleanup and enforced unlocked-session checks for metadata/token operations.
- [x] 2026-04-18 Added CLI commands for update, export, import, and change-password.
- [x] 2026-04-18 Added backup export/import encryption and password rotation support in the vault service.
- [x] 2026-04-18 Added Hermes-safe wrapper with capability-gated write actions and tests for default-deny behavior.
- [x] 2026-04-18 Completed #4 by adding operator guidance for Hermes write-gate policy and default-safe deployment in docs/hermes-write-gate-operations.md.
- [x] 2026-04-18 Completed #1 by hardening audit logging with owner-only file permissions and automatic log rotation.
- [x] 2026-04-18 Completed #2 by adding lockout, expiry, corruption, and plaintext-leak prevention tests.
- [x] 2026-04-18 Completed #3 by adding backup integrity signing, metadata signing coverage, and strict import integrity checks.
- [x] 2026-04-18 Added public README, Apache 2.0 license, NOTICE file, and author metadata naming Ufonik as the project author.
- [x] 2026-04-18 Added a release checklist document for v0.1.0 packaging and install flow validation.
- [x] 2026-04-18 Added GitHub Actions CI for Ruff and pytest on pushes and pull requests.
- [x] 2026-04-18 Fixed session persistence for installed CLI workflows by removing PID-bound session invalidation.
- [x] 2026-04-18 Validated local release gates: editable install, Ruff, pytest, and installed CLI smoke test.
- [x] 2026-04-18 Hardened filesystem permissions for database, session files, lock files, and exported backups.
- [x] 2026-04-18 Completed the local release checklist review: runtime ignore rules, CLI doc examples, repo hygiene scan, and version/changelog validation.
- [x] 2026-04-24 Phase 1: Fixed zeroize() to use ctypes.memset for proper C-level memory wipe (core.py).
- [x] 2026-04-24 Phase 1: Enabled SQLite WAL mode, synchronous=NORMAL, secure_delete, and integrity_check on initialize() (db.py).
- [x] 2026-04-24 Phase 1: Added inject_to_env() to vault.py, inject-env CLI command, and inject_env Hermes action (P0-14 core use case).
- [x] 2026-04-24 Phase 1: Fixed CLI VaultError unhandled traceback via _VaultGroup Click subclass catching VaultError and ValueError.
- [x] 2026-04-24 Phase 2: Replaced Path.rename() with os.replace() for atomic POSIX audit log rotation; touch + chmod empty log after (P1-6).
- [x] 2026-04-24 Phase 2: Added token revocation list — vault_tokens_revoked table, schema migration, revoke_token() method, CLI revoke-token, Hermes revoke_token action (P1-3).
- [x] 2026-04-24 Phase 2: Made --data optional on CLI add/update with interactive per-type prompts; hide_input=True for sensitive fields (P1-10).
- [x] 2026-04-24 Phase 2: Exposed consume_token action in hermes_tool.py (P1-21).
- [x] 2026-04-24 Phase 2: Added hypothesis property-based tests for encrypt/decrypt round-trip, ciphertext tamper, tag tamper, and zeroize; added hypothesis to dev deps (P1-23).
- [x] 2026-04-24 Phase 3: Added secret expiry/TTL — expires_at column in SCHEMA + ALTER TABLE migration, get_secret/get_masked return {expired:true} for expired secrets, add/update accept --expires-at, CLI list --expired filter (P1-16).
- [x] 2026-04-24 Phase 3: Added connection_string secret type with urllib.parse validation (scheme allowlist, host required unless sqlite), metadata stores scheme/host/port/has_credentials — never the password (P2-12).
- [x] 2026-04-24 Phase 3: Added password secret type with {value: str} payload and empty metadata; both types get interactive CLI prompts (P2-19).
- [x] 2026-04-24 Phase 3: Added vacuum CLI command and db.vacuum() method (VACUUM + WAL checkpoint TRUNCATE, reports before/after size) (P2-9).
- [x] 2026-04-24 Phase 3: Added bulk-import CLI command for YAML/JSON files with fail-fast validation before any writes; pyyaml added as runtime dep (P2-11).
- [x] 2026-04-24 Phase 3: Added 13 new tests covering new secret types, expiry, bulk import, and vacuum; ruff B017 fixed in test_core.py with specific InvalidTag exception type. 48/48 tests pass.
