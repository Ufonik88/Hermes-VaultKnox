# VaultKnox Master TODO

## Active Tasks

- [ ] Harden audit logging with file permissions and rotation.
- [ ] Expand tests for lockout windows, expiry handling, corrupted database cases, and plaintext leak prevention.
- [ ] Add import integrity checks and optional signed backup metadata.
- [ ] Document operational guidance for Hermes write-gate policy and default-safe deployment.

## Decisions And Ideas

- [ ] Rule: every meaningful feature, bug, change, decision, and new idea must be recorded in this file.
- [ ] Rule: incomplete items stay at the top of the document; completed items move to the bottom.
- [ ] Decision: implement VaultKnox as a source project in this repository and deploy it into ~/.hermes/vault as an install step.
- [ ] Decision: use Argon2id-derived key material plus HKDF context separation instead of the XOR key derivation from the original draft.
- [ ] Decision: ship a password-driven CLI first and defer true cross-process unlock caching until a safe session mechanism is implemented.
- [ ] Idea: provide a dedicated token resolver contract for browser automation before building the resolver itself.

## Completed Tasks And Change Log

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
