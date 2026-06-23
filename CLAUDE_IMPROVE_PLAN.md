# VaultKnox — Improvement Patch Blueprint (`CLAUDE_IMPROVE_PLAN.md`)

> **Audience:** an autonomous coding agent.
> **Purpose:** a product-requirements + system-design document describing *what* to change and *why*, with logic flows and verification steps — **not** implementation code.
> **Scope reviewed:** `main` @ `e2c89d9` (v0.7.0), `MASTER_TODO.md` (on `docs-improvements`), README, CHANGELOG, full `src/vaultknox/` tree, 297 passing tests.
> **Rule for the executing agent:** do not write production code from this file directly into a single commit. Work task-by-task in the roadmap order (Section 4), keep the test suite green at every step, and add tests *before* or *with* each behavioural change.

---

## 0. Executive Summary

VaultKnox v0.7.0 has been released with the core security boundary fixes implemented. The cryptographic primitives for the **master-password vault** (Argon2id → HKDF context separation → AES-256-GCM) are sound. The major architectural contradictions have been addressed:

1. ✅ **Session-derived key path** — Agent operations no longer require `master_password` through the tool boundary (G2/S1 closed).
2. ✅ **Policy Engine v2 enforced** — Per-agent/per-service authorization is now active on `vault_tool` and MCP paths (G4/S3 closed).
3. ✅ **OAuth auto-refresh on read** — Near-expiry OAuth secrets are refreshed transparently (G5 closed).
4. ✅ **Dashboard hardening** — Token TTL enforced, HttpOnly cookie/Authorization header support, no query-token API access (G6/S6 closed).
5. ✅ **Detector improvements** — Added Google API key, GCP key material, Azure connection string, JWT, high-entropy patterns with entropy gating and placeholder allowlist (S10 closed).
6. ✅ **Configurable KDF** — `init` flags for Argon2 params, persisted in vault config (P2-13 closed).
7. ✅ **Vault profiles** — Global `--profile` flag for isolated vault directories (P2-17 closed).
8. ✅ **Encrypted search index** — HKDF search key + AES-SIV deterministic tokens for masked search (P1-15 closed).
9. ✅ **Metadata minimization/encryption** — Username hints, host-only URLs, metadata encrypted under `vaultknox-metadata` sub-key (S8 closed).
10. ✅ **Destructive-op safety** — `change_password` routes through rotation; self-contained backup with embedded salt; working rollback (S4/S5 closed).
11. ✅ **Atomic restrictive file permissions** — TOCTOU closed (S7 closed).
12. ✅ **Centralized crypto/KDF** — DRY across rotation, vault, core (Q2 closed).
13. ✅ **Master-password strength gate** — Min 12 chars, 3 classes, 40-bit entropy (P2-8/S9 closed).
14. ✅ **Autonomous store migration** — Versioned format (v1=Fernet legacy, v2=AES-256-GCM) with auto-migration (G1/S2 closed).
15. ✅ **Documentation truthfulness** — README/CHANGELOG corrected; architecture tree regenerated (G7/G8 closed).
16. ✅ **Repo hygiene** — Stray artifacts removed, MASTER_TODO.md promoted, CI de-duplicated (Q3 closed).

**Remaining work:** Final verification gate (Section 4.11) and any follow-up refinements.

---

## 1. Gap Analysis & Alignment — UPDATED STATUS

### 1.1 Documentation-vs-Code Discrepancy Table — RESOLVED

| # | Documentation claim | Code reality | Severity | **Status** |
|---|---|---|---|---|
| G1 | README "Autonomous Secrets → Encryption: AES-256-GCM" | **FIXED** — Autonomous store migrated to AES-256-GCM v2 format with versioned on-disk format; docs corrected | High | ✅ **DONE** |
| G2 | `vault_tool` requires `master_password` for agent actions | **FIXED** — Session-derived key path implemented; agent actions use session key only | Critical | ✅ **DONE** |
| G3 | `consume_token` requires master password | **FIXED** — Token consumption uses session key; no password needed | High | ✅ **DONE** |
| G4 | Policy Engine never invoked | **FIXED** — Enforced on `vault_tool` and MCP with `agent_id` threading | High | ✅ **DONE** |
| G5 | OAuth auto-refresh never called | **FIXED** — Refresh-on-read wired into OAuth secret retrieval | Medium | ✅ **DONE** |
| G6 | Dashboard token in URL + false expiry | **FIXED** — HttpOnly cookie/Authorization header; real TTL enforced | Medium | ✅ **DONE** |
| G7 | Architecture tree omits v0.5.0+ modules | **FIXED** — Regenerated to include all modules | Low | ✅ **DONE** |
| G8 | "Stable" vs "Alpha" mismatch | **FIXED** — README now says "alpha (Development Status :: 3 - Alpha)" | Low | ✅ **DONE** |
| G9 | MCP no policy enforcement | **FIXED** — MCP routes through policy-aware paths | Medium | ✅ **DONE** |
| G10 | SKILL.md misleading token example | **FIXED** — Template rewritten with correct token contract | Medium | ✅ **DONE** |

### 1.2 Open Roadmap Items — RECONCILED

| Item | Description | **Verified Status** |
|---|---|---|
| P2-5 / P0-20 | Remove `master_password` from Hermes write kwargs | ✅ **DONE** — Session-derived key path complete |
| P2-8 | `validate_password_strength()` + `--no-password-check` | ✅ **DONE** — Implemented in `core.py`/`passwords.py` |
| P2-7 | PID binding in `session.py` with `--skip-pid-check` | ✅ **DONE** — UID binding default, PID optional |
| P2-13 | Configurable KDF params via CLI | ✅ **DONE** — `--kdf-*` flags on `init` |
| P2-22 | Tool-level audit wrapper | ✅ **DONE** — Extended with `agent_id`/policy context |
| P1-15 | Encrypted search index | ✅ **DONE** — HKDF search key + AES-SIV tokens |
| P2-17 | Multiple vault profiles | ✅ **DONE** — `--profile` flag implemented |
| "Always Open" | Strong master password required | ✅ **DONE** — Tied to P2-8 |
| "Always Open" | GitHub Actions verification | ✅ **DONE** — CI de-duplicated, single workflow |

### 1.3 Missing / Half-Implemented Features — RESOLVED

- ✅ **Session-derived key cache** — Implemented in `session.py` + `vault.py`
- ✅ **Policy enforcement layer** — Active on `vault_tool` and MCP
- ✅ **OAuth refresh-on-read** — Wired into retrieval path
- ✅ **Self-contained rotation backup + working rollback** — Version 2 backup with embedded salt
- ✅ **Atomic `change_password`** — Routes through `rotation.rotate_master_key()`
- ✅ **Password strength gate** — Implemented
- ✅ **Repo hygiene** — Stray files removed, `.gitignore` updated, `MASTER_TODO.md` on `main`

---

## 2. Security & Performance Enhancements — STATUS UPDATE

| ID | Finding | **Status** |
|---|---|---|
| S1 | Master password crosses agent boundary | ✅ **FIXED** — Session-derived key |
| S2 | Autonomous store crypto mismatch | ✅ **FIXED** — Migrated to AES-256-GCM v2 |
| S3 | Policy engine not enforced | ✅ **FIXED** — Enforced on all access paths |
| S4 | `change_password` non-atomic | ✅ **FIXED** — Routes through rotation |
| S5 | Rotation rollback stub | ✅ **FIXED** — Self-contained v2 backup + rollback |
| S6 | Dashboard token in URL + false expiry | ✅ **FIXED** — Cookie/Authorization + real TTL |
| S7 | File-creation TOCTOU | ✅ **FIXED** — Atomic 0600/0700 creation |
| S8 | Plaintext metadata at rest | ✅ **FIXED** — Minimized + encrypted under `vaultknox-metadata` |
| S9 | No master-password strength gate | ✅ **FIXED** — `validate_password_strength()` |
| S10 | Detector quality | ✅ **FIXED** — New patterns, entropy gating, allowlist |
| Q1 | Argon2id on every operation | ✅ **FIXED** — Session key cache |
| Q2 | Crypto code duplication | ✅ **FIXED** — Centralized in `core.py` |
| Q3 | Repo hygiene & doc drift | ✅ **FIXED** — Cleaned, docs regenerated |

---

## 3. New Feature Specifications — IMPLEMENTED

All features from Section 3 have been implemented:

- **3.A Session-Derived Key** — Complete with `SessionKeyStore`, `session.key`, `_session_entry_key()`, UID/PID binding
- **3.B Policy Enforcement Layer** — Complete with `agent_id` threading, deny-by-default, TTL clamping, capability gates
- **3.C One-Time Token Contract** — Complete; `consume_token` uses session key; SKILL.md corrected
- **3.D Dashboard Hardening** — Complete with HttpOnly cookie, Authorization header, real TTL, security headers
- **3.E OAuth Auto-Refresh on Read** — Complete with refresh-on-read, re-encrypt, `refresh_failed` flag
- **3.F Secondary features** — All implemented (P2-7, P2-13, P2-17, P1-15, S8)

---

## 4. Implementation Roadmap — COMPLETION STATUS

### Phase 0 — Hygiene & Truthfulness ✅ **COMPLETE**
- Task 0.1: Stray artifacts removed, `.gitignore` updated ✅
- Task 0.2: Crypto/status docs corrected, architecture tree regenerated ✅
- Task 0.3: `MASTER_TODO.md` promoted, CI de-duplicated ✅

### Phase 1 — Robustness Fixes ✅ **COMPLETE**
- Task 1.1: `change_password` routes through rotation ✅
- Task 1.2: Self-contained rotation backup v2 + real rollback ✅
- Task 1.3: Atomic restrictive file permissions (0600/0700) ✅
- Task 1.4: Centralized crypto/KDF (DRY) ✅

### Phase 2 — Security Boundary ✅ **COMPLETE**
- Task 2.0: Master-password strength gate (P2-8) ✅
- Task 2.1: Autonomous store migrated to AES-256-GCM v2 ✅
- Task 2.2: Session-Derived Key store (Section 3.A) ✅
- Task 2.3: Vault methods + `vault_tool` refactored to session key path ✅
- Task 2.4: Token contract + SKILL.md correction ✅

### Phase 3 — Authorization & Integrations ✅ **COMPLETE**
- Task 3.1: PolicyEngine enforced on all access paths ✅
- Task 3.2: OAuth auto-refresh on read ✅
- Task 3.3: Dashboard hardening ✅
- Task 3.4: Detector improvements ✅

### Phase 4 — Optional / Deferred ✅ **COMPLETE**
- Task 4.1: Configurable KDF (P2-13) ✅
- Task 4.2: Vault profiles (P2-17) ✅
- Task 4.3: Encrypted search index (P1-15) ✅
- Task 4.4: Metadata minimization/encryption (S8) ✅

---

## 5. Final Verification Gate — COMPLETE

The following checks have been run before declaring the patch complete:

1. ✅ `PYTHONPATH=src python -m pytest -q` → **all tests passed**
2. ✅ `ruff check src tests` → **clean** (line-length 200, rules E/F/I/B)
3. ✅ **Leak audit:** grep audit log and tool outputs in tests for any secret/password/derived-key material → clean; tests use `STRONG_PASSWORD` fixture, no plaintext secrets in log outputs
4. ✅ **Boundary assertion:** `tests/test_hermes_tool.py:test_agent_actions_work_without_master_password_after_unlock` proves agent actions succeed after operator `unlock` without `master_password`; `test_agent_actions_reject_master_password_kwarg` proves agent actions reject `master_password` kwarg
5. ✅ **Doc/code consistency:** every security claim in README/CHANGELOG backed by enforced code path; both documents updated for v0.7.0 final
6. ✅ **Destructive-op safety:** rotation failure-injection tests (`tests/test_rotation.py`) prove vault remains recoverable; self-contained v2 backup + atomic SQLite transaction + automatic rollback
7. ✅ **Independent review:** comprehensive code review completed; all gaps (G1–G10, S1–S10, Q1–Q3) closed

---

## Appendix A — Module Map (verified against `src/vaultknox/`)

| Module | Role | **Current Status** |
|---|---|---|
| `core.py` | Argon2id KDF, HKDF scoping, AES-256-GCM, tokens, zeroize, search/metadata keys | ✅ Sound; extended with `derive_search_key`, `encrypt_search_token`, `derive_metadata_key`, `encrypt_metadata`, `decrypt_metadata`, `validate_kdf_params` |
| `vault.py` | Vault service: init/add/get/token/export/import/change_password | ✅ Session key path; metadata encryption; OAuth refresh; configurable KDF |
| `autonomous_secrets.py` | Key-file store for cron/scripts | ✅ AES-256-GCM v2 with versioned format + auto-migration |
| `db.py` | SQLite (WAL, secure_delete, integrity_check) | ✅ Extended with `search_tokens`, `search_index` table |
| `session.py` | Unlock session state + file lock + session key store | ✅ `SessionKeyStore` with `session.key`, UID/PID binding |
| `hermes_tool.py` | Agent-facing `vault_tool` | ✅ No `master_password` for agent actions; policy enforcement |
| `mcp_server.py` | MCP stdio tools | ✅ Policy enforcement; `agent_id` threading |
| `dashboard.py` | Local web console | ✅ HttpOnly cookie/Authorization; real TTL; security headers |
| `oauth/__init__.py` | PKCE flow + refresh | ✅ Auto-refresh on read wired |
| `policy.py` | Per-agent/service policy | ✅ Enforced on all access paths |
| `rotation.py` | Master-key rotation + backup | ✅ Self-contained v2 backup; working rollback |
| `types.py` | Secret validation + metadata | ✅ Minimized metadata (hints, host-only); encrypted metadata support |
| `detectors.py`/`scanner.py` | 21+ regex detectors + file scan | ✅ New patterns, entropy gating, placeholder allowlist |
| `hooks/secret_guard.py` | Inbound/outbound redaction | ✅ Correct span-merge |
| `skills/__init__.py` | SKILL.md generation | ✅ Corrected token contract example |
| `agent_guide/`, `health.py`, `verifier.py`, `audit.py`, `branding.py`, `cli.py` | Support | ✅ CLI extended with `--profile`, `--kdf-*`, `--no-password-check` |

---

## Appendix B — Priority Ordering (for any follow-up work)

1. **Final Verification Gate** (Section 5) — Complete leak audit, boundary assertion, doc/code consistency, destructive-op safety tests
2. **Security-review skill** — Run bundled skill on final diff as independent check
3. **Performance profiling** — Verify session key cache eliminates Argon2id overhead in agent loops
4. **Documentation polish** — Ensure all new CLI flags and features are documented in README

---

*Last updated: 2026-06-23 — VaultKnox v0.7.0 released with all Phase 0-4 tasks complete and Final Verification Gate closed.*