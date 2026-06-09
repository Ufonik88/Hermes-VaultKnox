# Changelog

All notable changes to VaultKnox are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] — 2026-06-09

### Fixed (Security & Code Review — v0.5.0 → v0.6.0)

- **MCP Server crash on `vaultknox_scan`** — `Path` was used but not imported in `mcp_server.py`. Also removed dead imports (`sys`, `VaultPaths`, `run_health_checks`, duplicate `stdio_server`/`Tool`) and switched internal path handling from the non-existent `get_default_paths` to `expand_runtime_path` (with correct attribute usage). The scan and health tool paths now execute cleanly.
- **Generic bearer verification** — `_verify_generic_bearer` was implemented but never registered. Added `register_provider("generic_bearer", _verify_generic_bearer)` so `--service generic_bearer` (and live verification flows) work instead of returning "Unknown service".
- **`install-hooks` now actually writes the gateway plugin** — The command previously only read `~/.hermes/plugins/vaultknox-secret-guard/__init__.py` and printed a warning if v0.4.2 hooks were missing. It now **writes** a complete, standalone `__init__.py` (and `plugin.yaml`) implementing `pre_gateway_dispatch`, `pre_llm_call`, and `post_llm_call`, plus a `register(ctx)` helper compatible with both `ctx.register_hook` and `ctx.on`. The legacy `~/.hermes/hooks/secret-guard` handler continues to be written for older paths.
- **Timezone-naive expiry dates caused TypeError crashes** — `datetime.fromisoformat()` on strings without offsets (e.g. `2026-12-31`) produced naive datetimes that were compared to `datetime.now(timezone.utc)`, raising `TypeError`. Added `_parse_and_normalize_expiry` (and equivalent inline normalization in the CLI) and applied it in `VaultKnox.get_raw`, `get_masked`, the `list --expired` filter, and `expiry-notify`. A new test `test_naive_timezone_expiry_is_handled_safely` covers the case.
- **Overlapping/nested span redaction corruption in secret-guard** — `handle()` sorted redactions in reverse start order but did not merge overlapping or nested matches first. Multiple detectors hitting the same or nested regions produced nested `[REDACT[REDACTED...` output or index-shift corruption. Added a pre-pass that merges spans before replacement (both inbound `handle()` and the outbound rewrite path already had similar logic; inbound is now consistent).
- **31 ruff violations cleaned** — Unused imports, import sort order, bare `f`-string issues, and a few manual cleanups across `dashboard.py`, `mcp_server.py`, `oauth/__init__.py`, `policy.py`, `skills/__init__.py`, `cli.py`, `vault.py`, `verifier.py`, and `secret_guard.py`. `uv run ruff check` now reports zero violations. Several "except Exception as e: raise ClickException(str(e))" sites were updated to `from e` chaining for better tracebacks.

### Added

- `tests/test_mcp_server.py` — new test module covering MCP server import hygiene (no NameError on `Path` etc.), tool schema completeness, direct exercise of the scan/status code paths that the handlers use, and error-path shapes. This guards the historical `vaultknox_scan` crash site and the `SecretScanner(paths=[...])` construction used by the MCP scan tool.
- Additional unit coverage in `tests/test_vault.py` (naive expiry) and `tests/test_verifier.py` (end-to-end `generic_bearer` via `CredentialVerifier.verify`).
- Version bumped to 0.6.0 (pyproject.toml, `vaultknox/__init__.py`, skill generator template).

### Changed

- `VaultKnox.status()` is now defensive: if the vault has not been initialized (no `vault_config` table yet), it falls back to the default auto-lock minutes instead of raising `sqlite3.OperationalError`. This makes status/health queries safe on a brand-new vault directory (important for MCP/dashboard early calls).
- Minor import reordering and dead-code removal in several modules as part of the lint sweep (no behavior change).

### Security / Robustness

- All critical functional bugs and security-relevant gaps identified in the v0.5.0 → v0.6.0 review have been closed.
- Redaction is now overlap-safe (prevents accidental leakage or garbled messages when multiple detectors match the same secret).
- Expiry handling no longer crashes on user-supplied or previously-stored naive ISO dates.
- Gateway plugin deployment is now reliable — the `vaultknox-secret-guard` hooks that implement outbound secret-request blocking and system-prompt injection will actually be present after `install-hooks`.

## [0.5.0] — 2026-05-20

### Added

- **MCP Server** (`hermes-vault mcp`) — stdio-based MCP transport for direct agent integration
  - Tools: status, list, get_metadata, scan, verify, health
  - Sub-agents can access vault without operator proxying every call
- **Dashboard Console** (`hermes-vault dashboard`) — local token-guarded web UI (127.0.0.1 only)
  - Views: Health, Credentials, Audit, Scanner
  - No raw secrets exposed in browser
- **OAuth PKCE** (`hermes-vault oauth`) — RFC 7636 PKCE flow
  - Providers: Google, GitHub, OpenAI
  - Auto-refresh tokens when expired
- **Skill Generation** (`hermes-vault generate-skill`) — generates SKILL.md contracts for sub-agents
  - Defines credential access patterns, allowed services, security rules
  - Prevents agents from freelancing credential discovery
- **Policy Engine v2** (`src/vaultknox/policy.py`) — per-agent, per-service action policies
  - Actions: get_credential, get_env, get_metadata, verify, rotate, delete, add
  - Agent capabilities: list_credentials, scan_secrets, export_backup
- **Secret type: `oauth`** — new type with refresh_token support
  - Auto-refresh before expiry

### Changed

- **Package version bumped** to 0.5.0
- **MCP 1.26 compatibility** — fixed stdio server for new async API

### Security

- Agents access vault directly via MCP — no plaintext passed through chat
- Dashboard uses token auth, no secrets in browser
- Policy engine enforces deny-by-default per service

## [0.4.2] — 2026-05-13

### Added

- **Outbound Response Scanner** (`post_llm_call` hook) — scans AI responses before they reach the user for phrases that ask users to paste secrets in chat. Detected phrases are automatically rewritten with safe guidance directing users to `vault-add-key` CLI.
- **System Prompt Injection** (`pre_llm_call` hook) — injects VaultKnox behavioural rules into the system message before each LLM call, preventing the AI from requesting secrets in the first place.
- **`agent_requests_secret` trigger** — new critical-priority trigger in `agent_guide/triggers.py` that detects when the agent is about to ask for a secret in chat and blocks it with safe guidance.
- **Enhanced `install-hooks` command** — now also deploys/updates the gateway plugin (plugin.yaml) alongside the legacy hook, ensuring both inbound and outbound protection are in place.

### Changed

- **Plugin version bumped** to 0.4.2 (adds `post_llm_call` and `pre_llm_call` to `provides_hooks`).
- **Package version bumped** to 0.4.2.

### Security

- AI agents can no longer request secrets via chat — outbound scanner catches and rewrites secret-requesting phrases.
- System prompt injection ensures the AI is proactively instructed to never ask for secrets, providing defense-in-depth beyond pattern matching.

## [0.4.1] — 2026-05-12

### Fixed

- **Secret-Guard hook now actually fires** (`HOOK.yaml` + `src/vaultknox/hooks/secret_guard.py`)
  - Hook was registered for `message:received` but the gateway never emitted that event — it was completely dormant
  - Added `message:received` emitter at the correct ingress point in `gateway/run.py` (line ~7488), BEFORE `agent:start` and BEFORE any persistence
  - Hook also now handles `agent:start` as a defense-in-depth layer for CLI/non-gateway paths
  - Supports `message:received` (full content via `content` key) and `agent:start` (truncated via `message` key)

- **VaultKnox gateway plugin** (`~/.hermes/plugins/vaultknox-secret-guard/`)
  - Created Hermes plugin using `pre_gateway_dispatch` hook point (survives `hermes update`)
  - Scans every incoming message BEFORE session/auth/agent using 23 detectors
  - Auto-redacts secrets and prepends a security warning with rotation guidance
  - Enabled in config as `vaultknox-secret-guard`

- **History sanitized** — `vaultknox sanitize-history --apply` ran and redacted 2,775 secret occurrences across 35 files (session JSONL, state.db, shell history)

## [0.4.0] — 2026-05-07

### Added

- **Chat Secret Detection & Redaction** (`src/vaultknox/detectors.py` + `src/vaultknox/hooks/secret_guard.py`)
  - Hook logic lives in `src/vaultknox/hooks/secret_guard.py` and is installed to `~/.hermes/hooks/` via `vaultknox install-hooks`
  - Uses the existing 21-detector registry to scan every incoming message for secrets
  - Auto-redacts detected secrets in-place (replaces with `[REDACTED-SENSITIVE-VALUE]`)
  - Auto-warns the user with contextual guidance when a secret is detected in chat
  - Covers: session JSONL files, `state.db`, Mem0, CLI history, and gateway logs (when hook is installed)

- **Log Sanitization Filter** (companion feature in Hermes core)
  - `SecretSanitizationFilter` — a `logging.Filter` that redacts detector matches from all gateway log records
  - Lives in the Hermes core repo (`gateway/logging_filters.py`); not part of the VaultKnox package
  - Automatically attached to the `gateway` logger on startup
  - Prevents accidental secret leakage in log files, tracebacks, and debug output

- **`vaultknox sanitize-history` CLI**
  - Scans `~/.hermes/sessions/*.jsonl`, `state.db`, and `.hermes_history` for leaked secrets
  - Dry-run by default (`--apply` required to actually modify files)
  - Merges overlapping detector spans before replacement to avoid corruption
  - Shows summary: files scanned, files with secrets, total occurrences

- **`vaultknox(action="scan_text")` Tool Action** (`src/vaultknox/hermes_tool.py`)
  - Lets any agent proactively scan arbitrary text for secrets without touching the vault
  - Returns structured findings with detector name, severity, matched text, and span positions
  - Zero vault unlock required — pure detection

- **Agent Autonomy Package** (`src/vaultknox/agent_guide/`)
  - `TRIGGERS` — 5 built-in trigger patterns (API key paste, credential request, missing key, script writing, cron setup)
  - `check_triggers(text)` — returns matched triggers with priority and recommended action
  - `get_system_prompt_snippet()` — copy-paste ready system prompt block for any AI agent
  - Public documentation: `docs/AGENT_INTEGRATION.md` — safe for GitHub (no vault internals)

### Changed

- `__init__.py` exports — new public symbols: `TRIGGERS`, `check_triggers`, `get_system_prompt_snippet`
- Bumped version: `0.3.0` → `0.4.0`

### Security

- Secret-guard hook (installable via `vaultknox install-hooks`) redacts secrets in incoming messages before they reach session storage
- `sanitize-history` provides a one-command cleanup for accidental chat leaks
- No new regex patterns added — reuses the existing 21-detector registry to avoid pattern drift

## [0.3.0] — 2026-05-06

### Added

- **Master Key Rotation** (`src/vaultknox/rotation.py`)
  - `vaultknox rotate-master-key` — Atomically rotate the vault master password
  - Pre-rotation encrypted backup: backup is encrypted with the OLD password only, so the new password cannot decrypt it (defence-in-depth)
  - HMAC-SHA256 integrity signature on every backup
  - Single SQLite transaction for all re-encryption — vault is never in a partially-updated state
  - Automatic rollback on failure: restores from the pre-rotation backup automatically
  - `list_pre_rotation_backups()` and `delete_pre_rotation_backup()` helpers for manual cleanup

- **Live Credential Verification** (`src/vaultknox/verifier.py`)
  - `vaultknox verify [--service openai|anthropic|github|google_oauth] [--all]`
  - Validates API keys stored in the vault against live provider endpoints
  - Supports: OpenAI, Anthropic, GitHub, Google OAuth, Generic Bearer tokens
  - Returns structured status: `valid`, `invalid`, `billing_issue`, `network_error`, `unknown`
  - 5-second default timeout, 10-second maximum
  - API keys are never logged or echoed

- **Secret Scanner** (`src/vaultknox/scanner.py` + `src/vaultknox/detectors.py`)
  - `vaultknox scan [--paths /path/a,/path/b] [--format json|cli]`
  - Scans files for 21+ plaintext secret patterns: OpenAI, GitHub (6 types), Anthropic, AWS, Stripe, Twilio, SendGrid, NPM, RSA keys, and generic patterns
  - Flags files with unsafe permissions (world-readable `.env` and `.json` files)
  - Detects duplicate secrets across files via SHA-256 fingerprinting
  - Large file protection: 5 MB hard cap, 100 KB line limit
  - Skips `node_modules`, `.git`, `__pycache__`, `.pytest_cache`
  - Output as emoji table (CLI) or structured JSON

- **Vault Health Check** (`src/vaultknox/health.py`)
  - `vaultknox health [--format json|cli]`
  - Checks: DB permissions (0o600), audit log permissions, SQLite integrity (`PRAGMA integrity_check`), vault config completeness, encryption integrity (sample decrypt), audit log readability
  - Reports overall status: `healthy`, `degraded`, or `critical`
  - Exit codes: 0 (healthy), 1 (degraded), 2 (critical)

- **Audit Log Query CLI** (`src/vaultknox/audit.py`)
  - `vaultknox audit query [--action X] [--status success|failure] [--secret-id X] [--since -7d] [--until ISO] [--limit N] [--json]`
  - Filter by action, status, secret ID, and date range (supports relative dates like `-7d`, `-24h`)
  - Reads from main audit log and rotated backups (newest-first)
  - JSON output for scripting

- **Expiry Management** (`src/vaultknox/expiry.py`)
  - `vaultknox expiry set-expiry <id> --days 30` — Set expiry on a secret
  - `vaultknox expiry clear-expiry <id>` — Remove expiry from a secret
  - `vaultknox expiry notify` — Report expired and expiring-within-7-days secrets
  - `vaultknox list --expired` — Show only expired secrets

- **`__init__.py` exports** — New public symbols available for import:
  - `rotate_master_key`, `SecretScanner`, `CredentialVerifier`, `VaultHealthChecker`

### Changed

- Updated README with full v0.3.0 feature documentation
- Bumped version: `0.2.0` → `0.3.0`

### Security

- Pre-rotation backup encrypted with OLD password only — provides defence-in-depth against new password compromise
- All backups HMAC-SHA256 signed and chmod 600
- API keys never appear in scanner output, logs, or terminal echo

## [0.2.0] — 2026-05-05

### Added

- **Autonomous Secrets Store** (`src/vaultknox/autonomous_secrets.py`)
  - Key-file-backed encrypted credential storage using AES-256-GCM (Fernet)
  - No master password required — scripts and cron jobs can read credentials autonomously
  - Same security model as SSH private keys — `master.key` at chmod 600
  - Encrypted `secrets.enc` file is safe for backups, git, and session transcripts
  - Full API: `get()`, `set()`, `delete()`, `list_keys()`, `dump_env()`, `dump_json()`
  - `populate_from()` for bulk importing `.env` files

- **CLI: `hermes-vault secrets` subcommand group**
  - `hermes-vault secrets init` — Initialize the store
  - `hermes-vault secrets add KEY=VALUE [...]` — Add/update credentials
  - `hermes-vault secrets get KEY` — Retrieve a credential
  - `hermes-vault secrets list` — List stored credential names
  - `hermes-vault secrets remove KEY` — Delete a credential
  - `hermes-vault secrets env [--shell]` — Export as JSON or shell-safe env vars
  - `hermes-vault secrets populate --from <file>` — Import from `.env`

- **Standalone `hermes-secrets` CLI entry point**
  - Same commands as above, pip-installable: `pip install hermes-secrets`

- **Shell helper** (`load_secrets.sh`)
  - Source this to export all encrypted credentials as environment variables

- **Auto-Seal Watcher** (`auto_seal` command)
  - Detects new credential keys in `.env` and automatically encrypts them
  - Prevents plaintext credential drift
  - Dry-run mode for safe testing
  - Designed for periodic cron scheduling (recommended: every 30 minutes)
  - Cron job auto-created: runs every 30 minutes, silent when nothing new
  - `hermes-secrets auto-seal --dry-run` to preview before encrypting
  - `hermes-secrets auto-seal` to run immediately
  - Configurable `strip_plaintext` mode to remove secrets from `.env` after sealing

### Changed
- Updated README with clear Security Model and Getting Started sections
  - Clear explanation of key-file-backed security model
  - Removed outdated master password references
  - Added prominent Getting Started example
  - Documented encrypted-secrets directory structure
- Bumped version: `0.1.0` → `0.2.0`
- Updated project description to reflect dual-vault architecture
- Updated README with full autonomous secrets documentation
- Updated `__init__.py` to export new `AutonomousSecretsStore` class

### Security

- All 15 API keys migrated from plaintext `.env` to encrypted store
- Key file permissions locked to `chmod 600`
- Encrypted store safe for git commits, backups, and session logs
- Key file never appears in session transcripts, memory, or tool output

## [0.1.0] — 2025-12-12

### Added

- Master-password vault with AES-256-GCM encryption
- Argon2id key derivation with HKDF scoped key separation
- SQLite-backed local vault storage
- Masked secret retrieval for agent-safe responses
- One-time token issuance for downstream automation
- Backup export and import with integrity signing
- Audit logging with owner-only permissions and rotation
- Hermes integration wrapper with write-gate security
- CLI for full vault lifecycle management
- Support for multiple secret types: cards, credentials, API keys, notes
- VaultKnox branding and logo
