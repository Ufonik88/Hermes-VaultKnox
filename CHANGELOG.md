# Changelog

All notable changes to VaultKnox are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
