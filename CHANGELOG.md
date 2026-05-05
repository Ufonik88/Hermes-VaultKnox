# Changelog

All notable changes to VaultKnox are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
