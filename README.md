# Hermes VaultKnox

![VaultKnox Logo](src/vaultknox/assets/vaultknox-logo.svg)

VaultKnox is an encrypted secrets vault designed for Hermes Agent workflows. It provides a Python package and CLI for storing sensitive data locally, returning masked references to agents, and issuing short-lived tokens for automation without exposing plaintext in chat logs or memory files.

## Status

VaultKnox v1.0 is stable.

- Intended use: local development and operator-managed Hermes environments.
- Review the threat model before deploying in high-risk environments.
- Report issues at [github.com/Ufonik88/Hermes-VaultKnox/issues](https://github.com/Ufonik88/Hermes-VaultKnox/issues).

## Ownership

Author: Ufonik

This project is released under the Apache 2.0 license. The code remains copyrighted to Ufonik while permitting public use, modification, and redistribution under that license.


## Getting Started

## Getting Started

### Installation

```bash
pip install -e .[dev]
```

### Initialize the Encrypted Store

```bash
hermes-secrets init
```

### Add Your First API Key

```bash
hermes-secrets add NOTION_API_KEY=your-secret-key-here
```

### Use in a Script

```python
from vaultknox.autonomous_secrets import AutonomousSecretsStore

secrets = AutonomousSecretsStore()
api_key = secrets.get("NOTION_API_KEY")
print(f"API Key: {api_key}")
```

### Use in Cron Jobs

Add this line to the top of your cron prompt:

```bash
eval "$(python3 ~/.hermes/encrypted-secrets/secrets_manager.py env)"
```

Then access credentials as environment variables.


## Key Design


- Hermes never sees plaintext secrets; it only receives masked references and one-time tokens.
- AES-256-GCM protects stored payloads with unique random nonces.
- Argon2id derives the master key, with HKDF used for scoped key separation.
- SQLite stores encrypted vault data at `~/.hermes/vaultknox/secrets.db`.
- The master password is never stored on disk — only held in memory during an unlocked session (for the legacy system).
- Auto-lock defaults to 15 minutes of inactivity.
- Audit logs are written to `~/.hermes/vaultknox/audit.log` with owner-only permissions.

## Features

- AES-256-GCM encryption for stored secret payloads
- Argon2id-based master password key derivation with HKDF key separation
- SQLite-backed local vault storage
- Masked secret retrieval for agent-safe responses
- One-time token issuance for downstream automation
- Backup export and import with integrity signing
- Audit logging with owner-only permissions and rotation
- Hermes integration wrapper with write actions disabled by default

## Threat Model

VaultKnox is designed to reduce the risk of:

- plaintext secrets leaking into chat logs
- secrets being stored in unencrypted config or memory files
- casual disk access revealing vault contents

VaultKnox does not claim to defend against:

- a fully compromised host machine
- keyloggers
- advanced memory extraction on an unlocked process
- formal regulatory compliance requirements by itself

## Installation

### Development install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

### Run tests

```bash
PYTHONPATH=src python -m pytest -q
```

### Run CLI

```bash
PYTHONPATH=src python -m vaultknox.cli status
```

Or after install:

```bash
hermes-vault status
```

Show branding in CLI output:

```bash
hermes-vault logo --asset-path
hermes-vault --logo status
```

## Quick Start

```bash
hermes-vault init
# hermes-vault unlock  # Legacy - not needed for autonomous secrets
hermes-vault add --id revolut_card --type card --label "Revolut Virtual Card" --data '{"number":"4111111111111111","expiry":"12/28","cvv":"123","holder":"DJ C","bank":"Revolut"}'
hermes-vault get revolut_card --mask --purpose booking
hermes-vault export --file backup.vault
```

## Runtime Layout

Default runtime files are stored under `~/.hermes/`:

- `~/.hermes/vaultknox/` — legacy master-password vault (optional)
- `~/.hermes/encrypted-secrets/` — autonomous key-file-backed encrypted store (recommended)

The `encrypted-secrets/` directory contains:
- `master.key` — AES-256 key (chmod 600, never in logs)
- `secrets.enc` — encrypted JSON blob (safe for backups/git)

- `secrets.db`: encrypted SQLite vault database
- `audit.log`: audit trail with rotation
- `session.json`: session state metadata
- `session.lock`: session coordination lock file

## Hermes Integration

The safest integration path is the `vault_tool` wrapper in `src/vaultknox/hermes_tool.py`.

### Available Actions

| Action | Description | Write Gate |
|--------|-------------|------------|
| `status` | Check vault state (initialized/unlocked/count) | No |
| `unlock` | Unlock with master password | No |
| `lock` | Lock vault | No |
| `list` | List secrets (metadata only) | No |
| `get_masked` | Get masked view + optional one-time token | No |
| `get_token` | Issue single-use token for automation | No |
| `add` | Add new secret | Yes |
| `update` | Update existing secret | Yes |
| `delete` | Remove secret | Yes |
| `export` | Encrypted backup | No |
| `import` | Restore from backup | No |

### Safety Rules

1. Hermes never sees plaintext secrets.
2. Write actions require `allow_write=True`.
3. Tokens are single-use and expire by default after 300 seconds.
4. Auto-lock applies after inactivity.
5. Every access is logged without sensitive data.
6. VaultKnox contents must never be written to memory, config, or session transcripts.

Read the operator guidance in [docs/hermes-write-gate-operations.md](docs/hermes-write-gate-operations.md) before enabling write access for Hermes.

## Secret Types

- `card`: number, expiry, cvv, holder, bank
- `credential`: username, password, url, totp_secret
- `api_key`: key, service, scope
- `note`: freeform sensitive text

## Architecture

```text
src/vaultknox/
├── __init__.py      # Exports VaultKnox, VaultError, vault_tool
├── vault.py         # Main VaultKnox class and service logic
├── core.py          # Encryption, decryption, KDF, token generation
├── db.py            # SQLite operations
├── types.py         # Secret validation and masked views
├── audit.py         # Audit logging
├── session.py       # Session state management
├── config.py        # Paths and defaults
└── cli.py           # Click entry point
```

## Booking Flow Example

```text
User: "Book Marble for 2 tomorrow at 7pm"
1. vaultknox(action="get_masked", secret_id="revolut_card", purpose="booking")
   -> masked card data and optional token
2. Navigate to the booking flow and fill non-sensitive fields.
3. If payment is required, exchange for a one-time token.
4. Submit the form without exposing plaintext in agent logs.
```

## Autonomous Secrets (v0.2.0)

VaultKnox v0.2.0 introduces **Autonomous Secrets** — a key-file-backed encrypted
credential store designed for automated and unattended operation.

### Why Autonomous Secrets?

The master-password vault requires manual unlock (typically every 15 minutes),
which breaks cron jobs, scheduled tasks, and automated agent workflows.
Autonomous Secrets uses a **local key file** (chmod 600) instead of a password
prompt — scripts and cron jobs can read credentials without human intervention.

### Security Model

VaultKnox Autonomous Secrets uses a **key-file-backed security model** similar to SSH keys:

- **Key file**: `~/.hermes/encrypted-secrets/master.key` (chmod 600, owner-only)
- **Encryption**: AES-256-GCM with unique random nonces per encryption
- **Storage**: `secrets.enc` contains the encrypted credentials — safe for backups, git, and session logs
- **Threat model**: An attacker with root access to the filesystem can decrypt the secrets. This is the accepted trade-off for full autonomy without manual password prompts.
- **Operational security**: The key file must never appear in session transcripts, memory, or tool output. Ensure proper file permissions (chmod 600) and protect the key file like an SSH private key.


### Usage

```bash
# Initialize the store (one-time)
hermes-secrets init

# Add credentials
hermes-secrets add KILOCODE_API_KEY=sk-xxx NOTION_API_KEY=secret_xxx

# Retrieve a single value
hermes-secrets get NOTION_API_KEY

# List stored keys (values never shown)
hermes-secrets list

# Export as shell-safe environment variables
eval "$(hermes-secrets env --shell)"
echo $KILOCODE_API_KEY

# Import from existing .env file
hermes-secrets populate --from ~/.hermes/.env
```

### In Cron Jobs

Simply add one line at the top of the cron prompt:

```
eval $(python3 ~/.hermes/encrypted-secrets/secrets_manager.py env)
```

Then use the API keys as environment variables as before.

### Auto-Seal: Automatic New Credential Detection

VaultKnox v0.2.0 includes an **auto-seal** mechanism that automatically detects
and encrypts new credential keys as they're added. This prevents plaintext
credential drift — the #1 cause of accidental leaks.

**How it works:**

1. Scans `~/.hermes/.env` for keys ending in `_KEY`, `_TOKEN`, `_SECRET`,
   `_PASSWORD`, or `_CREDENTIALS`.
2. Cross-references with the encrypted store.
3. Encrypts any new credentials it finds.
4. Optionally strips the plaintext from `.env` (with `--strip` flag).

**Run on-demand after adding a new API key:**

```bash
# Dry-run first to see what would be encrypted:
hermes-secrets auto-seal --dry-run

# Then run it for real:
hermes-secrets auto-seal
```

**Automatic via cron (recommended):**

A cron job runs `auto-seal` every 30 minutes by default. If new credentials
are found, they're automatically encrypted. If nothing is found, the job
runs silently with no output. You can verify it's active:

```bash
hermes cron list | grep "Auto-Seal"
```

**Security note:** Auto-seal only encrypts. The plaintext remains in `.env`
by default so Hermes can still read it at startup. The encrypted store is an
additional safety net — your credentials are backed up in encrypted form
even if the `.env` file is accidentally exposed.

### Architecture

```text
~/.hermes/encrypted-secrets/
├── master.key          # Fernet AES-256 key (chmod 600, owner-only)
└── secrets.enc         # Encrypted JSON blob (safe for backups/git)

src/vaultknox/
├── autonomous_secrets.py  # AutonomousSecretsStore class + helpers
└── cli.py                 # `vaultknox secrets` subcommand group
```

### CLI (via VaultKnox)

```bash
# All secrets commands also work through the main VaultKnox CLI:
hermes-vault secrets init
hermes-vault secrets add KEY=VALUE
hermes-vault secrets list
hermes-vault secrets env --shell
```

## Release Guidance

Before treating VaultKnox as broadly usable:

1. Run the release checklist in [docs/release-checklist-v0.1.0.md](docs/release-checklist-v0.1.0.md).
2. Review the Hermes write-gate operations guide.
3. Verify no secrets or local vault files are committed.

## Repository Contents

- `src/vaultknox/`: runtime package
- `tests/`: automated tests
- `docs/`: operational and release documentation
- `MASTER_TODO.md`: active project tracking and changelog
