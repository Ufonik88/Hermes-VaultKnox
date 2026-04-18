# Hermes VaultKnox

VaultKnox is an encrypted secrets vault designed for Hermes Agent workflows. It provides a Python package and CLI for storing sensitive data locally, returning masked references to agents, and issuing short-lived tokens for automation without exposing plaintext in chat logs or memory files.

## Status

VaultKnox is currently alpha software.

- Intended use: local development and controlled operator-managed Hermes environments.
- Not yet intended as audited security software for general production deployment.
- Public release note: use this only if you understand the threat model and operational limits.

## Ownership

Author: Ufonik

This project is released under the Apache 2.0 license. The code remains copyrighted to Ufonik while permitting public use, modification, and redistribution under that license.

## Key Design

- Hermes never sees plaintext secrets; it only receives masked references and one-time tokens.
- AES-256-GCM protects stored payloads with unique random nonces.
- Argon2id derives the master key, with HKDF used for scoped key separation.
- SQLite stores encrypted vault data at `~/.hermes/vaultknox/secrets.db`.
- The master password is never stored on disk and is only held during an unlocked session.
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

## Quick Start

```bash
hermes-vault init
hermes-vault unlock
hermes-vault add --id revolut_card --type card --label "Revolut Virtual Card" --data '{"number":"4111111111111111","expiry":"12/28","cvv":"123","holder":"DJ C","bank":"Revolut"}'
hermes-vault get revolut_card --mask --purpose booking
hermes-vault export --file backup.vault
```

## Runtime Layout

Default runtime files are stored under `~/.hermes/vaultknox/`.

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
