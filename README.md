# Hermes VaultKnox

Encrypted secrets vault for Hermes Agent — stores cards, credentials, API keys, and sensitive notes.

## Key Design

- **Hermes never sees plaintext secrets** — only masked references and one-time tokens
- **AES-256-GCM** per-entry encryption with unique random nonces
- **Argon2id** for master key derivation (t=3, m=65536, p=4)
- **SQLite** at `~/.hermes/vaultknox/secrets.db`
- **Master password never stored on disk** — memory only during unlocked session
- **Auto-lock** after 15 min inactivity (configurable)
- **Audit log** at `~/.hermes/vaultknox/audit.log`

## Status

- [x] Core encryption (AES-256-GCM, Argon2id)
- [x] Database layer (SQLite, CRUD, tokens)
- [x] Type definitions & validation
- [x] CLI entry point
- [x] Audit logging
- [x] Hermes tool integration (`vaultknox` tool in hermes-agent)
- [x] All tests passing (19/19)
- [ ] Browser integration (token-based form filling)

## Quick Start

```bash
# Clone & install
cd ~/.hermes/Hermes-VaultKnox
python3 -m venv .venv
.venv/bin/pip install -e .

# Run tests
.venv/bin/python -m pytest tests/ -v

# CLI
.venv/bin/hermes-vault --help
```

## Hermes Integration

The `vaultknox` tool is registered in hermes-agent's tool registry and available to the AI agent.

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

1. Hermes NEVER sees plaintext secrets
2. Write actions require `allow_write=True`
3. Tokens are single-use and expire (default 300s)
4. Auto-lock after 15 min inactivity
5. Every access logged to audit.log (no sensitive data)
6. VaultKnox contents NEVER written to memory, config, or session transcripts

## Secret Types

- **card**: number, expiry, cvv, holder, bank
- **credential**: username, password, url, totp_secret
- **api_key**: key, service, scope
- **note**: freeform sensitive text

## Architecture

```
src/vaultknox/
├── __init__.py      # Exports VaultKnox, VaultError, vault_tool
├── vault.py         # Main VaultKnox class — orchestrates everything
├── core.py          # Encryption/decryption, key derivation, token generation
├── db.py            # SQLite operations
├── types.py         # Secret type definitions, validation, masked views
├── audit.py         # Audit logging
├── session.py       # Session state management
├── config.py        # Paths and defaults
└── cli.py           # CLI entry point (click)

hermes-agent/tools/vaultknox_tool.py  # Hermes tool integration
```

## Booking Flow Example

```
User: "Book Marble for 2 tomorrow at 7pm"
1. vaultknox(action="get_masked", secret_id="revolut_card", purpose="booking")
   → last4: 1111, token: vlt_xxx
2. Navigate to Dineplan, search Marble
3. Fill form: date, time, guests, name, phone
4. If payment: vaultknox(action="get_token", ...) → one-time token → fill card fields
5. Confirm booking
```

## Future (v2+)

- YubiKey/hardware token 2FA
- Shamir's Secret Sharing for key backup
- Time-based auto-wipe after N failed attempts
- System keyring integration
