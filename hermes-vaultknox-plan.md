# Hermes Vault — Secrets Management for Hermes Agent

## Overview

A lightweight, encrypted secrets vault designed specifically for **Hermes Agent**.  
The goal: allow Hermes to store and retrieve sensitive data (payment cards, login credentials, API tokens) **without ever exposing raw secrets in chat logs, memory files, or config files**.

### Core Principle
Hermes should **never see the plaintext secret**. The vault handles encryption/decryption internally and only returns masked or tokenized references to the agent.

---

## Architecture

### 1. Storage Layer
- **Format:** SQLite database at `~/.hermes/vault/secrets.db`
- **Encryption:** AES-256-GCM per-entry, with a derived key from the master password
- **Key derivation:** Argon2id (memory-hard, GPU-resistant)
- **Schema:**
  ```sql
  CREATE TABLE secrets (
      id          TEXT PRIMARY KEY,        -- e.g. "revolut_card", "dineplan_login"
      type        TEXT NOT NULL,           -- "card", "credential", "api_key", "note"
      label       TEXT NOT NULL,           -- Human-readable label
      data        BLOB NOT NULL,           -- Encrypted JSON payload
      nonce       BLOB NOT NULL,           -- Per-entry nonce (12 bytes)
      tag         BLOB NOT NULL,           -- GCM auth tag
      created_at  TEXT DEFAULT (datetime('now')),
      updated_at  TEXT DEFAULT (datetime('now')),
      metadata    TEXT                     -- Plaintext JSON (non-sensitive: expiry hint, last4, etc.)
  );

  CREATE TABLE vault_config (
      key   TEXT PRIMARY KEY,
      value TEXT NOT NULL
  );
  ```
- **vault_config** stores: `kdf_params`, `vault_version`, `locked_at` timestamp

### 2. Encryption Details
```
Master Password
    → Argon2id (t=3, m=65536, p=4) → Master Key (32 bytes)
    → Master Key XOR with stored salt → Encryption Key

Per-entry:
    plaintext JSON → AES-256-GCM(Encryption Key, random 12-byte nonce)
    → stored as: nonce + ciphertext + tag
```
- **Each entry gets a unique random nonce** — never reuse nonces
- **Master key is NEVER stored on disk** — only exists in memory while vault is unlocked
- **Lock timeout:** configurable, default 15 minutes of inactivity

### 3. Secret Types & Payload Schemas

**Card:**
```json
{
  "number": "4111111111111111",
  "expiry": "12/28",
  "cvv": "123",
  "holder": "DJ C",
  "bank": "Revolut"
}
```

**Credential:**
```json
{
  "username": "user@example.com",
  "password": "s3cureP@ss",
  "url": "https://dineplan.com",
  "totp_secret": null
}
```

**API Key:**
```json
{
  "key": "sk-abc123...",
  "service": "OpenAI",
  "scope": "full"
}
```

**Note:**
```json
{
  "content": "any freeform sensitive text"
}
```

---

## CLI Interface (`hermes-vault`)

A standalone Python CLI tool installed at `~/.hermes/vault/hermes-vault.py`  
(or packaged as `hermes-vault` via pip/setup.py)

### Commands

```bash
# Initialize vault (first time — creates DB, sets master password)
hermes-vault init

# Unlock vault for current session (stores session key in memory)
hermes-vault unlock

# Lock vault (clears session key from memory)
hermes-vault lock

# Add a secret
hermes-vault add --id revolut_card --type card --label "Revolut Virtual Card"
# → prompts for JSON input or reads from stdin

# Get a secret (decrypted, shown only in terminal — NOT piped to chat)
hermes-vault get revolut_card

# Get masked reference (safe for Hermes to see)
hermes-vault get revolut_card --mask
# → returns: {"id": "revolut_card", "type": "card", "last4": "1111", "exp": "12/28", "token": "vlt_a1b2c3d4"}

# List all secrets (metadata only, no decryption)
hermes-vault list

# Update a secret
hermes-vault update revolut_card --field number --value "5500000000000004"

# Delete a secret
hermes-vault delete revolut_card

# Export vault (encrypted backup — still requires master password to decrypt)
hermes-vault export --file backup.vault

# Import from backup
hermes-vault import --file backup.vault

# Status
hermes-vault status
# → shows: locked/unlocked, entry count, last unlock time, auto-lock timeout
```

---

## Hermes Agent Integration

### Tool Registration

Add a new tool to Hermes's tool system:

```python
# hermes_tools/vault.py

def vault(action: str, **kwargs) -> dict:
    """
    Hermes tool for secrets vault operations.
    
    Actions:
    - unlock: Unlock vault (requires master_password)
    - lock: Lock vault
    - status: Get vault status
    - list: List all secrets (metadata only)
    - get_masked: Get a secret as a masked reference (safe for chat)
    - get_token: Get a one-time use token for a secret
    - add: Add a new secret (data must be JSON string)
    - update: Update a secret field
    - delete: Delete a secret
    """
    pass
```

### Safety Rules for Hermes

1. **NEVER call `vault get` without `--mask` flag** — unmasked secrets must NEVER appear in chat responses, memory files, or logs
2. **Use tokens for automation** — when booking something, the flow is:
   - `vault.get_token("revolut_card")` → returns a one-time token
   - Pass token to the booking form filler
   - The form filler resolves the token internally (never logs the card number)
3. **Auto-lock** — if Hermes is idle for 15 minutes, vault auto-locks
4. **Audit log** — every vault access is logged to `~/.hermes/vault/audit.log` with timestamp, action, and secret ID (no sensitive data in the log)
5. **Memory exclusion** — vault contents are NEVER written to `~/.hermes/MEMORY.md`, `USER.md`, `config.yaml`, or session transcripts

### Booking Flow Example

```
User: "Book Marble for 2 tomorrow at 7pm"

Hermes thinking:
1. vault.get_masked("revolut_card") → last4: 1111, token: vlt_a1b2c3d4
2. Navigate to Dineplan, search Marble
3. Fill form: date, time, guests, name, phone
4. If payment required:
   - vault.get_token("revolut_card") → one-time token
   - Browser form filler resolves token → fills card fields
   - Token invalidated after use
5. Confirm booking

User sees: "Booked! Table for 2 at Marble, tomorrow 7pm. 
Card ending 1111 used for deposit if required."
```

---

## Configuration

Add to `~/.hermes/config.yaml`:

```yaml
vault:
  enabled: true
  db_path: ~/.hermes/vault/secrets.db
  auto_lock_minutes: 15
  audit_log: true
  max_attempts: 5               # Lock out after 5 failed unlock attempts
  lockout_minutes: 30
  # Optional: hardware key support (future)
  # yubikey_serial: null
```

---

## Security Considerations

### What We're Protecting Against
- Secrets leaked in chat logs ✅ (masked references only)
- Secrets in config/memory files ✅ (encrypted at rest)
- Memory dumps ✅ (Argon2id, key cleared on lock)
- Casual disk access ✅ (SQLite blob is AES-256-GCM encrypted)

### What We're NOT Protecting Against (and that's OK for v1)
- Compromised root access on the host machine (game over anyway)
- Keyloggers capturing the master password
- Side-channel attacks (this isn't a HSM)

### Future Hardening (v2+)
- YubiKey/hardware token as 2FA for unlock
- Shamir's Secret Sharing for master key backup
- Time-based auto-wipe after N failed attempts
- Integration with system keyring (gnome-keyring, macOS Keychain)

---

## Project Structure

```
~/.hermes/vault/
├── hermes-vault.py          # CLI entry point
├── vault_core.py            # Encryption, decryption, key derivation
├── vault_db.py              # SQLite operations
├── vault_types.py           # Secret type definitions & validation
├── vault_audit.py           # Audit logging
├── requirements.txt         # pycryptodome, argon2-cffi
├── tests/
│   ├── test_encryption.py
│   ├── test_db.py
│   ├── test_cli.py
│   └── test_integration.py
└── secrets.db               # Created on init (gitignored)
```

---

## Dependencies

```
pycryptodome>=3.19.0      # AES-256-GCM
argon2-cffi>=23.1.0       # Argon2id key derivation
click>=8.1.0              # CLI framework
```

---

## Implementation Order

1. **vault_core.py** — encryption/decryption primitives, key derivation
2. **vault_db.py** — SQLite schema, CRUD operations
3. **vault_types.py** — type definitions, JSON schema validation
4. **hermes-vault.py** — CLI with all commands
5. **vault_audit.py** — logging layer
6. **Tests** — unit tests for all modules
7. **Hermes integration** — register as a Hermes tool
8. **Browser integration** — token-based form filling for bookings

---

## Notes for Copilot

- This is a **standalone Python project** that integrates with Hermes Agent
- Hermes Agent lives at `~/.hermes/` and uses Python with hermes_tools
- The CLI must work independently AND as a Hermes tool
- All file paths are relative to `~/.hermes/vault/`
- Master password must NEVER be stored on disk — only in memory during unlocked session
- The `--mask` flag is critical — without it, secrets must never be returned to the agent
- Follow the same patterns as existing Hermes tools (terminal calls, dict returns)
- Write tests for everything — this handles sensitive data, no shortcuts
