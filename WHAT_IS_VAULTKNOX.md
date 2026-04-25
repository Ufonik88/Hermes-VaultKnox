# VaultKnox v1.0 — Official Overview

> VaultKnox is an encrypted, local-first secrets vault built for AI agent workflows. It stores sensitive data securely on disk and gives AI agents — specifically Hermes Agent — safe, auditable access through masked references and short-lived tokens, without ever exposing plaintext in chat logs, memory files, or session state.

**Version:** 1.0  
**Author:** Ufonik  
**License:** Apache 2.0  
**Repository:** [github.com/Ufonik88/Hermes-VaultKnox](https://github.com/Ufonik88/Hermes-VaultKnox)

---

## What Problem Does It Solve?

AI agents that handle real-world workflows inevitably need access to secrets — API keys, database credentials, payment card data, connection strings, passwords. The problem is that most deployments store these secrets in plaintext config files, environment variables, or unencrypted memory. When an agent processes them in a chat context, those secrets end up in logs, transcripts, and context files that persist on disk.

**VaultKnox solves this by design:**

- Secrets are encrypted at rest with AES-256-GCM before they ever touch a database or file.
- The master password is never stored on disk — only held in memory during an unlocked session.
- Hermes Agent never receives plaintext secrets. It gets a masked reference (e.g., `****`) or a time-limited token instead.
- Every access is logged to a tamper-evident audit log with owner-only permissions.

---

## Architecture

### Cryptographic Design

| Layer | Technology | Purpose |
|---|---|---|
| Key Derivation | Argon2id | Derives the master key from the master password. Memory-hard, side-channel resistant. |
| Key Separation | HKDF-SHA256 | Derives scoped sub-keys from the master key — one per operation type (entry encryption, backup signing, token generation). |
| Encryption | AES-256-GCM | Authenticated encryption. Each secret gets a unique random nonce; the tag guarantees integrity. |
| Nonce Generation | `secrets.token_bytes(12)` | Cryptographically secure random nonces — no two secrets share the same nonce. |

### Storage

- **SQLite** at `~/.hermes/vaultknox/secrets.db` — stores encrypted ciphertext, nonces, tags, and metadata. The raw secret data is never readable without the master key.
- **Session store** at `~/.hermes/vaultknox/sessions.json` — tracks whether the vault is currently unlocked and when it should auto-lock.
- **Audit log** at `~/.hermes/vaultknox/audit.log` — append-only JSON lines logging every vault operation with timestamp, action, outcome, and secret ID.

### Key Separation in Practice

The master key never directly encrypts anything. Instead, HKDF-SHA256 derives purpose-specific sub-keys:

```
master_key
  ├── vaultknox-entry         → encrypts/decrypts individual secrets
  ├── vaultknox-verifier     → password correctness check (stored as encrypted test payload)
  ├── vaultknox-backup        → encrypts vault exports
  └── vaultknox-backup-signature → signs vault exports for integrity
```

This means compromise of any sub-key does not expose the master key or any other sub-key's output.

---

## Secret Types

VaultKnox supports six typed secret categories, each with per-type validation rules:

| Type | Use Case | Required Fields | Metadata Extracted |
|---|---|---|---|
| `password` | Stored passwords | `value` | (none) |
| `api_key` | Third-party API keys | `key`, `service` | `service`, `scope` |
| `credential` | Username/password pairs | `username`, `password` | `username_hint`, `url` |
| `card` | Payment card details | `number`, `cvv`, `expiry`, `holder`, `bank` | `last4`, `expiry`, `bank` |
| `connection_string` | Database/service connection strings | `value` (URL format) | `scheme`, `host`, `port`, `has_credentials` |
| `note` | Encrypted freeform notes | `content` | (none) |

Each type has strict validation — connection strings must use a recognised scheme (postgresql://, mongodb://, etc.), card numbers must be digit strings of 12+ characters, CVVs must be 3–4 digits, etc.

---

## Core Features

### Masked Retrieval
When Hermes requests a secret, VaultKnox returns a masked view containing the secret ID, type, label, and structured metadata (e.g., last 4 digits of a card, hostname of a connection string, service name of an API key). The plaintext value is never included in the response.

### Short-Lived Tokens
Optionally, a masked retrieval can include a one-time-use token scoped to a specific purpose (e.g., `deploy-script`, `ci-pipeline`). Tokens expire after a configurable TTL (default: 300 seconds) and are single-use — consuming them retrieves the actual secret value for automation scripts or CI pipelines, then invalidates the token immediately.

### Atomic Bulk Import
Import multiple secrets in a single atomic operation. All entries are validated before any are written — if one entry fails validation, the entire operation rolls back cleanly.

### Export & Import with Integrity Signing
Vault exports are encrypted with a purpose-built backup key derived from the master password and a fresh random salt. The export also carries an HMAC-SHA256 signature so tampering with the export file is detectable on import. The raw vault bytes (the actual SQLite file) are what get exported and re-imported, preserving all data including tokens and session state.

### Password Change
Changing the master password re-derives all sub-keys and re-encrypts every secret in place. No secret is ever decrypted to plaintext outside the vault process.

### Auto-Lock
The vault locks automatically after a configurable period of inactivity (default: 15 minutes). Manual lock is also available. Locked state means no further operations are possible until re-unlocked with the master password.

### Brute-Force Protection
After a configurable number of failed password attempts (default: 5), the vault enters a lockout period (default: 15 minutes). Failed attempts are tracked and logged.

### Environment Variable Injection
Secrets can be injected into the current process environment as environment variables for use by downstream tools. The variable is registered for removal at process exit via `atexit`, ensuring it does not persist beyond the lifetime of the process.

### Token Revocation
Issued tokens can be manually revoked before they expire, immediately invalidating them.

---

## The Hermes Integration

VaultKnox ships a Hermes tool wrapper (`vaultknox.hermes_tool`) that integrates it into Hermes Agent's tool ecosystem. The key design decision: **write operations are disabled by default** — the tool will refuse to add, update, or delete secrets unless `allow_write=True` is explicitly passed. This prevents accidental writes from read-heavy agent workflows.

Every tool call — read or write — is audit-logged with success or failure outcome, so operators have a full trail of what the agent accessed and when.

---

## Security Properties

**VaultKnox is designed to defend against:**

- Plaintext secrets leaking into LLM chat logs or context files
- Secrets stored in unencrypted config, memory, or session files on disk
- Casual disk reads exposing vault contents (files have 0o600 permissions)
- Replay of encrypted vault data without the master password
- Tampered vault export files (integrity signature)

**VaultKnox does not claim to defend against:**

- A fully compromised host operating system
- Keyloggers capturing the master password at unlock time
- Advanced memory forensics on a running, unlocked vault process
- Formal regulatory compliance requirements on its own (PCI-DSS, SOC2, etc.)

---

## File Structure

```
~/.hermes/vaultknox/
├── secrets.db          # SQLite — encrypted vault data
├── sessions.json       # Session state (locked/unlocked + expiry)
├── sessions.lock      # Lock file for session writes
└── audit.log          # Append-only operation log

src/vaultknox/
├── core.py             # Crypto primitives (Argon2id, AES-GCM, HKDF, nonce/token gen)
├── vault.py            # VaultKnox class — all operations
├── db.py               # SQLite vault database
├── session.py          # Session store (unlock/lock/auto-lock)
├── audit.py            # Audit logging
├── config.py           # Path resolution, file permissions, defaults
├── types.py            # Secret types, validation, metadata building
├── cli.py              # CLI interface (Click-based)
├── hermes_tool.py      # Hermes Agent tool wrapper
└── branding.py         # CLI branding / display
```

---

## Quick Reference

```bash
# Initialize vault
vault init

# Unlock
vault unlock

# Add a secret
vault add api_key github_pat "GitHub Personal Access Token" \
  --data '{"key": "ghp_xxx", "service": "github"}'

# List secrets (masked)
vault list

# Get masked view
vault get-masked github_pat --purpose "ci-deploy"

# Lock
vault lock
```
