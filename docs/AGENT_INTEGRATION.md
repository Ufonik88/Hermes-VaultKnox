# Agent Integration Guide

## What VaultKnox Does

VaultKnox is an encrypted secrets vault for AI agents. It ensures API keys and credentials never appear in chat logs, session history, or agent context windows.

## For Agent Developers

### 1. Detect Secrets in User Messages

Before processing any user message, scan it for common secret patterns (API keys, tokens, passwords). If found:

- Warn the user immediately
- Do not process or echo the secret
- Guide them to safe storage

**Use the `scan_text` tool action:**

```python
vaultknox(action="scan_text", text=user_message)
```

This runs all built-in detectors on the text and returns findings without storing anything.

### 2. Install the Secret-Guard Hook

To automatically redact secrets from chat before they reach session storage, install the gateway hook:

```bash
vaultknox install-hooks
```

This writes `~/.hermes/hooks/secret-guard/handler.py` and `HOOK.yaml`, which use the VaultKnox detector registry to scan and redact every incoming `message:received` event.

> **v0.6.0 fix:** Earlier versions only warned if the gateway plugin `__init__.py` was missing or outdated but never wrote it. `install-hooks` now **always writes** a complete, standalone `__init__.py` implementing all three hooks (`pre_gateway_dispatch`, `pre_llm_call`, `post_llm_call`) and a `register(ctx)` helper. Run `vaultknox install-hooks` after upgrading to v0.6.0 to ensure the plugin is up to date.

### 2b. Proactive Protection (v0.4.2+)

The VaultKnox gateway plugin at `~/.hermes/plugins/vaultknox-secret-guard/` provides three layers of protection (reliable since v0.6.0 — earlier versions of `install-hooks` did not deploy the plugin file):

| Hook | When | What It Does |
|------|------|-------------|
| `pre_gateway_dispatch` | Inbound message arrives | Scans and redacts secrets in user messages (v0.4.1) |
| `pre_llm_call` | Before each LLM response | Injects behavioral rules: "NEVER ask user to paste secrets" |
| `post_llm_call` | After each LLM response | Scans AI output for secret-requesting phrases, rewrites with safe guidance |

The plugin survives `hermes update` and is automatically loaded when configured in `config.yaml`:
```yaml
plugins:
  enabled:
    - vaultknox-secret-guard
```

**The `pre_llm_call` hook** ensures the AI is reminded every turn to never request secrets in chat. **The `post_llm_call` hook** catches any residual requests and rewrites them with safe guidance directing users to the `vault-add-key` CLI.

### 3. Safe Storage Pattern

Direct users to the CLI (bypasses chat entirely):

```bash
vault-add-key openai "OpenAI API Key" sk-xxx
```

Or guide them to use the vault tool with `allow_write=True`:

```python
vaultknox(
    action="add",
    secret_id="openai",
    secret_type="api_key",
    label="OpenAI API Key",
    payload={"key": "sk-xxx", "service": "openai"},
    allow_write=True,
    master_password="...",
)
```

### 4. Safe Retrieval Pattern

Use the agent tool to get a masked reference:

```python
vaultknox(action="get_masked", secret_id="openai", purpose="making API call")
```

This returns metadata plus a one-time token. The actual secret is never exposed to the agent's context window.

### 5. Automation Pattern

For cron jobs and scripts that need unattended access:

```python
from vaultknox import AutonomousSecretsStore

store = AutonomousSecretsStore()
key = store.get("API_KEY_NAME")
```

This requires no master password and is designed for automation.

## What NOT to Do

- **Do not** ask users to type secrets in chat
- **Do not** store secrets in agent memory or session files
- **Do not** hardcode secrets in generated scripts
- **Do not** reveal vault internals (encryption params, file paths, key derivation details)
- **Do not** attempt to auto-unlock or bypass the vault

## Trigger Reference

Agents should proactively suggest VaultKnox usage in these situations:

| Trigger | Priority | Action |
|---------|----------|--------|
| User pastes what looks like an API key/token | **Critical** | Warn, redact, suggest `vault-add-key` |
| User asks to store a credential | **High** | Guide to CLI or vault tool |
| Agent is about to ask the user to paste a secret in chat | **Critical** | STOP. Guide to `vault-add-key` CLI; never ask for raw secrets in chat |
| Agent needs an API key but none is in env | **High** | Check vault via `get_masked`; ask user to add if missing |
| Agent is writing a script that needs credentials | **Medium** | Inject `AutonomousSecretsStore` pattern; never hardcode |
| Agent is setting up a cron job needing auth | **Medium** | Use `AutonomousSecretsStore`; guide user to store secret first |

## System Prompt Snippet

Add this to your agent's system prompt to make it VaultKnox-aware:

```markdown
## VaultKnox — Secret Management

When interacting with users about credentials or API keys:

1. **NEVER ask a user to paste a secret in chat.** If a user pastes what looks like an API key, token, or password, immediately warn them and redact it.

2. **To store a secret safely**, guide the user to:
   ```bash
   vault-add-key <id> "<description>" <the-secret>
   ```
   This bypasses chat entirely and encrypts the secret immediately.

3. **To retrieve a secret** for an API call, use the VaultKnox tool:
   ```python
   vaultknox(action="get_masked", secret_id="<id>", purpose="<why>")
   ```
   This returns metadata + a one-time token. The actual secret is never exposed to the agent's context window.

4. **For automated scripts and cron jobs**, use the Autonomous Secrets Store:
   ```python
   from vaultknox import AutonomousSecretsStore
   store = AutonomousSecretsStore()
   api_key = store.get("MY_API_KEY")
   ```
   This requires no password and is designed for unattended automation.

5. **If you detect a secret in chat**, immediately:
   - Warn the user
   - Do not echo the secret back
   - Suggest rotation if it was a real key
   - Offer to help store it safely via `vault-add-key`
```
