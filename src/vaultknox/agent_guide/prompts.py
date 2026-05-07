"""Ready-to-use system prompt snippets for VaultKnox-aware agents."""


def get_system_prompt_snippet() -> str:
    """Return a concise markdown block that tells agents how to handle secrets.

    Safe for injection into any agent's system prompt — contains no encryption
    internals, file paths, or master password mechanics.
    """
    return """
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
""".strip()
