# Agent Integration Guide

This document explains how VaultKnox v0.8.0 integrates with Hermes Agent. It documents the catalog-ready plugin shipped with the package, the three hook contracts it registers, and safe storage and retrieval patterns for agent developers.

## What VaultKnox Does

VaultKnox is an encrypted secrets vault for AI agents. It ensures API keys and credentials never appear in chat logs, session history, or agent context windows. The v0.8.0 plugin redacts inbound messages, injects safe-handling rules, and rewrites outbound assistant responses that ask the user to share a secret.

## The Plugin (v0.8.0)

The VaultKnox package now ships a self-contained plugin at `src/vaultknox/_hermes_plugin/`. `hermes-vault install-hooks` copies three files (`__init__.py`, `detectors.py`, `plugin.yaml`) into `~/.hermes/plugins/vaultknox/` and the operator enables it once in Hermes config.

The legacy `vaultknox-secret-guard` plugin directory and the `~/.hermes/hooks/secret-guard/` gateway hook are superseded. Current Hermes does not consume hook-event write-backs, so the legacy gateway hook was a no-op; the v0.8.0 plugin replaces both. `install-hooks` reports the superseded directories when present and never deletes them.

## Hook Contracts

The plugin registers three hooks (matching Hermes >=0.19 payloads and return shapes) and one tool.

### Hook: `pre_gateway_dispatch`

Runs on every inbound `MessageEvent` before persistence, agent dispatch, and any session storage writes.

Signature (callable registered under the hook name):

```python
def on_pre_gateway_dispatch(event, gateway=None, session_store=None, **kwargs):
    ...
```

Reads `event.text`. When the 28-detector registry finds a secret, the plugin returns:

```python
{"action": "rewrite", "text": "<security notice> + <redacted message>"}
```

The original `event.text` is replaced before anything is persisted; Hermes writes the rewritten value into session storage, so the secret never lands in JSONL logs.

Returns `None` when no detector matches, so the message flows through unchanged.

### Hook: `pre_llm_call`

Runs per LLM turn.

Signature:

```python
def on_pre_llm_call(session_id="", user_message="", conversation_history=None, **kwargs):
    ...
```

Returns the secret-handling rules from `vaultknox.agent_guide.prompts.get_system_prompt_snippet()` as `{"context": <str>}` exactly once per conversation. The plugin scans `conversation_history` for the snippet marker before injecting so the rules are not repeated on every turn. Hermes consumes `{"context": ...}` and prepends it to the user message for that turn.

### Hook: `transform_llm_output`

Runs after the tool loop, before the assistant response is delivered.

Signature:

```python
def on_transform_llm_output(response_text="", **kwargs):
    ...
```

Scans the assistant text for outbound phrases that ask the user to share a secret (`drop your api key`, `paste your key`, `share your token`, etc.). When matched, returns the replacement string. Hermes treats the first non-empty return value from this hook as the new response.

The previous `post_llm_call` hook name does not work on current Hermes: results from it are discarded. Do not register handlers under that name.

### Tool: `vaultknox`

The plugin registers a tool named `vaultknox`, exposed to the agent only when the `vaultknox` package is importable (the capability probe runs an `importlib.util.find_spec("vaultknox")` check).

| Action | Description | Write gate |
|---|---|---|
| `status` | Vault state (initialized/unlocked/count) | No |
| `list` | List secrets (metadata only) | No |
| `get_masked` | Masked view plus optional one-time token | No |
| `get_token` | Issue single-use token for automation | No |
| `consume_token` | Exchange a one-time token for plaintext | No |
| `scan_text` | Scan arbitrary text for secrets | No |
| `lock` | Lock vault | No |
| `add` | Add new secret | Yes (`allow_write=True`) |
| `update` | Update existing secret | Yes |
| `delete` | Remove secret | Yes |
| `inject_env` | Inject a secret into an environment variable | Yes |
| `revoke_token` | Revoke an outstanding one-time token | Yes |

Tool parameters: see the JSON Schema in `src/vaultknox/_hermes_plugin/__init__.py` (`_VAULTKNOX_TOOL_SCHEMA`). The handler dispatches to `vaultknox.hermes_tool.vault_tool(action=..., **{kwargs})` and returns its JSON-serialized output as the tool result.

## Install

```bash
hermes-vault install-hooks
```

Then enable the plugin in `~/.hermes/config.yaml`:

```yaml
plugins:
  enabled:
    - vaultknox
```

Restart the Hermes gateway. Confirm:

```bash
ls ~/.hermes/plugins/vaultknox/
# __init__.py  detectors.py  plugin.yaml
```

If `install-hooks` reports a superseded `vaultknox-secret-guard` plugin directory or `~/.hermes/hooks/secret-guard/`, disable the old entry in `config.yaml` and remove those directories when convenient; current Hermes does not load them.

## Verify

1. Plugin deployed: `ls ~/.hermes/plugins/vaultknox/` shows the three files.
2. Plugin enabled: `vaultknox` is listed under `plugins.enabled` in `~/.hermes/config.yaml`.
3. Plugin live: send yourself a test message containing a known API key pattern. The reply should arrive prefixed with the Security Notice and the key replaced by `[REDACTED-SENSITIVE-VALUE]`. No secret should land in `~/.hermes/sessions/*.jsonl` for that turn.
4. Tool exposed: ask the agent to run `vaultknox(action="status")`. A structured JSON status should be returned; otherwise the package is not importable in this environment (see troubleshooting in [docs/PLUGIN.md](PLUGIN.md)).

## Safe Storage Pattern

Direct users to the shipped CLI (bypasses chat entirely):

```bash
hermes-vault add --id OPENAI_API_KEY --type api_key \
  --label "OpenAI API Key" \
  --data '{"value":"sk-xxxxxxxxxxxxxxxxxxxxxxxx"}'
```

Or call the tool with explicit write consent:

```python
vaultknox(
    action="add",
    secret_id="OPENAI_API_KEY",
    secret_type="api_key",
    label="OpenAI API Key",
    payload={"value": "sk-xxx"},
    allow_write=True,
)
```

Agent paths never accept `master_password`. After an operator unlocks the vault, agent actions use a session-derived key automatically. Only `allow_write=True` is required for write actions.

## Safe Retrieval Pattern

Use the tool to get a masked reference plus a one-time token:

```python
vaultknox(action="get_masked", secret_id="OPENAI_API_KEY", purpose="making API call")
```

The plaintext secret is never exposed to the agent's context window. The caller (a downstream automation script) consumes the token with `vaultknox(action="consume_token", token=...)` to retrieve the secret value out-of-band.

## Automation Pattern

For cron jobs and scripts that need unattended access, use the Autonomous Secrets Store:

```python
from vaultknox import AutonomousSecretsStore

store = AutonomousSecretsStore()
key = store.get("MY_API_KEY")
```

No master password is required. This store reads its key from `~/.hermes/encrypted-secrets/master.key` (chmod 600, owner-only) and is designed for unattended operation.

## What NOT to Do

- Do not ask users to type secrets in chat.
- Do not store secrets in agent memory or session files.
- Do not hardcode secrets in generated scripts.
- Do not reveal vault internals (encryption params, file paths, key derivation details).
- Do not attempt to auto-unlock or bypass the vault.
- Do not register against the dead hook names `post_llm_call`, `message:received`, or rely on `system_message` injection. Only `pre_gateway_dispatch`, `pre_llm_call`, and `transform_llm_output` are current.

## Trigger Reference

Agents should proactively suggest VaultKnox usage in these situations:

| Trigger | Priority | Action |
|---------|----------|--------|
| User pastes what looks like an API key or token | Critical | Warn, redact, suggest `hermes-vault add` |
| User asks to store a credential | High | Guide to CLI or vault tool |
| Agent is about to ask the user to paste a secret in chat | Critical | STOP. Guide to `hermes-vault add`; never ask for raw secrets in chat |
| Agent needs an API key but none is in env | High | Check vault via `get_masked`; ask user to add if missing |
| Agent is writing a script that needs credentials | Medium | Inject `AutonomousSecretsStore` pattern; never hardcode |
| Agent is setting up a cron job needing auth | Medium | Use `AutonomousSecretsStore`; guide user to store secret first |

## System Prompt Snippet

The plugin's `pre_llm_call` hook injects a behavioral snippet (kept byte-equal to `vaultknox.agent_guide.prompts.get_system_prompt_snippet()`) at the start of each conversation. For agents that run outside the plugin (or for testing), the snippet is:

```markdown
## VaultKnox — Secret Management

When interacting with users about credentials or API keys:

1. **NEVER ask a user to paste a secret in chat.** If a user pastes what looks like an API key, token, or password, immediately warn them and redact it.

2. **To store a secret safely**, guide the user to:
   ```bash
   hermes-vault add --id <id> --type api_key --label "<description>" --data '{"value":"<the-secret>"}'
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
   - Offer to help store it safely via `hermes-vault add`
```

## Troubleshooting

Common failure modes and remediations:

- **Plugin loads but nothing happens.** Most often `vaultknox` is not listed under `plugins.enabled` in `~/.hermes/config.yaml`, or the Hermes gateway was not restarted after the edit. Restart and confirm the directory content shown above.
- **`vaultknox` tool missing.** The capability probe couldn't import the package. Install it in the environment the agent uses: `pip install vaultknox` (or `pip install -e .` from the source tree). Confirm with `python -c "import vaultknox; print(vaultknox.__version__)".
- **Vault locked.** The master vault requires the operator to unlock before the tool can read or write secrets. Use `hermes-vault unlock` interactively; the session key is then reused for subsequent agent calls. The Autonomous Secrets Store has no unlock step.
- **Outbound rewriting never fires.** Confirm the plugin is enabled and the gateway restarted; outbound rewriting happens on `transform_llm_output`, which is only loaded when the plugin is active.
- **Inbound redaction never fires.** Same root cause as above; the inbound hook reads `event.text` and only redacts when a detector matches.

See [docs/PLUGIN.md](PLUGIN.md) for the full operator checklist and additional diagnostics.
