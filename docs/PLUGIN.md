# VaultKnox Plugin for Hermes

This document covers the install, configuration, and verification path for the VaultKnox plugin shipped with the package. It is the operator-facing counterpart to [AGENT_INTEGRATION.md](AGENT_INTEGRATION.md), which documents the developer-facing hook contracts.

## What Ships

The VaultKnox v0.8.3 package includes a self-contained plugin at `src/vaultknox/_hermes_plugin/` with three files:

| File | Role |
|---|---|
| `__init__.py` | Hook implementations and tool registration |
| `detectors.py` | 28-pattern detector registry (vendored byte-equal to `vaultknox.detectors`) |
| `plugin.yaml` | Plugin manifest declaring `provides_hooks` and `provides_tools` |

`hermes-vault install-hooks` copies these three files into `~/.hermes/plugins/vaultknox/`. The installer is idempotent: re-running it overwrites the destination cleanly with the canonical copies.

Plugin manifest (`plugin.yaml`):

```yaml
name: vaultknox
version: 0.8.3
requires_hermes: ">=0.19"
provides_hooks:
  - pre_gateway_dispatch
  - pre_llm_call
  - transform_llm_output
provides_tools:
  - vaultknox
```

The plugin is `kind: standalone` and adds zero runtime dependencies at import time. The `vaultknox` tool is exposed conditionally: the capability probe (`importlib.util.find_spec("vaultknox")`) runs when Hermes evaluates tool availability and its result is cached briefly (about 30 seconds), so the plugin loads cleanly even when the package is not installed; the tool is only offered when the import succeeds.

## Install

```bash
hermes-vault install-hooks
```

Sample output (paths shown for illustration):

```
  ✅ Installed vaultknox plugin (v0.8.3) to /home/you/.hermes/plugins/vaultknox
     • __init__.py
     • detectors.py
     • plugin.yaml

  To activate, add to Hermes config.yaml:
    plugins:
      enabled:
        - vaultknox
```

If older artifacts are present, the installer reports them without modifying them:

- `~/.hermes/plugins/vaultknox-secret-guard/` — superseded plugin directory. Disable in `~/.hermes/config.yaml` and remove when convenient.
- `~/.hermes/hooks/secret-guard/` — legacy gateway hook directory. Current Hermes does not consume hook-event write-backs, so this directory has no effect; safe to remove.

Then enable the new plugin in `~/.hermes/config.yaml`:

```yaml
plugins:
  enabled:
    - vaultknox
```

Restart the Hermes gateway so the new plugin list is loaded. Plugin loading happens at gateway startup, not per request.

## Verify

Run the following sequence. Each step should produce the listed output; deviations are remediated in [Troubleshooting](#troubleshooting).

### Step 1: files exist

```bash
ls ~/.hermes/plugins/vaultknox/
```

Expected output:

```
__init__.py
detectors.py
plugin.yaml
```

### Step 2: plugin listed in config

```bash
grep -A2 "plugins:" ~/.hermes/config.yaml
```

Expected output (key line):

```
  enabled:
    - vaultknox
```

### Step 3: capability probe passes

In the same Python environment that Hermes uses:

```bash
python -c "import vaultknox; print(vaultknox.__version__)"
```

Expected: a version string printed without traceback. If this fails the tool will not be registered.

### Step 4: inbound redaction live

Send yourself a chat message containing a known API key pattern (for example an `sk-...` string). Expect the reply to be prefixed with a Security Notice and the key replaced with `[REDACTED-SENSITIVE-VALUE]`. Confirm `~/.hermes/sessions/*.jsonl` does not contain the key for that turn.

### Step 5: outbound redaction + rewriting live

Two things happen on `transform_llm_output`:

1. **Value redaction.** The assistant reply is scanned with the same 28-pattern detector registry used inbound; any match is replaced with `[REDACTED-SENSITIVE-VALUE]`. Ask the assistant to quote a detector-matching dummy value back to you — the delivered reply shows the placeholder, not the value.
2. **Solicitation rewrite.** Responses that ask you to share a secret are rewritten to the `hermes-vault add ...` form. The snippet injected by `pre_llm_call` prevents most of this upstream; `transform_llm_output` rewrites any residual phrasing.

Detection is regex-based, so a credential in a shape no detector covers is not redacted.

### Step 6: tool exposed

Ask the agent to call `vaultknox(action="status")`. Expect a JSON status object. A response indicating `vaultknox_not_installed` means the package is not importable in this environment (remediation below).

## Uninstall / Disable

Two options:

1. Disable temporarily (the plugin files stay on disk): remove `vaultknox` from `~/.hermes/config.yaml` and restart Hermes.
2. Remove fully: delete the directory `~/.hermes/plugins/vaultknox/` and remove `vaultknox` from `~/.hermes/config.yaml`. Restart Hermes. The CLI does not currently expose an `uninstall-hooks` command.

## Plugin Update Path

When upgrading the package:

```bash
pip install -U vaultknox
hermes-vault install-hooks   # refresh the deployed copies
```

Restart the Hermes gateway after `install-hooks` completes.

## Troubleshooting

### Plugin loads but nothing happens

| Symptom | Cause | Remediation |
|---|---|---|
| Files present, config lists `vaultknox`, but no redaction | Hermes gateway not restarted after editing `config.yaml` | Restart the Hermes gateway process |
| `pre_llm_call` snippet never appears | Capability probe failed at import time | Confirm `python -c "import vaultknox"` succeeds; reinstall the package in the same env Hermes uses |
| Reinstalls of the package silently no-op | Stale bytecode in `__pycache__` next to the plugin directory | `find ~/.hermes/plugins/vaultknox -name __pycache__ -exec rm -rf {} +` |

### `vaultknox` tool missing

The capability probe could not import the package. Confirm:

```bash
python -c "import vaultknox; print(vaultknox.__version__)"
```

If that fails, install the package in the same Python environment the Hermes gateway uses:

```bash
pip install vaultknox
```

After installation, restart Hermes so the plugin re-registers the tool and the probe runs again. If multiple Python interpreters are involved (for example a venv versus a system install), make sure `hermes` and `python` resolve to the same interpreter that has `vaultknox` installed.

### Vault locked

The master vault requires the operator to unlock before the tool can read or write secrets:

```bash
hermes-vault unlock
```

The session key is then reused for the agent's subsequent calls. If the vault is locked again (after auto-lock at 15 minutes by default; configurable via `hermes-vault init --auto-lock-minutes <n>`), repeat the unlock. The Autonomous Secrets Store has no unlock step; scripts reading from `~/.hermes/encrypted-secrets/` work without operator action as long as the key file is readable.

### Tool returns `{"error": "VaultError", "message": "..."}`

Inspect the message; common causes include:

- Vault not initialized. Run `hermes-vault init`.
- Vault locked. Run `hermes-vault unlock`.
- Missing operator unlock for write actions even though `allow_write=true` was passed (the master vault still needs to be unlocked).
- Secret not found. Confirm `hermes-vault list` shows the id.

### Outbound redaction/rewriting never fires

Confirm the plugin is enabled and the gateway was restarted. `transform_llm_output` is only fired when the plugin is active. Two distinct passes run there: value redaction (the 28-pattern registry) and solicitation rewrite (the 12 outbound phrases in `OUTBOUND_PATTERNS`). If the assistant emits a value or a phrase you expect to be caught, file an issue with the exact string (masked) so the detector or pattern can be checked.

To confirm the deployed copy is current, check its version:

```bash
grep '^version:' ~/.hermes/plugins/vaultknox/plugin.yaml   # expect 0.8.3
```

A deployed 0.8.0 plugin rewrites solicitation phrases but does **not** redact secret values outbound. Re-run `hermes-vault install-hooks` from a v0.8.3 install and restart the gateway.

### Legacy artifacts still on disk

Disable the old entry in `~/.hermes/config.yaml`:

```yaml
plugins:
  enabled:
    - vaultknox   # remove any older - vaultknox-secret-guard entries
```

Then remove the directories:

```bash
rm -rf ~/.hermes/plugins/vaultknox-secret-guard
rm -rf ~/.hermes/hooks/secret-guard
```

Restart Hermes.

## Cross-References

- [AGENT_INTEGRATION.md](AGENT_INTEGRATION.md) — hook contracts and tool schema
- [hermes-write-gate-operations.md](hermes-write-gate-operations.md) — production write-gate policy
- [CHANGELOG.md](../CHANGELOG.md) — release notes for hook contract changes through v0.8.3
