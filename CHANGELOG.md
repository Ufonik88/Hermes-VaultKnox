# Changelog

All notable changes to VaultKnox are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.3] — 2026-09-22

### Documentation accuracy pass

A line-by-line technical-writing review of `README.md`, `docs/PLUGIN.md`, `docs/AGENT_INTEGRATION.md`, `docs/hermes-write-gate-operations.md` and `CHANGELOG.md` against the code. 23 amendments; each was checked against a specific line before it was kept:

- **The Hermes action table listed `export` and `import`, which `vault_tool` rejects**, and omitted `revoke_token`, which it supports. The table now matches `READ_ACTIONS | WRITE_ACTIONS | scan_text`.
- **The detector table mis-graded five detectors.** Google API Key, the GCP service-account private key and the Azure storage connection string are `critical`, not high/medium; the high-entropy assignment is `high`, not medium; the detector is named `Generic Secret Pattern`; the private-key pattern also matches OPENSSH and PGP headers. The three rows now sum to exactly 28.
- **The cron snippet called `python3 ~/.hermes/encrypted-secrets/secrets_manager.py env`**, a script that is not part of the package. Replaced with `eval "$(hermes-secrets env --shell)"`, the shipped entry point (`secrets_env`, `--shell` in `cli.py`), matching the identical snippet a dozen lines above it.
- **`scan_text` findings were described as "logged"; the hook's log line carries only the count and the detector names.** Fingerprints live in returned finding objects. Corrected.
- **The fingerprint is unsalted SHA-256**, and the plugin docstring called it "safe to log" without qualification. Docs and docstrings now say unsalted and say what it does not hide.
- **Safety rule 5 ("every access is logged") over-reached**: `scan_text` returns before the audit write.
- **The tool schema claimed read actions never expose plaintext while listing `consume_token` as a read action.** It now names `consume_token` as the deliberate exception.
- Also corrected: the sub-key tree omitted the v0.7.0 `vaultknox-metadata` and `vaultknox-search` sub-keys; the HKDF row claimed a "token generation" sub-key that does not exist (tokens come from `generate_token`); the capability probe was described as running at every tool dispatch when Hermes caches it for about 30 seconds; the `consume_token` "out-of-band" example pointed at the agent tool call that the next paragraph says puts plaintext into model context, so it now points at `hermes-vault consume-token`; the write-gate guide's allowed-by-default list now carries its `consume_token` and `unlock` conditions; plus duplicate numbering, a duplicated documentation-map row, a run-on changelog pointer, and stale runtime-directory labels.

### Verification

- `PYTHONPATH=src python3 -m pytest tests/ -q` → **387 passed** (documentation, tool-description and docstring text only: no behaviour change, no new tests).
- `ruff check src tests` → clean. `hermes plugins validate src/vaultknox/_hermes_plugin` → 13/13.
- The `[0.8.2]` Verification section below was backfilled in this release from the run actually taken at that commit.

## [0.8.2] — 2026-09-22

### Fixed

- **`inject_env` is now gated by `allow_write`.** The action writes decrypted plaintext into the process environment, and five documents (README action table, README tool row, integration guide table, write-gate guide, plugin tool schema) already advertised it as write-gated, but `hermes_tool.py` classified it in `READ_ACTIONS`, so the agent tool path ran it ungated. It moved to `WRITE_ACTIONS`. The operator CLI path (`hermes-vault inject-env`, which prompts for the master password itself) and the MCP server are unaffected; only the Hermes tool wrapper now requires the flag it always advertised.
- **README safety rule 1 stated "Hermes never sees plaintext secrets" without qualification.** It now names the two deliberate routes by which plaintext does reach the model: an operator policy that authorises raw `consume_token`, and `inject_env`. Reads through `get_masked`/`list`/`get_token` remain plaintext-free.

### Verification

- `PYTHONPATH=src python3 -m pytest tests/ -q` → **387 passed** (0.8.1 baseline: 386 passed; this release added 1 write-gate test and removed none).
- The new `test_hermes_wrapper_gates_inject_env` fails on 0.8.1 with `DID NOT RAISE VaultError` and passes here.
- `ruff check src tests` → clean. `hermes plugins validate src/vaultknox/_hermes_plugin` → 13/13, including the security scan, and again from a fresh clone checked out at the release commit.

## [0.8.1] — 2026-09-22

### Fixed

- **Outbound replies now run the 28-pattern value detector and redact.** The plugin's `transform_llm_output` hook previously called only the solicitation-phrase scanner (`OUTBOUND_PATTERNS` — `drop your api key`, `paste your key`, …). An API key, token, or password sitting in an otherwise neutral assistant reply passed through to the user unchanged, even though the plugin catalog entry and `plugin.yaml` advertised outbound value redaction. Outbound text now takes two passes: (1) the full detector registry redacts matching values to `[REDACTED-SENSITIVE-VALUE]`, (2) solicitation phrases are rewritten on the *redacted* text so span indices stay valid. Returns `None` when nothing matched, preserving Hermes' "first non-empty return wins" contract.
- **Same gap closed in the package-side hook.** `vaultknox.hooks.secret_guard` now exposes `scan_and_redact(text) -> (redacted, findings)` (the loop previously inlined in `handle()`) and `transform_outbound(text) -> str | None`, the complete outbound pass. `handle()` is unchanged in behaviour and now shares the helper.
- **Log hygiene preserved.** Outbound findings log detector *names* and a count only; matches carry a SHA-256 fingerprint, never the raw value.

### Documentation

- **Every claim now matches the code.** `plugin.yaml`, `docs/AGENT_INTEGRATION.md`, `docs/PLUGIN.md`, and `README.md` describe outbound as *solicitation rewrite + secret-value redaction*, and state the scope: detection is regex-based, so a credential in a shape no detector covers is not caught.
- **Trust-boundary caveat documented.** Masked reads (`get_masked`, `list`) and one-time tokens (`get_token`) never expose plaintext to model context, but if the operator's vault policy authorises the raw `consume_token` action for the agent, that handler returns the plaintext value by design — so "never in agent context" holds only for the read actions that return masked refs/tokens.

### Added

- **Regression tests.** `tests/test_hermes_plugin.py::TestOutboundValueRedaction` (detector-positive egress, symmetric control, compose-with-rewrite, log hygiene, idempotence), `tests/test_chat_detection.py::TestOutboundValueRedaction` for the package path, and `tests/test_hermes_plugin_sync.py::test_outbound_transform_parity_with_package_hook` pinning plugin/package output equality. The egress tests fail on v0.8.0 (12 failed / 2 passed when run against the 0.8.0 tree) and pass on v0.8.1.

### Verification

- `PYTHONPATH=src python -m pytest tests/ -q` → **386 passed** (0.8.0 baseline: 372 passed; this release added 14 outbound-redaction tests and removed none)
- New outbound-redaction contracts fail red against `899fd8a` (v0.8.0) and pass on this commit

## [0.8.0] — 2026-09-21

### Added

- **Catalog-ready Hermes plugin shipped inside the package** (`src/vaultknox/_hermes_plugin/`). A single self-contained plugin directory registers three hooks and one tool:
  - `pre_gateway_dispatch` — redacts API keys, tokens, and passwords from inbound messages before they are stored, using the vendored detector registry.
  - `pre_llm_call` — injects the secret-handling rules into the agent's per-turn context (once per conversation).
  - `transform_llm_output` — rewrites outbound responses that ask the user to share a secret.
  - `vaultknox` tool — vault operations (masked reads, one-time tokens, secret scanning); exposed automatically when the `vaultknox` package is importable.
- **`hermes-vault install-hooks` now deploys the packaged plugin** to `~/.hermes/plugins/vaultknox/` (previously it generated a plugin copy inline). It reports superseded `vaultknox-secret-guard` plugin and legacy hook directories but never deletes them.
- **Plugin contract and sync test suites.** `tests/test_hermes_plugin.py` pins the plugin to the current Hermes hook payload/return shapes; `tests/test_hermes_plugin_sync.py` proves the plugin loads standalone (with the package unavailable) and keeps the vendored copies byte-equal to the package originals.
- **Autonomous store tests** (`tests/test_autonomous_secrets.py`): v1→v2 migration round-trip, raw-key recovery, interrupted-state clean failure, and the v2 set/get/list/delete lifecycle.

### Fixed

- **Hook contract drift in the secret-guard plugin (protection restored).** The generated plugin used shapes the current Hermes runtime no longer consumes. Outbound rewriting now happens on `transform_llm_output` (`post_llm_call` results are discarded), inbound redaction reads `event.text` from the `pre_gateway_dispatch` payload and returns `{"action": "rewrite", "text": ...}`, and prompt rules return `{"context": ...}`. Inbound redaction is live for the first time on current Hermes builds.
- **`vaultknox-onboard` plugin.** Removed the dead `pre_gateway_dispatch` hook (`onboard_repo` is not a supported gateway action) and repaired the invalid `plugin.yaml` (a stray docstring line made it unparseable).
- **Guidance standardized on the shipped CLI.** The system-prompt snippet, outbound rewrite, and trigger actions now reference `hermes-vault add ...` instead of `vault-add-key`, which was never part of the public install.
- **GCP private-key detector no longer trips secret scanners on its own definition** — the header literal is assembled from adjacent strings.
- **`hermes-vault get --mask` crashed with a `TypeError`** — the CLI passed the secret id where the password argument belongs. The password is now prompted and forwarded correctly, and the redundant locked-session check that blocked password-based masked reads (the unmasked path never had it) was removed.
- **`hermes-vault health` crashed while rendering its report** — it referenced a non-existent `CheckSeverity.CRITICAL` member instead of `CheckSeverity.ERROR`.
- **Autonomous secrets store migration is now crash-safe.** The v1→v2 migration rewrote the key file *before* the store file; an interruption in between left a key file that could no longer decrypt the store, permanently breaking reads. The migration now rewrites only the store file and keeps the key file bytes as the v2 HKDF input. Store errors surface as clean CLI messages instead of raw tracebacks.

### Verification

- `python -m pytest tests/` → **passed**; `ruff check src tests` → clean
- `hermes plugins validate` against the packaged plugin directory → all checks pass (manifest, capability probe, declared hooks/tools/middleware, security scan)

## [0.7.3] — 2026-07-14

### Security

- **VaultKnox Onboard sandbox — replaced `shell=True` with argv-based execution.** `SandboxExecutor.run()` now passes `shell=False` to `subprocess.Popen`, with commands tokenized through `shlex.split`. Shell metacharacters such as `;`, `&&`, `$()`, backticks, pipes, and newlines are no longer interpreted, closing the command-chaining bypass that existed under the previous implementation.
- **Sensitive-path argument blocklist added.** Even when the command binary is allowlisted, arguments that reference `/.ssh/`, `/.gnupg/`, `/etc/shadow`, `/etc/passwd`, `/proc/`, or `/sys/` are rejected before execution.
- **Secret environment variables are stripped from child processes.** Common credential-bearing variables (`GITHUB_TOKEN`, `AWS_SECRET_ACCESS_KEY`, `VAULTKNOX_MASTER_PASSWORD`, etc.) are removed from `env` before `Popen`, preventing build/install scripts from inheriting the parent process's secrets via stdout/stderr.
- **Process-group timeout kill.** Timeout now sends `SIGKILL` to the entire process group, not just the shell PID, preventing fork-bomb survivors after the timeout window.

### Verification

- `PYTHONPATH=src python -m pytest -q` → **passed**
- New regression suite: `tests/onboard/test_onboard.py::TestSandboxSecurity` (8 tests covering metacharacters, sensitive paths, env stripping, and timeout kill behavior).

## [0.7.2] — 2026-07-10

### Added

- **VaultKnox Onboard — autonomous repository onboarding** — the first new capability shipped after the v0.7.1 security-hardening release (PR #8). A new `onboard` command group lets Hermes Agent analyze, document, and prepare any repository for AI-driven development (Python, Node.js, Rust, Go, Ruby, PHP, and more).
  - `vaultknox onboard analyze` — detect languages, frameworks, dependency manifests, entry points, test directories, and repo structure (`src/vaultknox/onboard/analyzer/`).
  - `vaultknox onboard document` — generate `AGENTS.md`, `README.md`, `SETUP.md`, and `ARCHITECTURE.md` from analysis; existing user-authored files are never overwritten (`src/vaultknox/onboard/documenter/`).
  - `vaultknox onboard setup` — install dependencies, run build checks, and surface missing environment variables (`src/vaultknox/onboard/environment/`).
  - `vaultknox onboard full` — the recommended first-contact pipeline: analyze → document → setup in one run.
  - `vaultknox onboard install-plugin` — deploy the `vaultknox-onboard` gateway plugin to `~/.hermes/plugins/` for automatic onboarding-request detection.
  - `vaultknox onboard generate-skill` — emit a `SKILL.md` contract describing VaultKnox Onboard for sub-agents.
- **Milestone note** — Onboard is the first feature to land on `main` since the v0.7.1 hardening release, reopening the post-hardening feature track.

## [0.7.0] — 2026-06-23

### Added

- **Metadata encryption at rest** — secret metadata is now encrypted under a dedicated `vaultknox-metadata` HKDF sub-key using AES-256-GCM, ensuring service names, username hints, and scope info are never stored in plaintext in the SQLite database (`src/vaultknox/core.py`, `src/vaultknox/vault.py`).
- **Encrypted search index** — deterministic search tokens (AES-GCM with content-derived nonce) are generated per payload field and stored in a `search_index` table, enabling future exact-match search without exposing plaintext values (`src/vaultknox/core.py`, `src/vaultknox/db.py`).
- **Metadata minimization** — username hints now store only first+last character (e.g. `j***n`); URLs are stored as host-only; full values never appear in metadata fields (`src/vaultknox/types.py`).
- **Configurable KDF parameters** — `init` command accepts `--kdf-time-cost`, `--kdf-memory-cost`, `--kdf-parallelism`, `--kdf-hash-len`, and `--kdf-type` for Argon2 tuning; parameters are persisted and reused on subsequent unlocks (`src/vaultknox/cli.py`, `src/vaultknox/vault.py`, `src/vaultknox/core.py`).
- **Vault profiles** — global `--profile <name>` flag routes vault storage to `~/.hermes/vaultknox-profiles/<name>/` for isolated vault environments (`src/vaultknox/config.py`, `src/vaultknox/cli.py`).
- **`get_token` policy TTL clamping** — one-time token TTL is now clamped by agent/service policy, matching `get_masked` behavior (`src/vaultknox/hermes_tool.py`).
- **Agent actions reject `master_password` kwarg** — agent-facing actions (`add`, `update`, etc.) now raise `VaultError` if `master_password` is passed, enforcing the session-derived key path (`src/vaultknox/hermes_tool.py`).
- **MCP scan capability check** — `vaultknox_scan` MCP tool requires `agent_id` and checks `scan_secrets` capability via PolicyEngine (`src/vaultknox/mcp_server.py`).
- **Policy enforcement test suite** — new `tests/test_policy_enforcement.py` covering deny-by-default behavior, per-service allow/deny, raw-secret access gating, policy TTL clamping, encrypted metadata service resolution, and denial response safety.
- **OAuth refresh test suite** — new `tests/test_oauth_refresh.py` validating near-expiry refresh persistence and non-throwing refresh failure fallback.
- **Dashboard hardening tests** — new `tests/test_dashboard.py` validating API token bootstrap/cookie flow and hardened response headers.
- **Detector coverage expansion** — scanner tests now include additional detector behavior and entropy helper assertions.
- **Rotation metadata/search re-encryption tests** — `tests/test_rotation.py` now verifies metadata and search tokens are re-encrypted after rotation.

### Changed

- **Version bump** — package and runtime version advanced to `0.7.0`.
- **Session-derived key path finalized** — vault operations used by agents (`add`, `update`, `delete`, `consume_token`, `inject_env`, and related flows) operate via session key after operator unlock, without forwarding `master_password` through agent tool kwargs.
- **Policy Engine v2 activation** — `vault_tool` now enforces policy for agent actions with deny-by-default semantics, action-to-policy mapping, capability checks, service resolution, raw-secret access gating, audited denials, and policy-constrained token TTL.
- **MCP policy alignment** — MCP tool schemas and handlers now support `agent_id` and route through policy-aware paths for metadata/list/status access.
- **Autonomous store crypto migration** — autonomous secrets now use AES-256-GCM v2 storage, with legacy Fernet v1 files auto-migrated on load.
- **PolicyDoctor service resolution** — patch generation now resolves service from secret metadata before fallback heuristics; service resolution also handles encrypted metadata, note types, and type-based fallback.
- **OAuth retrieval behavior** — OAuth secrets are refreshed on read when near expiry (if provider/client/refresh data is present), with encrypted persistence of refreshed tokens.
- **Dashboard auth model hardening** — dashboard now supports Authorization/Cookie auth, enforces real token TTL, blocks query-token API access after bootstrap, and sets `Cache-Control: no-store` + `X-Content-Type-Options: nosniff` headers.
- **Detector and scanner improvements** — added Google API key, GCP private-key marker, Azure connection string, JWT, and high-entropy secret assignment detection; scanner now applies entropy thresholding and placeholder allowlist filtering for generic high-entropy matches.
- **`get_masked` now accepts password parameter** — `get_masked(password, secret_id, ...)` for consistent API surface across vault operations.
- **Bulk import uses encrypted metadata and search tokens** — `bulk_import_secrets` now encrypts metadata and generates search tokens for each entry.
- **Rotation re-encrypts metadata and search tokens** — master key rotation now also re-encrypts metadata and regenerates search tokens under the new key.
- **CLI `_vault()` accepts profile parameter** — internal factory passes profile to `expand_runtime_path` for profile-based directory resolution.

### Security

- **Metadata is now encrypted at rest** — service names, username hints, and scope data are AES-256-GCM encrypted under a dedicated HKDF sub-key; plaintext metadata never written to the database.
- **Username hints minimized** — only first and last character stored (e.g. `j***n`); full username never leaked via metadata.
- **URLs stored as host-only** — full URLs never appear in metadata; only the hostname component is retained.
- **Agent actions reject `master_password` kwarg** — prevents accidental password forwarding in session-key flows.
- **Policy controls are now live** instead of inert for the primary agent-access paths.
- **Token handling is stricter** on dashboard and policy-constrained on metadata token issuance.
- **Encrypted metadata/search invariants verified** — metadata and deterministic search tokens are re-encrypted on writes, imports, OAuth refreshes, and master-key rotation.
- **OAuth secrets are less likely to silently expire** due to refresh-on-read behavior and failure signaling.

### Verification

- `PYTHONPATH=src python -m pytest -q` → **passed**

## [0.6.1] — 2026-06-10

### Fixed

- **Broken public package exports** — `AutonomousSecretsStore` and `AutonomousSecretsError` were listed in `vaultknox.__all__` but never imported, so `from vaultknox import AutonomousSecretsStore` failed despite being documented in README and `docs/AGENT_INTEGRATION.md`. Both symbols are now exported correctly.
- **Timezone-naive token and lockout comparisons** — Extended the v0.6.0 expiry normalization to `consume_token` and vault lockout checks so naive ISO timestamps no longer raise `TypeError` when compared against UTC `datetime.now()`.
- **Session auto-lock with naive timestamps** — `SessionStore.is_unlocked()` now treats naive `expires_at` values as UTC before comparing, preventing a crash if `session.json` is hand-edited or migrated from older data.

### Changed

- **Skill generator version** — `SkillGenerator` now uses `vaultknox.__version__` instead of a hardcoded version string, so generated `SKILL.md` files stay in sync with releases.
- **MCP verify handler** — Removed a misleading dead `try/except` block; the tool still correctly returns `requires_master_password` because MCP has no password channel.

### Added

- `tests/test_package_exports.py` — guards `__all__` completeness and the documented `from vaultknox import AutonomousSecretsStore` import path.
- `test_naive_timezone_token_expiry_is_handled_safely` in `tests/test_vault.py`.

## [0.6.0] — 2026-06-09

### Fixed (Security & Code Review — v0.5.0 → v0.6.0)

- **MCP Server crash on `vaultknox_scan`** — `Path` was used but not imported in `mcp_server.py`. Also removed dead imports (`sys`, `VaultPaths`, `run_health_checks`, duplicate `stdio_server`/`Tool`) and switched internal path handling from the non-existent `get_default_paths` to `expand_runtime_path` (with correct attribute usage). The scan and health tool paths now execute cleanly.
- **Generic bearer verification** — `_verify_generic_bearer` was implemented but never registered. Added `register_provider("generic_bearer", _verify_generic_bearer)` so `--service generic_bearer` (and live verification flows) work instead of returning "Unknown service".
- **`install-hooks` now actually writes the gateway plugin** — The command previously only read `~/.hermes/plugins/vaultknox-secret-guard/__init__.py` and printed a warning if v0.4.2 hooks were missing. It now **writes** a complete, standalone `__init__.py` (and `plugin.yaml`) implementing `pre_gateway_dispatch`, `pre_llm_call`, and `post_llm_call`, plus a `register(ctx)` helper compatible with both `ctx.register_hook` and `ctx.on`. The legacy `~/.hermes/hooks/secret-guard` handler continues to be written for older paths.
- **Timezone-naive expiry dates caused TypeError crashes** — `datetime.fromisoformat()` on strings without offsets (e.g. `2026-12-31`) produced naive datetimes that were compared to `datetime.now(timezone.utc)`, raising `TypeError`. Added `_parse_and_normalize_expiry` (and equivalent inline normalization in the CLI) and applied it in `VaultKnox.get_raw`, `get_masked`, the `list --expired` filter, and `expiry-notify`. A new test `test_naive_timezone_expiry_is_handled_safely` covers the case.
- **Overlapping/nested span redaction corruption in secret-guard** — `handle()` sorted redactions in reverse start order but did not merge overlapping or nested matches first. Multiple detectors hitting the same or nested regions produced nested `[REDACT[REDACTED...` output or index-shift corruption. Added a pre-pass that merges spans before replacement (both inbound `handle()` and the outbound rewrite path already had similar logic; inbound is now consistent).
- **31 ruff violations cleaned** — Unused imports, import sort order, bare `f`-string issues, and a few manual cleanups across `dashboard.py`, `mcp_server.py`, `oauth/__init__.py`, `policy.py`, `skills/__init__.py`, `cli.py`, `vault.py`, `verifier.py`, and `secret_guard.py`. `uv run ruff check` now reports zero violations. Several "except Exception as e: raise ClickException(str(e))" sites were updated to `from e` chaining for better tracebacks.

### Added

- `tests/test_mcp_server.py` — new test module covering MCP server import hygiene (no NameError on `Path` etc.), tool schema completeness, direct exercise of the scan/status code paths that the handlers use, and error-path shapes. This guards the historical `vaultknox_scan` crash site and the `SecretScanner(paths=[...])` construction used by the MCP scan tool.
- Additional unit coverage in `tests/test_vault.py` (naive expiry) and `tests/test_verifier.py` (end-to-end `generic_bearer` via `CredentialVerifier.verify`).
- Version bumped to 0.6.0 (pyproject.toml, `vaultknox/__init__.py`, skill generator template).

### Changed

- `VaultKnox.status()` is now defensive: if the vault has not been initialized (no `vault_config` table yet), it falls back to the default auto-lock minutes instead of raising `sqlite3.OperationalError`. This makes status/health queries safe on a brand-new vault directory (important for MCP/dashboard early calls).
- Minor import reordering and dead-code removal in several modules as part of the lint sweep (no behavior change).

### Security / Robustness

- All critical functional bugs and security-relevant gaps identified in the v0.5.0 → v0.6.0 review have been closed.
- Redaction is now overlap-safe (prevents accidental leakage or garbled messages when multiple detectors match the same secret).
- Expiry handling no longer crashes on user-supplied or previously-stored naive ISO dates.
- Gateway plugin deployment is now reliable — the `vaultknox-secret-guard` hooks that implement outbound secret-request blocking and system-prompt injection will actually be present after `install-hooks`.

## [0.5.0] — 2026-05-20

### Added

- **MCP Server** (`hermes-vault mcp`) — stdio-based MCP transport for direct agent integration
  - Tools: status, list, get_metadata, scan, verify, health
  - Sub-agents can access vault without operator proxying every call
- **Dashboard Console** (`hermes-vault dashboard`) — local token-guarded web UI (127.0.0.1 only)
  - Views: Health, Credentials, Audit, Scanner
  - No raw secrets exposed in browser
- **OAuth PKCE** (`hermes-vault oauth`) — RFC 7636 PKCE flow
  - Providers: Google, GitHub, OpenAI
  - Auto-refresh tokens when expired
- **Skill Generation** (`hermes-vault generate-skill`) — generates SKILL.md contracts for sub-agents
  - Defines credential access patterns, allowed services, security rules
  - Prevents agents from freelancing credential discovery
- **Policy Engine v2** (`src/vaultknox/policy.py`) — per-agent, per-service action policies
  - Actions: get_credential, get_env, get_metadata, verify, rotate, delete, add
  - Agent capabilities: list_credentials, scan_secrets, export_backup
- **Secret type: `oauth`** — new type with refresh_token support
  - Auto-refresh before expiry

### Changed

- **Package version bumped** to 0.5.0
- **MCP 1.26 compatibility** — fixed stdio server for new async API

### Security

- Agents access vault directly via MCP — no plaintext passed through chat
- Dashboard uses token auth, no secrets in browser
- Policy engine enforces deny-by-default per service

## [0.4.2] — 2026-05-13

### Added

- **Outbound Response Scanner** (`post_llm_call` hook) — scans AI responses before they reach the user for phrases that ask users to paste secrets in chat. Detected phrases are automatically rewritten with safe guidance directing users to `vault-add-key` CLI.
- **System Prompt Injection** (`pre_llm_call` hook) — injects VaultKnox behavioural rules into the system message before each LLM call, preventing the AI from requesting secrets in the first place.
- **`agent_requests_secret` trigger** — new critical-priority trigger in `agent_guide/triggers.py` that detects when the agent is about to ask for a secret in chat and blocks it with safe guidance.
- **Enhanced `install-hooks` command** — now also deploys/updates the gateway plugin (plugin.yaml) alongside the legacy hook, ensuring both inbound and outbound protection are in place.

### Changed

- **Plugin version bumped** to 0.4.2 (adds `post_llm_call` and `pre_llm_call` to `provides_hooks`).
- **Package version bumped** to 0.4.2.

### Security

- AI agents can no longer request secrets via chat — outbound scanner catches and rewrites secret-requesting phrases.
- System prompt injection ensures the AI is proactively instructed to never ask for secrets, providing defense-in-depth beyond pattern matching.

## [0.4.1] — 2026-05-12

### Fixed

- **Secret-Guard hook now actually fires** (`HOOK.yaml` + `src/vaultknox/hooks/secret_guard.py`)
  - Hook was registered for `message:received` but the gateway never emitted that event — it was completely dormant
  - Added `message:received` emitter at the correct ingress point in `gateway/run.py` (line ~7488), BEFORE `agent:start` and BEFORE any persistence
  - Hook also now handles `agent:start` as a defense-in-depth layer for CLI/non-gateway paths
  - Supports `message:received` (full content via `content` key) and `agent:start` (truncated via `message` key)

- **VaultKnox gateway plugin** (`~/.hermes/plugins/vaultknox-secret-guard/`)
  - Created Hermes plugin using `pre_gateway_dispatch` hook point (survives `hermes update`)
  - Scans every incoming message BEFORE session/auth/agent using 23 detectors
  - Auto-redacts secrets and prepends a security warning with rotation guidance
  - Enabled in config as `vaultknox-secret-guard`

- **History sanitized** — `vaultknox sanitize-history --apply` ran and redacted 2,775 secret occurrences across 35 files (session JSONL, state.db, shell history)

## [0.4.0] — 2026-05-07

### Added

- **Chat Secret Detection & Redaction** (`src/vaultknox/detectors.py` + `src/vaultknox/hooks/secret_guard.py`)
  - Hook logic lives in `src/vaultknox/hooks/secret_guard.py` and is installed to `~/.hermes/hooks/` via `vaultknox install-hooks`
  - Uses the existing 21-detector registry to scan every incoming message for secrets
  - Auto-redacts detected secrets in-place (replaces with `[REDACTED-SENSITIVE-VALUE]`)
  - Auto-warns the user with contextual guidance when a secret is detected in chat
  - Covers: session JSONL files, `state.db`, Mem0, CLI history, and gateway logs (when hook is installed)

- **Log Sanitization Filter** (companion feature in Hermes core)
  - `SecretSanitizationFilter` — a `logging.Filter` that redacts detector matches from all gateway log records
  - Lives in the Hermes core repo (`gateway/logging_filters.py`); not part of the VaultKnox package
  - Automatically attached to the `gateway` logger on startup
  - Prevents accidental secret leakage in log files, tracebacks, and debug output

- **`vaultknox sanitize-history` CLI**
  - Scans `~/.hermes/sessions/*.jsonl`, `state.db`, and `.hermes_history` for leaked secrets
  - Dry-run by default (`--apply` required to actually modify files)
  - Merges overlapping detector spans before replacement to avoid corruption
  - Shows summary: files scanned, files with secrets, total occurrences

- **`vaultknox(action="scan_text")` Tool Action** (`src/vaultknox/hermes_tool.py`)
  - Lets any agent proactively scan arbitrary text for secrets without touching the vault
  - Returns structured findings with detector name, severity, matched text, and span positions
  - Zero vault unlock required — pure detection

- **Agent Autonomy Package** (`src/vaultknox/agent_guide/`)
  - `TRIGGERS` — 5 built-in trigger patterns (API key paste, credential request, missing key, script writing, cron setup)
  - `check_triggers(text)` — returns matched triggers with priority and recommended action
  - `get_system_prompt_snippet()` — copy-paste ready system prompt block for any AI agent
  - Public documentation: `docs/AGENT_INTEGRATION.md` — safe for GitHub (no vault internals)

### Changed

- `__init__.py` exports — new public symbols: `TRIGGERS`, `check_triggers`, `get_system_prompt_snippet`
- Bumped version: `0.3.0` → `0.4.0`

### Security

- Secret-guard hook (installable via `vaultknox install-hooks`) redacts secrets in incoming messages before they reach session storage
- `sanitize-history` provides a one-command cleanup for accidental chat leaks
- No new regex patterns added — reuses the existing 21-detector registry to avoid pattern drift

## [0.3.0] — 2026-05-06

### Added

- **Master Key Rotation** (`src/vaultknox/rotation.py`)
  - `vaultknox rotate-master-key` — Atomically rotate the vault master password
  - Pre-rotation encrypted backup: backup is encrypted with the OLD password only, so the new password cannot decrypt it (defence-in-depth)
  - HMAC-SHA256 integrity signature on every backup
  - Single SQLite transaction for all re-encryption — vault is never in a partially-updated state
  - Automatic rollback on failure: restores from the pre-rotation backup automatically
  - `list_pre_rotation_backups()` and `delete_pre_rotation_backup()` helpers for manual cleanup

- **Live Credential Verification** (`src/vaultknox/verifier.py`)
  - `vaultknox verify [--service openai|anthropic|github|google_oauth] [--all]`
  - Validates API keys stored in the vault against live provider endpoints
  - Supports: OpenAI, Anthropic, GitHub, Google OAuth, Generic Bearer tokens
  - Returns structured status: `valid`, `invalid`, `billing_issue`, `network_error`, `unknown`
  - 5-second default timeout, 10-second maximum
  - API keys are never logged or echoed

- **Secret Scanner** (`src/vaultknox/scanner.py` + `src/vaultknox/detectors.py`)
  - `vaultknox scan [--paths /path/a,/path/b] [--format json|cli]`
  - Scans files for 21+ plaintext secret patterns: OpenAI, GitHub (6 types), Anthropic, AWS, Stripe, Twilio, SendGrid, NPM, RSA keys, and generic patterns
  - Flags files with unsafe permissions (world-readable `.env` and `.json` files)
  - Detects duplicate secrets across files via SHA-256 fingerprinting
  - Large file protection: 5 MB hard cap, 100 KB line limit
  - Skips `node_modules`, `.git`, `__pycache__`, `.pytest_cache`
  - Output as emoji table (CLI) or structured JSON

- **Vault Health Check** (`src/vaultknox/health.py`)
  - `vaultknox health [--format json|cli]`
  - Checks: DB permissions (0o600), audit log permissions, SQLite integrity (`PRAGMA integrity_check`), vault config completeness, encryption integrity (sample decrypt), audit log readability
  - Reports overall status: `healthy`, `degraded`, or `critical`
  - Exit codes: 0 (healthy), 1 (degraded), 2 (critical)

- **Audit Log Query CLI** (`src/vaultknox/audit.py`)
  - `vaultknox audit query [--action X] [--status success|failure] [--secret-id X] [--since -7d] [--until ISO] [--limit N] [--json]`
  - Filter by action, status, secret ID, and date range (supports relative dates like `-7d`, `-24h`)
  - Reads from main audit log and rotated backups (newest-first)
  - JSON output for scripting

- **Expiry Management** (`src/vaultknox/expiry.py`)
  - `vaultknox expiry set-expiry <id> --days 30` — Set expiry on a secret
  - `vaultknox expiry clear-expiry <id>` — Remove expiry from a secret
  - `vaultknox expiry notify` — Report expired and expiring-within-7-days secrets
  - `vaultknox list --expired` — Show only expired secrets

- **`__init__.py` exports** — New public symbols available for import:
  - `rotate_master_key`, `SecretScanner`, `CredentialVerifier`, `VaultHealthChecker`

### Changed

- Updated README with full v0.3.0 feature documentation
- Bumped version: `0.2.0` → `0.3.0`

### Security

- Pre-rotation backup encrypted with OLD password only — provides defence-in-depth against new password compromise
- All backups HMAC-SHA256 signed and chmod 600
- API keys never appear in scanner output, logs, or terminal echo

## [0.2.0] — 2026-05-05

### Added

- **Autonomous Secrets Store** (`src/vaultknox/autonomous_secrets.py`)
  - Key-file-backed encrypted credential storage (legacy format later migrated to AES-256-GCM v2)
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
- Updated README with clear Security Model and Getting Started sections
  - Clear explanation of key-file-backed security model
  - Removed outdated master password references
  - Added prominent Getting Started example
  - Documented encrypted-secrets directory structure
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
