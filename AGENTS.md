# AGENTS.md — Hermes VaultKnox

Guidance for AI agents operating alongside the encrypted secrets vault.

## Critical Rules

- **Never** echo, store, or log the master password in plaintext.
- Never ask users to paste credentials in chat; direct them to the CLI.
- Deliver credentials only through secure, out-of-band channels.
- Use the vault CLI and the `vaultknox` tool for all secret access; never
  hardcode secrets in code, prompts, or memory files.

## Operational Rules

- Prefer masked reads (`get_masked`) and one-time tokens (`get_token`).
- Treat issued tokens as single-use and short-lived.
- Keep write actions (`add`, `update`, `delete`) behind the explicit
  `allow_write=true` flag and operator approval.
- Review audit events after any write session.

Last updated: 2026-09-21
