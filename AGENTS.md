# AGENTS.md — Hermes VaultKnox

Guidance for the encrypted secrets vault.

## Critical Rules
- **Never** echo, store, or log the master password in plaintext
- Always deliver credentials via Signal DM (E2E) when needed
- Use the vault CLI directly for operations

## Security Protocol
- Seed accounts: generate random password → hash in DB → force password change on first login
- Never share temporary or seed passwords in Discord/Telegram channels

Last updated: 2026-05-19