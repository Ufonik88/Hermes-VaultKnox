# Hermes Write-Gate Operations Guide

## Purpose

This guide defines how to run VaultKnox safely when Hermes Agent is integrated. The default stance is deny-by-default for writes so Hermes can read masked data and issue tokens without modifying stored secrets unless an operator explicitly allows it.

## Security Model

- Default mode: Hermes write actions are blocked.
- Allowed by default: status, lock, unlock, list, get_masked, get_token.
- Blocked by default: add, update, delete.
- Elevation path: write actions require allow_write=true in the calling integration.

## Deployment Defaults

1. Keep allow_write disabled in production unless there is a clear automation need.
2. Use masked lookups and one-time tokens for booking and payment flows.
3. Keep auto-lock enabled and set to a short duration (15 minutes or less).
4. Restrict file permissions for runtime artifacts to owner-only access.

## Runtime Policy

1. Unlock only when needed for active operations.
2. Re-lock after workflow completion.
3. Never expose raw payloads in Hermes-visible logs, prompts, or memory files.
4. Treat token use as one-time and short-lived.

## Write Enablement Procedure

1. Confirm change window and business justification.
2. Enable write gate only for the required integration process.
3. Perform the minimum needed write operations.
4. Disable write gate immediately after completion.
5. Review audit events for add, update, and delete actions.

## Suggested Integration Guardrails

- Require an explicit operator flag before passing allow_write=true.
- Require master password entry per write session.
- Add a caller identity field to audit details at integration boundaries.
- Add policy checks that reject write calls outside approved automation contexts.

## Incident Handling

If unexpected write actions are observed:

1. Lock the vault immediately.
2. Disable write gate in the Hermes integration layer.
3. Rotate the master password.
4. Review audit logs to identify affected secret IDs and timestamps.
5. Restore from backup if tampering is confirmed.

## Checklist for Production Readiness

- [ ] Write gate defaults to disabled.
- [ ] Hermes workflows use get_masked and get_token paths.
- [ ] Audit logging is enabled and reviewed.
- [ ] Auto-lock is configured and tested.
- [ ] Backup import/export process is documented and tested.
- [ ] Operators know how to enable and disable write gate safely.
