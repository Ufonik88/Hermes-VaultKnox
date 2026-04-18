# VaultKnox v0.1.0 Release Checklist

## Packaging

- [x] Verify `pip install -e .[dev]` succeeds in a clean environment.
- [x] Verify the `hermes-vault` console script resolves correctly after install.
- [x] Verify runtime artifacts are ignored and not included in source control.

## Quality Gates

- [x] Run `ruff check src tests`.
- [x] Run `PYTHONPATH=src python -m pytest -q`.
- [x] Verify documentation examples match current CLI behavior.

## Security Review

- [x] Confirm no real secrets, backups, or audit logs are committed.
- [x] Confirm Hermes write-gate defaults remain deny-by-default.
- [x] Confirm backup export/import integrity checks still reject tampering.
- [x] Confirm audit logs do not include plaintext secret payloads.

## Public Release Notes

- [x] Confirm README includes alpha warning and threat-model limitations.
- [x] Confirm license and ownership files are present.
- [x] Confirm operator documentation exists for Hermes write-gate usage.
- [x] Confirm release version and changelog summary are accurate.

## Manual Smoke Test

- [x] Initialize a fresh vault.
- [x] Unlock the vault.
- [x] Add a test secret.
- [x] Retrieve a masked response.
- [x] Issue and consume a one-time token.
- [x] Export a backup and re-import it into a clean runtime path.