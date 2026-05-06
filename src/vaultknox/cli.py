from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import click

from vaultknox.autonomous_secrets import AutonomousSecretsError, AutonomousSecretsStore
from vaultknox.branding import get_logo_asset_path, get_logo_banner
from vaultknox.config import expand_runtime_path
from vaultknox.vault import VaultError, VaultKnox


class _VaultGroup(click.Group):
    """Click group that converts VaultError and ValueError into clean ClickException messages."""

    def invoke(self, ctx: click.Context) -> object:
        try:
            return super().invoke(ctx)
        except (VaultError, ValueError) as exc:
            raise click.ClickException(str(exc)) from exc


def _vault(runtime_dir: str | None) -> VaultKnox:
    return VaultKnox(expand_runtime_path(runtime_dir))


def _prompt_password(confirm: bool = False) -> str:
    return click.prompt("Master password", hide_input=True, confirmation_prompt=confirm)


def _prompt_secret_payload(secret_type: str) -> dict[str, Any]:
    """Interactively collect secret fields for the given type. Sensitive fields use hide_input."""
    if secret_type == "api_key":
        payload: dict[str, Any] = {
            "service": click.prompt("Service"),
            "key": click.prompt("API key", hide_input=True),
        }
        scope = click.prompt("Scope (optional, press enter to skip)", default="")
        if scope:
            payload["scope"] = scope
        return payload
    if secret_type == "credential":
        payload = {
            "username": click.prompt("Username"),
            "password": click.prompt("Password", hide_input=True),
        }
        url = click.prompt("URL (optional, press enter to skip)", default="")
        if url:
            payload["url"] = url
        return payload
    if secret_type == "note":
        return {"content": click.prompt("Note content")}
    if secret_type == "connection_string":
        return {"value": click.prompt("Connection string", hide_input=True)}
    if secret_type == "password":
        return {"value": click.prompt("Password value", hide_input=True)}
    raise click.UsageError(f"Interactive prompts are not supported for type '{secret_type}'. Use --data with a JSON payload.")


@click.group(cls=_VaultGroup)
@click.option("--runtime-dir", type=click.Path(path_type=Path), default=None, help="Override the runtime vault directory.")
@click.option("--logo", "show_logo", is_flag=True, default=False, help="Display the VaultKnox ASCII logo before command output.")
@click.pass_context
def main(ctx: click.Context, runtime_dir: Path | None, show_logo: bool) -> None:
    ctx.ensure_object(dict)
    ctx.obj["vault"] = _vault(str(runtime_dir) if runtime_dir else None)
    if show_logo:
        click.echo(get_logo_banner())


@main.command()
@click.option("--asset-path", is_flag=True, default=False, help="Also print the packaged SVG asset path.")
def logo(asset_path: bool) -> None:
    click.echo(get_logo_banner())
    if asset_path:
        click.echo(f"SVG logo: {get_logo_asset_path()}")


@main.command()
@click.pass_obj
def status(obj: dict[str, VaultKnox]) -> None:
    vault = obj["vault"]
    state = vault.status()
    click.echo(json.dumps({
        "initialized": state.initialized,
        "unlocked": state.unlocked,
        "secret_count": state.secret_count,
        "auto_lock_minutes": state.auto_lock_minutes,
    }, indent=2))


@main.command()
@click.option("--auto-lock-minutes", default=15, show_default=True, type=int)
@click.pass_obj
def init(obj: dict[str, VaultKnox], auto_lock_minutes: int) -> None:
    vault = obj["vault"]
    password = _prompt_password(confirm=True)
    vault.initialize(password, auto_lock_minutes=auto_lock_minutes)
    click.echo("Vault initialized")


@main.command()
@click.pass_obj
def unlock(obj: dict[str, VaultKnox]) -> None:
    vault = obj["vault"]
    result = vault.unlock(_prompt_password())
    click.echo(json.dumps(result, indent=2))


@main.command()
@click.pass_obj
def lock(obj: dict[str, VaultKnox]) -> None:
    vault = obj["vault"]
    vault.lock()
    click.echo("Vault locked")


@main.command("list")
@click.option("--expired", is_flag=True, default=False, help="Show only expired secrets.")
@click.pass_obj
def list_command(obj: dict[str, VaultKnox], expired: bool) -> None:
    vault = obj["vault"]
    from datetime import datetime, timezone
    secrets = vault.list_secrets()
    if expired:
        now = datetime.now(timezone.utc)
        secrets = [s for s in secrets if s.get("expires_at") and datetime.fromisoformat(s["expires_at"]) <= now]
    click.echo(json.dumps(secrets, indent=2))


@main.command()
@click.option("--id", "secret_id", required=True)
@click.option("--type", "secret_type", required=True)
@click.option("--label", required=True)
@click.option("--data", default=None, help="Secret payload as JSON. Omit to use interactive field prompts.")
@click.option("--expires-at", default=None, help="Expiry datetime in ISO 8601 format (e.g. 2025-12-31T00:00:00+00:00).")
@click.pass_obj
def add(obj: dict[str, VaultKnox], secret_id: str, secret_type: str, label: str, data: str | None, expires_at: str | None) -> None:
    vault = obj["vault"]
    payload = json.loads(data) if data is not None else _prompt_secret_payload(secret_type)
    result = vault.add_secret(_prompt_password(), secret_id, secret_type, label, payload, expires_at=expires_at)
    click.echo(json.dumps(result, indent=2))


@main.command()
@click.argument("secret_id")
@click.option("--type", "secret_type", required=True)
@click.option("--label", required=True)
@click.option("--data", default=None, help="Secret payload as JSON. Omit to use interactive field prompts.")
@click.option("--expires-at", default=None, help="Expiry datetime in ISO 8601 format (e.g. 2025-12-31T00:00:00+00:00).")
@click.pass_obj
def update(obj: dict[str, VaultKnox], secret_id: str, secret_type: str, label: str, data: str | None, expires_at: str | None) -> None:
    vault = obj["vault"]
    payload = json.loads(data) if data is not None else _prompt_secret_payload(secret_type)
    result = vault.update_secret(_prompt_password(), secret_id, secret_type, label, payload, expires_at=expires_at)
    click.echo(json.dumps(result, indent=2))


@main.command()
@click.argument("secret_id")
@click.option("--mask", is_flag=True, default=False)
@click.option("--purpose", default=None, help="Issue a one-time token for this purpose.")
@click.pass_obj
def get(obj: dict[str, VaultKnox], secret_id: str, mask: bool, purpose: str | None) -> None:
    vault = obj["vault"]
    result = vault.get_masked(secret_id, purpose=purpose) if mask else vault.get_secret(_prompt_password(), secret_id)
    click.echo(json.dumps(result, indent=2))


@main.command()
@click.argument("secret_id")
@click.pass_obj
def delete(obj: dict[str, VaultKnox], secret_id: str) -> None:
    vault = obj["vault"]
    vault.delete_secret(_prompt_password(), secret_id)
    click.echo("Secret deleted")


@main.command("issue-token")
@click.argument("secret_id")
@click.option("--purpose", required=True)
@click.pass_obj
def issue_token(obj: dict[str, VaultKnox], secret_id: str, purpose: str) -> None:
    vault = obj["vault"]
    click.echo(vault.issue_token(secret_id, purpose))


@main.command("consume-token")
@click.argument("token")
@click.pass_obj
def consume_token(obj: dict[str, VaultKnox], token: str) -> None:
    vault = obj["vault"]
    result = vault.consume_token(_prompt_password(), token)
    click.echo(json.dumps(result, indent=2))


@main.command()
@click.option("--file", "file_path", required=True, help="Backup file location.")
@click.pass_obj
def export(obj: dict[str, VaultKnox], file_path: str) -> None:
    vault = obj["vault"]
    result = vault.export_vault(_prompt_password(), file_path)
    click.echo(json.dumps(result, indent=2))


@main.command("import")
@click.option("--file", "file_path", required=True, help="Backup file location.")
@click.option("--force", is_flag=True, default=False, help="Replace existing vault database.")
@click.pass_obj
def import_command(obj: dict[str, VaultKnox], file_path: str, force: bool) -> None:
    vault = obj["vault"]
    result = vault.import_vault(_prompt_password(), file_path, force=force)
    click.echo(json.dumps(result, indent=2))


@main.command("change-password")
@click.pass_obj
def change_password(obj: dict[str, VaultKnox]) -> None:
    vault = obj["vault"]
    current = click.prompt("Current master password", hide_input=True)
    new_password = click.prompt("New master password", hide_input=True, confirmation_prompt=True)
    vault.change_password(current, new_password)
    click.echo("Master password changed")


@main.command("inject-env")
@click.option("--id", "secret_id", required=True, help="Secret ID to inject.")
@click.option("--env-var", required=True, help="Environment variable name to set.")
@click.pass_obj
def inject_env(obj: dict[str, VaultKnox], secret_id: str, env_var: str) -> None:
    vault = obj["vault"]
    result = vault.inject_to_env(_prompt_password(), secret_id, env_var)
    click.echo(json.dumps(result, indent=2))


@main.command("revoke-token")
@click.argument("token")
@click.option("--reason", default=None, help="Optional reason for revocation.")
@click.pass_obj
def revoke_token_cmd(obj: dict[str, VaultKnox], token: str, reason: str | None) -> None:
    vault = obj["vault"]
    result = vault.revoke_token(_prompt_password(), token, reason)
    click.echo(json.dumps(result, indent=2))


@main.command("vacuum")
@click.pass_obj
def vacuum(obj: dict[str, VaultKnox]) -> None:
    """Reclaim unused space and checkpoint the WAL file."""
    import os
    vault = obj["vault"]
    db_path = vault.paths.db_path
    before = os.path.getsize(db_path) if db_path.exists() else 0
    vault.db.vacuum()
    after = os.path.getsize(db_path) if db_path.exists() else 0
    click.echo(json.dumps({"before_bytes": before, "after_bytes": after, "saved_bytes": before - after}, indent=2))


@main.command("cleanup-tokens")
@click.pass_obj
def cleanup_tokens(obj: dict[str, VaultKnox]) -> None:
    """Remove expired one-time tokens from the database."""
    vault = obj["vault"]
    result = vault.cleanup_expired_tokens()
    click.echo(json.dumps(result, indent=2))


@main.command("bulk-import")
@click.option("--file", "file_path", required=True, type=click.Path(exists=True, path_type=Path), help="YAML or JSON file containing secrets to import.")
@click.option("--format", "file_format", type=click.Choice(["yaml", "json"], case_sensitive=False), default=None, help="File format. Defaults to auto-detect from extension.")
@click.pass_obj
def bulk_import(obj: dict[str, VaultKnox], file_path: Path, file_format: str | None) -> None:
    """Import multiple secrets from a YAML or JSON file.

    File format: {"secrets": [{"id": "...", "type": "...", "label": "...", "data": {...}}]}
    """
    vault = obj["vault"]
    fmt = file_format or ("yaml" if file_path.suffix.lower() in {".yml", ".yaml"} else "json")
    try:
        if fmt == "yaml":
            import yaml  # type: ignore[import-untyped]
            raw = yaml.safe_load(file_path.read_text(encoding="utf-8"))
        else:
            raw = json.loads(file_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise click.ClickException(f"Failed to parse import file: {exc}") from exc
    if not isinstance(raw, dict) or "secrets" not in raw:
        raise click.ClickException("Import file must contain a top-level 'secrets' list")
    entries = raw["secrets"]
    if not isinstance(entries, list):
        raise click.ClickException("'secrets' must be a list")
    result = vault.bulk_import_secrets(_prompt_password(), entries)
    click.echo(json.dumps(result, indent=2))


# ---------------------------------------------------------------------------
# Secrets (autonomous, key-file-backed) subcommand group
# ---------------------------------------------------------------------------


@main.group(cls=_VaultGroup)
def secrets() -> None:
    """
    Manage the autonomous (key-file-backed) encrypted secrets store.

    Unlike the master-password vault, this store uses a key file on disk
    for decryption — no manual unlock needed. Designed for cron jobs,
    scripts, and automated workflows.

    \b
    Security note: same model as SSH private keys (chmod 600 on key file).
    The encrypted .enc file is safe for backups, git, and session transcripts.
    """


@secrets.command("init")
@click.option("--force", is_flag=True, default=False, help="Re-initialize (destroys existing secrets)")
@click.pass_obj
def secrets_init(obj: dict, force: bool) -> None:
    store = AutonomousSecretsStore()
    click.echo(store.initialize(force=force))


@secrets.command("add")
@click.argument("pairs", nargs=-1, required=True)
@click.pass_obj
def secrets_add(obj: dict, pairs: tuple[str, ...]) -> None:
    store = AutonomousSecretsStore()
    for pair in pairs:
        if "=" not in pair:
            click.echo(f"Skipping '{pair}' — use KEY=VALUE format", err=True)
            continue
        key, value = pair.split("=", 1)
        store.set(key.strip(), value.strip())
        click.echo(f"  ✅ {key.strip()}")
    click.echo(f"  Secrets saved ({len(store.list_keys())} total)")


@secrets.command("get")
@click.argument("key")
@click.pass_obj
def secrets_get(obj: dict, key: str) -> None:
    store = AutonomousSecretsStore()
    click.echo(store.get(key))


@secrets.command("list")
@click.pass_obj
def secrets_list(obj: dict) -> None:
    store = AutonomousSecretsStore()
    keys = store.list_keys()
    if not keys:
        click.echo("  ℹ️  No secrets stored.")
        return
    click.echo(f"  📋 {len(keys)} secrets:")
    for k in keys:
        click.echo(f"     🔑 {k}")


@secrets.command("remove")
@click.argument("key")
@click.pass_obj
def secrets_remove(obj: dict, key: str) -> None:
    store = AutonomousSecretsStore()
    store.delete(key)
    click.echo(f"  ✅ Removed '{key}'")


@secrets.command("env")
@click.option("--shell", is_flag=True, default=False, help="Output as shell-safe exports")
@click.pass_obj
def secrets_env(obj: dict, shell: bool) -> None:
    store = AutonomousSecretsStore()
    if shell:
        click.echo(store.dump_env())
    else:
        click.echo(store.dump_json())


@secrets.command("populate")
@click.option("--from", "env_file", required=True, help="Path to .env file to import")
@click.option("--overwrite", is_flag=True, default=False, help="Overwrite existing keys")
@click.pass_obj
def secrets_populate(obj: dict, env_file: str, overwrite: bool) -> None:
    store = AutonomousSecretsStore()
    results = store.populate_from(env_file, overwrite=overwrite)
    for key, status in results.items():
        click.echo(f"  {'✅' if status == 'stored' else '⏭️'}  {key}: {status}")
    stored = sum(1 for s in results.values() if s == "stored")
    click.echo(f"  Imported {stored} new secret(s) — {len(results)} total processed")


@secrets.command("auto-seal")
@click.option("--dry-run", is_flag=True, default=False, help="Report what would be encrypted without doing it")
@click.option("--strip", is_flag=True, default=False, help="Replace plaintext .env values with comments after sealing")
@click.pass_obj
def secrets_auto_seal(obj: dict, dry_run: bool, strip: bool) -> None:
    """
    Auto-detect and encrypt any new credentials from .env.

    Scans ~/.hermes/.env for credential keys (ending in _KEY, _TOKEN,
    _SECRET, _PASSWORD) that aren't yet in the encrypted store, and
    automatically encrypts them. Run this periodically or after adding
    new API keys — it's the "set-and-forget" safety net.
    """
    store = AutonomousSecretsStore()
    results = store.auto_seal(dry_run=dry_run, strip_plaintext=strip)

    label = "🔄 Would seal" if dry_run else "✅ Sealed"

    if results["encrypted"]:
        for item in results["encrypted"]:
            action = item.get("action", "encrypted")
            click.echo(f"  {'🔮' if dry_run else '🔐'} {item['key']}: {action}")
    else:
        click.echo("  ✅ No new credentials detected — everything is already encrypted.")

    if results["skipped"]:
        click.echo(f"  ℹ️  Skipped {len(results['skipped'])} already-encrypted keys")

    if results["errors"]:
        for err in results["errors"]:
            click.echo(f"  ❌ {err.get('key', '')}: {err.get('error', 'unknown error')}", err=True)

    total = len(results["encrypted"])
    click.echo(f"\n  {'🔮 Would encrypt' if dry_run else '🔐 Auto-sealed'} {total} new credential(s)")


# ---------------------------------------------------------------------------
# Operational Commands: rotate, verify, scan, health, audit
# ---------------------------------------------------------------------------


@main.command("rotate-master-key")
@click.pass_obj
def rotate_master_key_cmd(obj: dict[str, VaultKnox]) -> None:
    """
    Rotate the vault master key atomically.

    Prompts for the current password and a new password (with confirmation).
    Creates an encrypted pre-rotation backup before rotating.

    The backup is encrypted with the OLD password only — the new password
    cannot decrypt it. This provides defence-in-depth if the new password
    is later compromised.
    """
    vault = obj["vault"]
    old_password = click.prompt("Current master password", hide_input=True)
    new_password = click.prompt("New master password", hide_input=True, confirmation_prompt=True)

    from vaultknox.rotation import rotate_master_key

    result = rotate_master_key(vault.db, vault.paths.runtime_dir, old_password, new_password)
    click.echo(json.dumps(result, indent=2))


@main.command("verify")
@click.option(
    "--service",
    type=click.Choice(["openai", "anthropic", "github", "google_oauth", "generic_bearer"]),
    default=None,
    help="Verify a specific service by name. Defaults to all api_key secrets.",
)
@click.option("--all", "verify_all", is_flag=True, default=False, help="Verify all api_key secrets.")
@click.pass_obj
def verify(obj: dict[str, VaultKnox], service: str | None, verify_all: bool) -> None:
    """
    Verify API key credentials stored in the vault against live provider endpoints.

    By default verifies all 'api_key' type secrets. Use --service to verify a specific one.

    Results are printed as a table with service, secret_id, and verification status.
    """
    from vaultknox.verifier import CredentialVerifier

    verifier = CredentialVerifier()
    vault = obj["vault"]

    # Determine which secrets to verify
    if service:
        secrets_list = [s for s in vault.list_secrets() if s.get("service", "").lower() == service.lower()]
        if not secrets_list:
            click.echo(f"No secrets found for service '{service}'.")
            return
    elif verify_all:
        secrets_list = [s for s in vault.list_secrets() if s.get("type") == "api_key"]
        if not secrets_list:
            click.echo("No 'api_key' type secrets found to verify.")
            return
    else:
        secrets_list = [s for s in vault.list_secrets() if s.get("type") == "api_key"]
        if not secrets_list:
            click.echo("No 'api_key' type secrets found to verify.")
            return

    click.echo(f"Verifying {len(secrets_list)} credential(s)...\n")
    password = _prompt_password()
    for secret in secrets_list:
        secret_id = secret.get("id", "?")
        service_name = secret.get("service", "unknown")
        # Get the full secret to verify
        try:
            full = vault.get_secret(password, secret_id)
            payload = full.get("payload", {})
            result = verifier.verify(payload)
        except Exception as exc:  # noqa: BLE001
            click.echo(f"  ❌ {service_name}/{secret_id}: error — {exc}")
            continue

        status_icon = {
            "valid": "✅",
            "invalid": "❌",
            "billing_issue": "💳",
            "network_error": "🌐",
            "unknown": "❓",
        }.get(result.status, "?")

        click.echo(f"  {status_icon} {service_name}/{secret_id}: {result.status} — {result.message}")


@main.command("scan")
@click.option(
    "--paths",
    default=None,
    help="Comma-separated paths to scan. Defaults to ~/.hermes and shell RC files.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["cli", "json"], case_sensitive=False),
    default="cli",
    help="Output format.",
)
@click.pass_obj
def scan(obj: dict[str, VaultKnox], paths: str | None, output_format: str) -> None:
    """
    Scan files for plaintext secrets and security issues.

    Detects 21+ secret patterns (OpenAI, GitHub, AWS, Stripe, SSH keys, etc.)
    and flags files with unsafe permissions (world-readable .env files).

    Default paths: ~/.hermes, ~/.bashrc, ~/.zshrc, ~/.profile
    """
    from pathlib import Path

    from vaultknox.scanner import SecretScanner, format_findings_cli, format_findings_json

    scan_paths = [Path(p.strip()) for p in paths.split(",")] if paths else None
    scanner = SecretScanner(paths=scan_paths) if scan_paths else SecretScanner()
    findings, permission_issues, stats = scanner.scan()

    if output_format == "json":
        click.echo(format_findings_json(findings, permission_issues, stats))
    else:
        click.echo(format_findings_cli(findings, permission_issues, stats))


@main.command("health")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["cli", "json"], case_sensitive=False),
    default="cli",
    help="Output format.",
)
@click.pass_obj
def health(obj: dict[str, VaultKnox], output_format: str) -> None:
    """
    Run a full vault health check and report results.

    Checks: DB permissions, audit log permissions, SQLite integrity,
    config completeness, encryption integrity, audit log readability,
    and autonomous secrets store health.

    Exit code: 0 if healthy, 1 if degraded, 2 if critical.
    """
    from vaultknox.health import CheckSeverity, VaultHealthChecker

    vault = obj["vault"]
    checker = VaultHealthChecker(vault.paths, master_password=None)
    report = checker.run_all_checks()

    if output_format == "json":
        click.echo(json.dumps(report.to_dict(), indent=2))
        return

    # Human-readable output
    status_colors = {
        "healthy": "✅",
        "degraded": "⚠️ ",
        "critical": "🔴",
    }
    icon = status_colors.get(report.overall_status, "?")
    click.echo(f"\n{icon} Vault Health: {report.overall_status.upper()}\n")

    for check in report.checks:
        sev_icon = {
            CheckSeverity.CRITICAL: "🔴",
            CheckSeverity.WARNING: "⚠️ ",
            CheckSeverity.INFO: "ℹ️ ",
        }.get(check.severity, "?")
        status_icon = "✅" if check.status.value == "pass" else "❌"
        click.echo(f"  {sev_icon} {status_icon} {check.name}: {check.message}")

    click.echo(f"\nOverall: {report.overall_status.upper()}")

    # Set exit code
    raise SystemExit(0 if report.overall_status == "healthy" else 1 if report.overall_status == "degraded" else 2)


# ---------------------------------------------------------------------------
# Audit log subcommand group
# ---------------------------------------------------------------------------


@main.group('audit')
def audit() -> None:
    """Audit log queries and management."""


@audit.command("query")
@click.option("--action", default=None, help="Filter by action name (e.g. unlock, add_secret).")
@click.option("--status", default=None, help="Filter by status (e.g. success, failure).")
@click.option("--secret-id", default=None, help="Filter by secret ID.")
@click.option(
    "--since",
    default=None,
    help="Only events after this datetime (ISO 8601, e.g. 2026-01-01T00:00:00+00:00 or -7d for 7 days ago).",
)
@click.option(
    "--until",
    default=None,
    help="Only events before this datetime (ISO 8601).",
)
@click.option("--limit", default=None, type=int, help="Maximum number of events to return (most recent first).")
@click.option("--json", "output_json", is_flag=True, default=False, help="Output as JSON.")
@click.pass_obj
def audit_query(
    obj: dict[str, VaultKnox],
    action: str | None,
    status: str | None,
    secret_id: str | None,
    since: str | None,
    until: str | None,
    limit: int | None,
    output_json: bool,
) -> None:
    """
    Query the vault audit log with optional filters.

    Supports filtering by action, status, secret_id, date range, and limit.
    Results are returned newest-first by default.

    Examples:
        vaultknox audit query --action unlock --limit 20
        vaultknox audit query --since -7d --status failure
        vaultknox audit query --json
    """
    from datetime import timedelta

    from vaultknox.audit import query_audit_log

    vault = obj["vault"]

    # Parse relative dates like -7d
    def parse_relative(ts: str | None) -> Any:
        if ts is None:
            return None
        if ts.startswith("-"):
            # e.g. -7d → 7 days ago
            import re
            m = re.match(r"^-(\d+)([dhm])$", ts)
            if m:
                value, unit = int(m.group(1)), m.group(2)
                delta = {"d": timedelta(days=value), "h": timedelta(hours=value), "m": timedelta(minutes=value)}[unit]
                from datetime import datetime, timezone
                return datetime.now(timezone.utc) - delta
        # Treat as ISO 8601
        from datetime import datetime, timezone
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))

    since_dt = parse_relative(since)
    until_dt = parse_relative(until)

    events = query_audit_log(
        vault.paths.audit_log_path,
        action=action,
        status=status,
        secret_id=secret_id,
        since=since_dt,
        until=until_dt,
        limit=limit,
    )

    if output_json:
        click.echo(json.dumps(events, indent=2))
    else:
        if not events:
            click.echo("No matching audit events found.")
            return
        for event in events:
            ts = event.get("timestamp", "?")
            act = event.get("action", "?")
            stat = event.get("status", "?")
            sid = event.get("secret_id", "")
            detail = f" [{sid}]" if sid else ""
            click.echo(f"  {ts}  {act}  {stat}{detail}")


# ---------------------------------------------------------------------------
# Expiry management subcommand group
# ---------------------------------------------------------------------------


@main.group('expiry')
def expiry() -> None:
    """Manage secret expiry dates and notifications."""


@expiry.command("set-expiry")
@click.argument("secret_id")
@click.option("--days", type=int, required=True, help="Number of days until expiry.")
@click.pass_obj
def set_expiry(obj: dict[str, VaultKnox], secret_id: str, days: int) -> None:
    """
    Set or update the expiry date for a secret.

    Example: vaultknox expiry set-expiry api_key_1 --days 30
    """
    from datetime import datetime, timezone, timedelta

    vault = obj["vault"]
    password = _prompt_password()
    # Get existing secret to preserve type/label/payload
    existing = vault.get_secret(password, secret_id)
    expires_at = (datetime.now(timezone.utc) + timedelta(days=days)).replace(microsecond=0)
    vault.update_secret(
        password, secret_id,
        existing.get("type", ""), existing.get("label", ""),
        existing.get("payload", {}),
        expires_at=expires_at.isoformat(),
    )
    click.echo(f"Expiry set for '{secret_id}': {expires_at.isoformat()}")


@expiry.command("clear-expiry")
@click.argument("secret_id")
@click.pass_obj
def clear_expiry(obj: dict[str, VaultKnox], secret_id: str) -> None:
    """Remove the expiry date from a secret."""
    vault = obj["vault"]
    password = _prompt_password()
    existing = vault.get_secret(password, secret_id)
    vault.update_secret(
        password, secret_id,
        existing.get("type", ""), existing.get("label", ""),
        existing.get("payload", {}),
        expires_at=None,
    )
    click.echo(f"Expiry cleared for '{secret_id}'.")


@expiry.command("notify")
@click.pass_obj
def expiry_notify(obj: dict[str, VaultKnox]) -> None:
    """
    List secrets that are expired or expiring soon.

    Checks secrets with expires_at set and reports those already expired
    or expiring within the next 7 days.
    """
    from datetime import datetime, timezone, timedelta

    vault = obj["vault"]
    secrets = vault.list_secrets()
    now = datetime.now(timezone.utc)
    soon = now + timedelta(days=7)

    expired = []
    expiring_soon = []

    for s in secrets:
        raw = s.get("expires_at")
        if not raw:
            continue
        try:
            exp = datetime.fromisoformat(raw).astimezone(timezone.utc)
        except ValueError:
            continue
        if exp <= now:
            expired.append((s["id"], exp.isoformat()))
        elif exp <= soon:
            expiring_soon.append((s["id"], exp.isoformat()))

    if not expired and not expiring_soon:
        click.echo("No secrets are expired or expiring within 7 days. ✅")
        return

    if expired:
        click.echo(f"🔴 EXPIRED ({len(expired)}):")
        for sid, exp in expired:
            click.echo(f"  {sid}: expired at {exp}")

    if expiring_soon:
        click.echo(f"\n⚠️  EXPIRING SOON ({len(expiring_soon)}):")
        for sid, exp in expiring_soon:
            click.echo(f"  {sid}: expires at {exp}")


# ---------------------------------------------------------------------------
# Standalone entry point for ``hermes-secrets`` CLI
# ---------------------------------------------------------------------------


def secrets_main() -> None:
    """Invoke the secrets subcommand group as a standalone CLI.

    Usage::

        python3 -m vaultknox.cli secrets --help

    Or via the installed ``hermes-secrets`` entry point::

        hermes-secrets init
        hermes-secrets add KEY=VALUE
        hermes-secrets env --shell
    """
    # Build a standalone Click group matching just the ``secrets`` subcommands.
    # We reuse the _VaultGroup error handler from the main CLI.
    group = _VaultGroup(
        name="hermes-secrets",
        help="Encrypted credential store for autonomous (key-file-backed) secrets.",
        invoke_without_command=False,
    )

    # Register each secrets subcommand
    for cmd in secrets.commands.values():
        group.add_command(cmd)

    # Run without the parent group context
    group()


if __name__ == "__main__":
    try:
        main()
    except VaultError as exc:
        raise click.ClickException(str(exc)) from exc