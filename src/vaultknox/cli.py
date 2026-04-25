from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import click

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


if __name__ == "__main__":
    try:
        main()
    except VaultError as exc:
        raise click.ClickException(str(exc)) from exc