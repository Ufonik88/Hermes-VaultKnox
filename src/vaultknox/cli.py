from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import click

from vaultknox.autonomous_secrets import AutonomousSecretsStore
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


def _vault(runtime_dir: str | None, profile: str | None = None) -> VaultKnox:
    return VaultKnox(expand_runtime_path(runtime_dir, profile))


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
@click.option("--profile", type=str, default=None, help="Vault profile name (uses ~/.hermes/vaultknox-profiles/<name>).")
@click.option("--logo", "show_logo", is_flag=True, default=False, help="Display the VaultKnox ASCII logo before command output.")
@click.pass_context
def main(ctx: click.Context, runtime_dir: Path | None, profile: str | None, show_logo: bool) -> None:
    ctx.ensure_object(dict)
    ctx.obj["vault"] = _vault(str(runtime_dir) if runtime_dir else None, profile)
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
    }))


@main.command()
def mcp() -> None:
    """Start the MCP stdio server for VaultKnox."""
    from vaultknox.mcp_server import run_mcp_server

    run_mcp_server()


@main.command("generate-skill")
@click.option("--output", "output_path", type=click.Path(path_type=Path), default=None, help="Output path for SKILL.md")
@click.option("--agent", "agent_id", default=None, help="Agent ID to scope skill for")
def generate_skill(output_path: Path | None, agent_id: str | None) -> None:
    """Generate SKILL.md contract for credential access."""
    from vaultknox.skills import generate_skill

    try:
        result = generate_skill(output_path, agent_id)
        click.echo("Generated: " + result["path"])
        click.echo("Hash: " + result["content_hash"])
        click.echo("Secrets: " + str(result["secret_count"]))
    except Exception as e:
        raise click.ClickException(str(e)) from e


@main.command()
@click.option("--host", default="127.0.0.1", help="Host to bind to")
@click.option("--port", default=0, type=int, help="Port (0 = auto)")
@click.option("--no-open", is_flag=True, help="Don't open browser automatically")
def dashboard(host: str, port: int, no_open: bool) -> None:
    """Start the VaultKnox Dashboard (local, token-guarded)."""
    from vaultknox.dashboard import serve_dashboard

    serve_dashboard(host=host, port=port, open_browser=not no_open)


@main.command("oauth")
@click.option("--provider", required=True, type=click.Choice(["google", "github", "openai"]), help="OAuth provider")
@click.option("--client-id", required=True, help="OAuth client ID")
@click.option("--client-secret", required=True, help="OAuth client secret")
@click.option("--alias", default="default", help="Credential alias")
@click.option("--port", default=0, type=int, help="Callback port (0 = auto)")
@click.option("--timeout", default=300, type=int, help="Callback timeout in seconds")
@click.option("--no-open", is_flag=True, help="Don't open browser")
@click.pass_obj
def oauth_login(obj: dict[str, VaultKnox], provider: str, client_id: str, client_secret: str, alias: str, port: int, timeout: int, no_open: bool) -> None:
    """OAuth PKCE login flow - authenticates via browser and stores tokens."""
    from vaultknox.oauth import oauth_login as do_oauth_login

    vault = obj["vault"]

    try:
        result = do_oauth_login(
            provider_id=provider,
            client_id=client_id,
            client_secret=client_secret,
            alias=alias,
            port=port or None,
            timeout=float(timeout),
            open_browser=not no_open,
        )

        # Store in vault
        stored = vault.add_secret(
            password=_prompt_password(),
            secret_id=result.secret_id,
            secret_type="oauth",
            label=result.label,
            payload=result.to_payload(),
        )
        click.echo(json.dumps(stored, indent=2))
        click.echo(f"\nOAuth credential '{result.secret_id}' stored successfully.")
        if result.refresh_token:
            click.echo("Refresh token stored - tokens will auto-refresh when expired.")

    except Exception as e:
        raise click.ClickException(str(e)) from e


@main.command()
@click.option("--auto-lock-minutes", default=15, show_default=True, type=int)
@click.option("--no-password-check", is_flag=True, default=False, help="Skip password strength validation.")
@click.option("--kdf-time-cost", default=3, show_default=True, type=int, help="Argon2 time cost (iterations).")
@click.option("--kdf-memory-cost", default=65536, show_default=True, type=int, help="Argon2 memory cost (KB).")
@click.option("--kdf-parallelism", default=4, show_default=True, type=int, help="Argon2 parallelism (lanes).")
@click.option("--kdf-hash-len", default=32, show_default=True, type=int, help="Argon2 hash length (bytes).")
@click.option("--kdf-type", default="argon2id", show_default=True, type=click.Choice(["argon2id", "argon2i", "argon2d"]), help="Argon2 variant.")
@click.pass_obj
def init(obj: dict[str, VaultKnox], auto_lock_minutes: int, no_password_check: bool, kdf_time_cost: int, kdf_memory_cost: int, kdf_parallelism: int, kdf_hash_len: int, kdf_type: str) -> None:
    """Initialize a new vault with a master password."""
    vault = obj["vault"]
    password = _prompt_password(confirm=True)
    kdf_params = {
        "time_cost": kdf_time_cost,
        "memory_cost": kdf_memory_cost,
        "parallelism": kdf_parallelism,
        "hash_len": kdf_hash_len,
        "type": kdf_type,
    }
    vault.initialize(password, auto_lock_minutes=auto_lock_minutes, skip_password_check=no_password_check, kdf_params=kdf_params)
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
        def parse_normalized(ts: str) -> datetime:
            dt = datetime.fromisoformat(ts)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        secrets = [s for s in secrets if s.get("expires_at") and parse_normalized(s["expires_at"]) <= now]
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
@click.option("--no-password-check", is_flag=True, default=False, help="Skip password strength validation.")
@click.pass_obj
def change_password(obj: dict[str, VaultKnox], no_password_check: bool) -> None:
    vault = obj["vault"]
    current = click.prompt("Current master password", hide_input=True)
    new_password = click.prompt("New master password", hide_input=True, confirmation_prompt=True)
    vault.change_password(current, new_password, skip_password_check=no_password_check)
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

    # label = "🔄 Would seal" if dry_run else "✅ Sealed"
    # (removed unused variable)

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
    from datetime import datetime, timedelta, timezone

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
    from datetime import datetime, timedelta, timezone

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
            dt = datetime.fromisoformat(raw)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            exp = dt.astimezone(timezone.utc)
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
# Sanitize History: detect and redact leaked secrets from persistent stores
# ---------------------------------------------------------------------------


@main.command("sanitize-history")
@click.option("--apply", is_flag=True, default=False, help="Apply changes (default is dry-run)")
@click.option("--paths", default=None, help="Comma-separated paths to scan. Default: sessions/, state.db, .hermes_history")
@click.pass_obj
def sanitize_history(obj: dict, apply: bool, paths: str | None) -> None:
    """
    Scan persistent stores for leaked secrets and redact them.

    Checks session JSONL files, state.db messages table, and CLI history
    for secret patterns using VaultKnox detectors. Default is dry-run.

    Examples:
        vaultknox sanitize-history           # Preview what would be redacted
        vaultknox sanitize-history --apply   # Actually redact
    """
    import sqlite3
    from pathlib import Path

    from vaultknox.detectors import DETECTORS

    _REDACT = "[REDACTED-SENSITIVE-VALUE]"
    hermes_home = Path.home() / ".hermes"

    default_paths = [
        hermes_home / "sessions",
        hermes_home / "state.db",
        hermes_home / ".hermes_history",
    ]
    scan_targets = [Path(p.strip()) for p in paths.split(",")] if paths else default_paths

    total_findings = 0
    total_files_scanned = 0
    total_files_modified = 0
    files_modified = []


    hermes_message_text_fields = [
        (
            "content",
            "SELECT rowid, content FROM messages WHERE content IS NOT NULL",
            "UPDATE messages SET content = ? WHERE rowid = ?",
        ),
        (
            "tool_calls",
            "SELECT rowid, tool_calls FROM messages WHERE tool_calls IS NOT NULL",
            "UPDATE messages SET tool_calls = ? WHERE rowid = ?",
        ),
        (
            "reasoning",
            "SELECT rowid, reasoning FROM messages WHERE reasoning IS NOT NULL",
            "UPDATE messages SET reasoning = ? WHERE rowid = ?",
        ),
        (
            "reasoning_details",
            "SELECT rowid, reasoning_details FROM messages WHERE reasoning_details IS NOT NULL",
            "UPDATE messages SET reasoning_details = ? WHERE rowid = ?",
        ),
        (
            "reasoning_content",
            "SELECT rowid, reasoning_content FROM messages WHERE reasoning_content IS NOT NULL",
            "UPDATE messages SET reasoning_content = ? WHERE rowid = ?",
        ),
        (
            "codex_message_items",
            "SELECT rowid, codex_message_items FROM messages WHERE codex_message_items IS NOT NULL",
            "UPDATE messages SET codex_message_items = ? WHERE rowid = ?",
        ),
    ]

    def _redact_text(text: str) -> tuple[str, int]:
        """Redact all detector matches in text. Returns (redacted_text, count)."""
        matches = []
        for detector in DETECTORS:
            for m in detector.pattern.finditer(text):
                matches.append((m.start(), m.end()))
        if not matches:
            return text, 0
        # Merge overlapping spans
        matches.sort(key=lambda s: s[0])
        merged = []
        for start, end in matches:
            if merged and start <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))
        # Replace reverse order
        redacted = text
        for start, end in reversed(merged):
            redacted = redacted[:start] + _REDACT + redacted[end:]
        return redacted, len(merged)

    for target in scan_targets:
        if not target.exists():
            click.echo(f"  ⏭️  Skipping non-existent path: {target}")
            continue

        if target.is_dir():
            # Scan all .jsonl files in the directory
            for jsonl_file in sorted(target.glob("*.jsonl")):
                total_files_scanned += 1
                lines = jsonl_file.read_text(encoding="utf-8").splitlines()
                modified_lines = []
                file_findings = 0
                changed = False
                for line in lines:
                    redacted, count = _redact_text(line)
                    file_findings += count
                    if count:
                        changed = True
                    modified_lines.append(redacted)
                if changed:
                    total_findings += file_findings
                    total_files_modified += 1
                    files_modified.append(str(jsonl_file))
                    if apply:
                        jsonl_file.write_text("\n".join(modified_lines) + "\n", encoding="utf-8")
                        click.echo(f"  🔴 Redacted {file_findings} secret(s) in {jsonl_file.name}")
                    else:
                        click.echo(f"  🔍 Would redact {file_findings} secret(s) in {jsonl_file.name}")

        elif target.name == "state.db":
            total_files_scanned += 1
            try:
                conn = sqlite3.connect(str(target))
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'messages'")
                if cursor.fetchone() is None:
                    click.echo("  ⚠️  state.db skipped: messages table not found")
                    conn.close()
                    continue

                cursor.execute("PRAGMA table_info(messages)")
                existing_columns = {row[1] for row in cursor.fetchall()}
                db_findings = 0
                for col, select_sql, update_sql in hermes_message_text_fields:
                    if col not in existing_columns:
                        continue
                    cursor.execute(select_sql)
                    for rowid, value in cursor.fetchall():
                        if not isinstance(value, str) or not value:
                            continue
                        redacted, count = _redact_text(value)
                        if count:
                            db_findings += count
                            if apply:
                                cursor.execute(update_sql, (redacted, rowid))
                conn.commit()
                conn.close()
                if db_findings:
                    total_findings += db_findings
                    total_files_modified += 1
                    files_modified.append(str(target))
                    if apply:
                        click.echo(f"  🔴 Redacted {db_findings} secret(s) in state.db")
                    else:
                        click.echo(f"  🔍 Would redact {db_findings} secret(s) in state.db")
            except Exception as exc:  # noqa: BLE001
                click.echo(f"  ⚠️  state.db scan failed: {exc}")

        elif target.name == ".hermes_history":
            total_files_scanned += 1
            content = target.read_text(encoding="utf-8")
            redacted, count = _redact_text(content)
            if count:
                total_findings += count
                total_files_modified += 1
                files_modified.append(str(target))
                if apply:
                    target.write_text(redacted, encoding="utf-8")
                    click.echo(f"  🔴 Redacted {count} secret(s) in .hermes_history")
                else:
                    click.echo(f"  🔍 Would redact {count} secret(s) in .hermes_history")

    # Summary
    mode = "APPLIED" if apply else "DRY-RUN"
    click.echo(f"\n{'=' * 50}")
    click.echo(f"  Mode: {mode}")
    click.echo(f"  Files scanned: {total_files_scanned}")
    click.echo(f"  Files with secrets: {total_files_modified}")
    click.echo(f"  Total secret occurrences: {total_findings}")
    if files_modified:
        click.echo(f"  Files {'modified' if apply else 'flagged'}:")
        for f in files_modified:
            click.echo(f"    - {f}")
    click.echo(f"{'=' * 50}")

    if not apply and total_findings > 0:
        click.echo(f"\n  Run with --apply to actually redact {total_findings} occurrence(s).")


@main.command("install-hooks")
def install_hooks() -> None:
    """Install the secret-guard hook and plugin into ~/.hermes/.

    Deploys two components:

    1. **Legacy hook** (~/.hermes/hooks/secret-guard/) — thin wrapper
       importing ``vaultknox.hooks.secret_guard``. Handles the
       ``message:received`` event for inbound redaction.

    2. **Gateway plugin** (~/.hermes/plugins/vaultknox-secret-guard/) —
       registers ``pre_gateway_dispatch``, ``post_llm_call``, and
       ``pre_llm_call`` hooks. Provides inbound redaction, outbound
       secret-request scanning, and system prompt injection.
    """
    from pathlib import Path

    # --- Legacy hook ---
    hook_dir = Path.home() / ".hermes" / "hooks" / "secret-guard"
    hook_dir.mkdir(parents=True, exist_ok=True)

    handler_path = hook_dir / "handler.py"
    handler_source = '''\
"""Thin wrapper for the VaultKnox secret-guard hook.

This file is auto-generated by ``vaultknox install-hooks``.
Do not edit — update the package and re-run install-hooks instead.
"""

from vaultknox.hooks.secret_guard import handle
'''
    handler_path.write_text(handler_source, encoding="utf-8")

    yaml_path = hook_dir / "HOOK.yaml"
    yaml_content = '''\
name: secret-guard
description: |
  Detect secrets (API keys, tokens, passwords) in incoming chat messages
  and redact them before the message reaches session storage. Uses the
  existing VaultKnox detector registry — zero new regex to maintain.
events:
  - message:received
'''
    yaml_path.write_text(yaml_content, encoding="utf-8")

    click.echo(f"  ✅ Installed secret-guard hook to {hook_dir}")
    click.echo(f"     • {handler_path.name}")
    click.echo(f"     • {yaml_path.name}")

    # --- Gateway plugin (v0.4.2 — outbound + system prompt injection) ---
    plugin_dir = Path.home() / ".hermes" / "plugins" / "vaultknox-secret-guard"
    plugin_dir.mkdir(parents=True, exist_ok=True)

    plugin_init_path = plugin_dir / "__init__.py"
    plugin_init_content = '''\
"""VaultKnox gateway plugin for Nous Research Hermes Agent.

This file is auto-generated by ``vaultknox install-hooks``.
Do not edit — update the package and re-run install-hooks instead.
"""

from __future__ import annotations
from typing import Any
from vaultknox.hooks.secret_guard import handle as redact_handle, scan_outbound, rewrite_outbound
from vaultknox.agent_guide.prompts import get_system_prompt_snippet

def on_pre_gateway_dispatch(**kwargs: Any) -> dict[str, Any] | None:
    text = kwargs.get("user_message") or kwargs.get("content") or kwargs.get("message")
    if not text or not isinstance(text, str):
        return None
    context = {"content": text}
    redact_handle("message:received", context)
    if context.get("_secret_guard_redacted"):
        return {"action": "rewrite", "text": context["content"]}
    return None

def on_pre_llm_call(**kwargs: Any) -> dict[str, Any] | None:
    snippet = get_system_prompt_snippet()
    history = kwargs.get("conversation_history") or []
    for msg in history:
        content = msg.get("content", "") if isinstance(msg, dict) else getattr(msg, "content", "")
        if snippet in content:
            return None
    system_msg = kwargs.get("system_message") or ""
    if snippet in system_msg:
        return None
    return {"context": snippet}

def on_post_llm_call(**kwargs: Any) -> dict[str, Any] | None:
    response = kwargs.get("assistant_response") or kwargs.get("response") or ""
    if not response or not isinstance(response, str):
        return None
    matches = scan_outbound(response)
    if matches:
        rewritten = rewrite_outbound(response, matches)
        return {"response": rewritten}
    return None

def register(ctx: Any) -> None:
    """Register the plugin hooks with Hermes."""
    for hook_name, callback in [
        ("pre_gateway_dispatch", on_pre_gateway_dispatch),
        ("pre_llm_call", on_pre_llm_call),
        ("post_llm_call", on_post_llm_call),
    ]:
        if hasattr(ctx, "register_hook"):
            ctx.register_hook(hook_name, callback)
        elif hasattr(ctx, "on"):
            ctx.on(hook_name, callback)
'''
    plugin_init_path.write_text(plugin_init_content, encoding="utf-8")

    plugin_yaml_path = plugin_dir / "plugin.yaml"
    plugin_yaml_content = """\
name: vaultknox-secret-guard
description: |
  Detects API keys, tokens, and passwords in incoming chat messages and redacts
  them. Also scans outbound AI responses for secret-requesting phrases and
  injects VaultKnox behavioural rules into the system prompt.
version: 0.4.2
author: Ufonik / VaultKnox
kind: standalone
provides_hooks:
  - pre_gateway_dispatch
  - post_llm_call
  - pre_llm_call
"""
    plugin_yaml_path.write_text(plugin_yaml_content, encoding="utf-8")

    click.echo("  ✅ Updated vaultknox-secret-guard plugin to v0.4.2")
    click.echo(f"     • {plugin_init_path.name}")
    click.echo(f"     • {plugin_yaml_path.name}")


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