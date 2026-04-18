from __future__ import annotations

import json
from pathlib import Path

import click

from vaultknox.config import expand_runtime_path
from vaultknox.vault import VaultError, VaultKnox


def _vault(runtime_dir: str | None) -> VaultKnox:
    return VaultKnox(expand_runtime_path(runtime_dir))


def _prompt_password(confirm: bool = False) -> str:
    return click.prompt("Master password", hide_input=True, confirmation_prompt=confirm)


@click.group()
@click.option("--runtime-dir", type=click.Path(path_type=Path), default=None, help="Override the runtime vault directory.")
@click.pass_context
def main(ctx: click.Context, runtime_dir: Path | None) -> None:
    ctx.ensure_object(dict)
    ctx.obj["vault"] = _vault(str(runtime_dir) if runtime_dir else None)


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
@click.pass_obj
def list_command(obj: dict[str, VaultKnox]) -> None:
    vault = obj["vault"]
    click.echo(json.dumps(vault.list_secrets(), indent=2))


@main.command()
@click.option("--id", "secret_id", required=True)
@click.option("--type", "secret_type", required=True)
@click.option("--label", required=True)
@click.option("--data", required=True, help="Secret payload as JSON.")
@click.pass_obj
def add(obj: dict[str, VaultKnox], secret_id: str, secret_type: str, label: str, data: str) -> None:
    vault = obj["vault"]
    payload = json.loads(data)
    result = vault.add_secret(_prompt_password(), secret_id, secret_type, label, payload)
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
    vault.delete_secret(secret_id)
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


if __name__ == "__main__":
    try:
        main()
    except VaultError as exc:
        raise click.ClickException(str(exc)) from exc