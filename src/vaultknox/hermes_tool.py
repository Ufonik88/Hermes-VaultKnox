from __future__ import annotations

from typing import Any

from vaultknox.config import expand_runtime_path
from vaultknox.vault import VaultError, VaultKnox

READ_ACTIONS = {"status", "list", "get_masked", "get_token", "unlock", "lock"}
WRITE_ACTIONS = {"add", "update", "delete"}


def vault_tool(action: str, allow_write: bool = False, runtime_dir: str | None = None, **kwargs: Any) -> dict[str, Any]:
    vault = VaultKnox(expand_runtime_path(runtime_dir))
    if action in WRITE_ACTIONS and not allow_write:
        raise VaultError("Write actions are disabled for Hermes unless allow_write is enabled")

    if action == "status":
        status = vault.status()
        return {
            "initialized": status.initialized,
            "unlocked": status.unlocked,
            "secret_count": status.secret_count,
            "auto_lock_minutes": status.auto_lock_minutes,
        }
    if action == "unlock":
        return vault.unlock(kwargs["master_password"])
    if action == "lock":
        vault.lock()
        return {"status": "locked"}
    if action == "list":
        return {"secrets": vault.list_secrets()}
    if action == "get_masked":
        return vault.get_masked(
            kwargs["secret_id"],
            purpose=kwargs.get("purpose"),
            token_ttl_seconds=kwargs.get("token_ttl_seconds", 300),
        )
    if action == "get_token":
        return {
            "token": vault.issue_token(
                kwargs["secret_id"],
                purpose=kwargs["purpose"],
                token_ttl_seconds=kwargs.get("token_ttl_seconds", 300),
            )
        }
    if action == "add":
        return vault.add_secret(
            kwargs["master_password"],
            kwargs["secret_id"],
            kwargs["secret_type"],
            kwargs["label"],
            kwargs["payload"],
        )
    if action == "update":
        return vault.update_secret(
            kwargs["master_password"],
            kwargs["secret_id"],
            kwargs["secret_type"],
            kwargs["label"],
            kwargs["payload"],
        )
    if action == "delete":
        vault.delete_secret(kwargs["master_password"], kwargs["secret_id"])
        return {"deleted": kwargs["secret_id"]}

    allowed = ", ".join(sorted(READ_ACTIONS | WRITE_ACTIONS))
    raise VaultError(f"Unsupported action '{action}'. Allowed actions: {allowed}")