from __future__ import annotations

from typing import Any

from vaultknox.audit import write_audit_event
from vaultknox.config import expand_runtime_path
from vaultknox.vault import VaultError, VaultKnox

READ_ACTIONS = {"status", "list", "get_masked", "get_token", "unlock", "lock", "inject_env", "consume_token"}
WRITE_ACTIONS = {"add", "update", "delete", "revoke_token"}


def _required_password(action: str, master_password: str | None) -> str:
    if not master_password:
        raise VaultError(f"Action '{action}' requires master_password")
    return master_password


def vault_tool(
    action: str,
    allow_write: bool = False,
    runtime_dir: str | None = None,
    master_password: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    paths = expand_runtime_path(runtime_dir)
    vault = VaultKnox(paths)
    if action in WRITE_ACTIONS and not allow_write:
        raise VaultError("Write actions are disabled for Hermes unless allow_write is enabled")

    try:
        if action == "status":
            status = vault.status()
            result = {
                "initialized": status.initialized,
                "unlocked": status.unlocked,
                "secret_count": status.secret_count,
                "auto_lock_minutes": status.auto_lock_minutes,
            }
        elif action == "unlock":
            result = vault.unlock(_required_password(action, master_password))
        elif action == "lock":
            vault.lock()
            result = {"status": "locked"}
        elif action == "list":
            result = {"secrets": vault.list_secrets()}
        elif action == "get_masked":
            result = vault.get_masked(
                kwargs["secret_id"],
                purpose=kwargs.get("purpose"),
                token_ttl_seconds=kwargs.get("token_ttl_seconds", 300),
            )
        elif action == "get_token":
            result = {
                "token": vault.issue_token(
                    kwargs["secret_id"],
                    purpose=kwargs["purpose"],
                    token_ttl_seconds=kwargs.get("token_ttl_seconds", 300),
                )
            }
        elif action == "add":
            result = vault.add_secret(
                _required_password(action, master_password),
                kwargs["secret_id"],
                kwargs["secret_type"],
                kwargs["label"],
                kwargs["payload"],
            )
        elif action == "update":
            result = vault.update_secret(
                _required_password(action, master_password),
                kwargs["secret_id"],
                kwargs["secret_type"],
                kwargs["label"],
                kwargs["payload"],
            )
        elif action == "delete":
            vault.delete_secret(_required_password(action, master_password), kwargs["secret_id"])
            result = {"deleted": kwargs["secret_id"]}
        elif action == "inject_env":
            result = vault.inject_to_env(_required_password(action, master_password), kwargs["secret_id"], kwargs["env_var"])
        elif action == "consume_token":
            result = vault.consume_token(_required_password(action, master_password), kwargs["token"])
        elif action == "revoke_token":
            result = vault.revoke_token(_required_password(action, master_password), kwargs["token"], kwargs.get("reason"))
        else:
            allowed = ", ".join(sorted(READ_ACTIONS | WRITE_ACTIONS))
            raise VaultError(f"Unsupported action '{action}'. Allowed actions: {allowed}")
    except Exception:
        write_audit_event(paths.audit_log_path, f"tool_{action}", "failure")
        raise

    write_audit_event(paths.audit_log_path, f"tool_{action}", "success")
    return result