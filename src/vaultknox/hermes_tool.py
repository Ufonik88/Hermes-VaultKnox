from __future__ import annotations

from typing import Any

from vaultknox.audit import write_audit_event
from vaultknox.config import expand_runtime_path
from vaultknox.core import derive_metadata_key
from vaultknox.detectors import DETECTORS
from vaultknox.policy import PolicyEngine
from vaultknox.vault import VaultError, VaultKnox

READ_ACTIONS = {"status", "list", "get_masked", "get_token", "unlock", "lock", "inject_env", "consume_token"}
WRITE_ACTIONS = {"add", "update", "delete", "revoke_token"}

# Actions that require master_password (operator-only, not agent)
OPERATOR_ACTIONS = {"unlock"}

# Actions that don't need policy check
NO_POLICY_ACTIONS = {"scan_text", "unlock", "lock", "status"}

# Map vault actions to policy actions
ACTION_TO_POLICY = {
    "status": None,
    "list": "list_credentials",
    "get_masked": "get_metadata",
    "get_token": "get_metadata",
    "inject_env": "get_env",
    "consume_token": "get_credential",
    "add": "add",
    "update": "add",
    "delete": "delete",
    "revoke_token": "delete",
    "unlock": None,
    "lock": None,
    "scan_text": None,
}


def _resolve_service(vault: VaultKnox, secret_id: str) -> str:
    """Resolve service from secret metadata."""
    try:
        row = vault.db.get_secret_row(secret_id)
        meta = vault._decode_metadata(derive_metadata_key(vault._session_entry_key()), row["metadata"])
        if "service" in meta and isinstance(meta.get("service"), str) and meta["service"]:
            return meta["service"]
        if row["type"] == "note":
            return "note"
        if isinstance(row["type"], str) and row["type"]:
            return row["type"]
        if "-" in secret_id:
            return secret_id.split("-")[0]
        if "_" in secret_id:
            return secret_id.split("_")[0]
        return secret_id
    except Exception:
        if "-" in secret_id:
            return secret_id.split("-")[0]
        if "_" in secret_id:
            return secret_id.split("_")[0]
        return secret_id


def _check_policy(
    paths,
    vault: VaultKnox,
    agent_id: str | None,
    action: str,
    secret_id: str | None = None,
    token: str | None = None,
    secret_type: str | None = None,
) -> dict[str, Any] | None:
    """Check policy access. Returns error dict if denied, None if allowed."""
    if action in NO_POLICY_ACTIONS:
        return None
    
    if agent_id is None:
        # No agent_id provided - deny by default for security
        return {"error": "policy_denied", "message": "agent_id required"}
    
    policy_engine = PolicyEngine(paths.base_dir / "policy.yaml")
    
    policy_action = ACTION_TO_POLICY.get(action)
    if policy_action is None:
        return None  # No policy check needed
    
    # Handle capability checks
    if policy_action in ("list_credentials", "scan_secrets", "export_backup", "import_credentials"):
        if not policy_engine.check_capability(agent_id, policy_action):
            return {"error": "policy_denied", "message": f"Agent lacks capability: {policy_action}"}
        return None
    
    # Resolve service
    service = "unknown"
    if secret_id:
        service = _resolve_service(vault, secret_id)
    elif token and action in {"consume_token", "revoke_token"}:
        try:
            token_row = vault.db.get_token_row(token)
            service = _resolve_service(vault, str(token_row["secret_id"]))
        except Exception:
            # Let vault operation raise canonical token error
            return None
    elif secret_type and action in {"add", "update"}:
        service = secret_type
    
    if not policy_engine.check_access(agent_id, service, policy_action):
        write_audit_event(paths.audit_log_path, f"tool_{action}", "denied", details={"agent_id": agent_id, "service": service})
        return {"error": "policy_denied", "message": f"Agent '{agent_id}' denied access to '{service}' for action '{policy_action}'"}

    if policy_action == "get_credential" and not policy_engine.can_get_raw_secret(agent_id, service):
        write_audit_event(paths.audit_log_path, f"tool_{action}", "denied", details={"agent_id": agent_id, "service": service, "reason": "raw_secret_access"})
        return {"error": "policy_denied", "message": f"Agent '{agent_id}' is not permitted raw secret access for '{service}'"}
    
    return None


def _clamp_token_ttl(paths, vault: VaultKnox, agent_id: str | None, secret_id: str, requested_ttl: int) -> int:
    if not agent_id:
        return requested_ttl
    policy_engine = PolicyEngine(paths.base_dir / "policy.yaml")
    service = _resolve_service(vault, secret_id)
    agent_policy = policy_engine._agents.get(agent_id)
    if not agent_policy:
        return requested_ttl
    token_ttl = requested_ttl
    if service in agent_policy.services:
        svc_max = agent_policy.services[service].max_ttl_seconds
        if svc_max:
            token_ttl = min(token_ttl, svc_max)
    if agent_policy.max_ttl_seconds:
        token_ttl = min(token_ttl, agent_policy.max_ttl_seconds)
    return token_ttl


def vault_tool(
    action: str,
    allow_write: bool = False,
    runtime_dir: str | None = None,
    master_password: str | None = None,
    agent_id: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    paths = expand_runtime_path(runtime_dir)
    vault = VaultKnox(paths)
    if action in WRITE_ACTIONS and not allow_write:
        raise VaultError("Write actions are disabled for Hermes unless allow_write is enabled")

    # Operator actions (unlock) require master_password
    if action in OPERATOR_ACTIONS:
        if not master_password:
            raise VaultError(f"Action '{action}' requires master_password")
    elif master_password is not None:
        raise VaultError(f"Action '{action}' does not accept master_password; unlock the vault first")

    try:
        # --- Policy check ---
        policy_error = _check_policy(
            paths,
            vault,
            agent_id,
            action,
            kwargs.get("secret_id"),
            kwargs.get("token"),
            kwargs.get("secret_type"),
        )
        if policy_error:
            return policy_error

        # --- Non-vault actions (no password or DB required) ---
        if action == "scan_text":
            text = kwargs.get("text", "")
            findings = []
            for detector in DETECTORS:
                for match in detector.pattern.finditer(text):
                    findings.append({
                        "detector": detector.name,
                        "severity": detector.severity,
                        "matched_text": match.group(0),
                        "span": match.span(),
                    })
            return {"findings": findings, "count": len(findings), "scanned_chars": len(text)}

        # --- Vault actions ---
        if action == "status":
            status = vault.status()
            result = {
                "initialized": status.initialized,
                "unlocked": status.unlocked,
                "secret_count": status.secret_count,
                "auto_lock_minutes": status.auto_lock_minutes,
            }
        elif action == "unlock":
            result = vault.unlock(master_password)
        elif action == "lock":
            vault.lock()
            result = {"status": "locked"}
        elif action == "list":
            result = {"secrets": vault.list_secrets()}
        elif action == "get_masked":
            token_ttl = _clamp_token_ttl(paths, vault, agent_id, kwargs["secret_id"], kwargs.get("token_ttl_seconds", 300))
            
            result = vault.get_masked(
                None,
                kwargs["secret_id"],
                purpose=kwargs.get("purpose"),
                token_ttl_seconds=token_ttl,
            )
        elif action == "get_token":
            token_ttl = _clamp_token_ttl(paths, vault, agent_id, kwargs["secret_id"], kwargs.get("token_ttl_seconds", 300))
            result = {
                "token": vault.issue_token(
                    kwargs["secret_id"],
                    purpose=kwargs["purpose"],
                    token_ttl_seconds=token_ttl,
                )
            }
        elif action == "add":
            result = vault.add_secret(
                None,  # Use session key
                kwargs["secret_id"],
                kwargs["secret_type"],
                kwargs["label"],
                kwargs["payload"],
            )
        elif action == "update":
            result = vault.update_secret(
                None,  # Use session key
                kwargs["secret_id"],
                kwargs["secret_type"],
                kwargs["label"],
                kwargs["payload"],
            )
        elif action == "delete":
            vault.delete_secret(None, kwargs["secret_id"])  # Use session key
            result = {"deleted": kwargs["secret_id"]}
        elif action == "inject_env":
            result = vault.inject_to_env(None, kwargs["secret_id"], kwargs["env_var"])
        elif action == "consume_token":
            result = vault.consume_token(None, kwargs["token"])
        elif action == "revoke_token":
            result = vault.revoke_token(None, kwargs["token"], kwargs.get("reason"))
        else:
            allowed = ", ".join(sorted(READ_ACTIONS | WRITE_ACTIONS | {"scan_text"}))
            raise VaultError(f"Unsupported action '{action}'. Allowed actions: {allowed}")
    except Exception:
        write_audit_event(paths.audit_log_path, f"tool_{action}", "failure")
        raise

    write_audit_event(paths.audit_log_path, f"tool_{action}", "success", details={"agent_id": agent_id})
    return result
