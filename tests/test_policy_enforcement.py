from __future__ import annotations

from pathlib import Path

from vaultknox.config import expand_runtime_path
from vaultknox.hermes_tool import vault_tool
from vaultknox.vault import VaultKnox

STRONG_PASSWORD = "CorrectHorse123!"


def _write_policy(runtime_dir: Path, policy: dict) -> None:
    (runtime_dir / "policy.yaml").write_text(__import__("yaml").dump(policy, default_flow_style=False), encoding="utf-8")


def test_agent_without_policy_is_denied(tmp_path: Path) -> None:
    runtime_dir = tmp_path / ".runtime"
    vault = VaultKnox(expand_runtime_path(runtime_dir))
    vault.initialize(STRONG_PASSWORD)
    vault.unlock(STRONG_PASSWORD)

    result = vault_tool(
        "add",
        allow_write=True,
        runtime_dir=str(runtime_dir),
        agent_id="agent-a",
        secret_id="note_1",
        secret_type="note",
        label="Note",
        payload={"content": "secret"},
    )
    assert result["error"] == "policy_denied"


def test_policy_service_scoped_allow_and_deny(tmp_path: Path) -> None:
    runtime_dir = tmp_path / ".runtime"
    vault = VaultKnox(expand_runtime_path(runtime_dir))
    vault.initialize(STRONG_PASSWORD)
    vault.unlock(STRONG_PASSWORD)

    policy = {
        "version": "2",
        "agents": {
            "agent-a": {
                "services": {
                    "note": {"actions": ["add", "get_metadata", "get_credential"]},
                },
                "raw_secret_access": True,
                "capabilities": ["list_credentials"],
            }
        },
    }
    _write_policy(runtime_dir, policy)

    allowed = vault_tool(
        "add",
        allow_write=True,
        runtime_dir=str(runtime_dir),
        agent_id="agent-a",
        secret_id="note_1",
        secret_type="note",
        label="Allowed Note",
        payload={"content": "secret"},
    )
    assert allowed["id"] == "note_1"

    denied = vault_tool(
        "add",
        allow_write=True,
        runtime_dir=str(runtime_dir),
        agent_id="agent-a",
        secret_id="api_1",
        secret_type="api_key",
        label="Denied API",
        payload={"service": "openai", "key": "sk-test-allowed-xxxxxxxxxxxxxxxx"},
    )
    assert denied["error"] == "policy_denied"


def test_get_credential_requires_raw_secret_access(tmp_path: Path) -> None:
    runtime_dir = tmp_path / ".runtime"
    vault = VaultKnox(expand_runtime_path(runtime_dir))
    vault.initialize(STRONG_PASSWORD)
    vault.unlock(STRONG_PASSWORD)
    vault.add_secret(STRONG_PASSWORD, "note_1", "note", "Test Note", {"content": "secret-content"})
    token = vault.issue_token("note_1", "test")

    policy = {
        "version": "2",
        "agents": {
            "agent-a": {
                "services": {"note": {"actions": ["get_credential"]}},
                "raw_secret_access": False,
            }
        },
    }
    _write_policy(runtime_dir, policy)

    result = vault_tool("consume_token", runtime_dir=str(runtime_dir), agent_id="agent-a", token=token)
    assert result["error"] == "policy_denied"


def test_token_ttl_clamped_by_policy(tmp_path: Path) -> None:
    runtime_dir = tmp_path / ".runtime"
    vault = VaultKnox(expand_runtime_path(runtime_dir))
    vault.initialize(STRONG_PASSWORD)
    vault.unlock(STRONG_PASSWORD)
    vault.add_secret(STRONG_PASSWORD, "note_1", "note", "Test Note", {"content": "secret-content"})

    policy = {
        "version": "2",
        "agents": {
            "agent-a": {
                "services": {
                    "note": {"actions": ["get_metadata"], "max_ttl_seconds": 10},
                },
                "max_ttl_seconds": 20,
            }
        },
    }
    _write_policy(runtime_dir, policy)

    result = vault_tool(
        "get_masked",
        runtime_dir=str(runtime_dir),
        agent_id="agent-a",
        secret_id="note_1",
        purpose="test",
        token_ttl_seconds=999,
    )
    token = result.get("token")
    assert isinstance(token, str)

    row = vault.db.get_token_row(token)
    expires_at = row["expires_at"]
    from datetime import datetime, timezone

    dt = datetime.fromisoformat(expires_at)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    ttl = (dt - datetime.now(timezone.utc)).total_seconds()
    assert ttl <= 11


def test_denial_returns_no_secret_data(tmp_path: Path) -> None:
    runtime_dir = tmp_path / ".runtime"
    vault = VaultKnox(expand_runtime_path(runtime_dir))
    vault.initialize(STRONG_PASSWORD)
    vault.unlock(STRONG_PASSWORD)

    policy = {"version": "2", "agents": {}}
    _write_policy(runtime_dir, policy)

    result = vault_tool(
        "add",
        allow_write=True,
        runtime_dir=str(runtime_dir),
        agent_id="agent-a",
        secret_id="note_1",
        secret_type="note",
        label="Denied",
        payload={"content": "secret"},
    )
    assert result["error"] == "policy_denied"
    assert "payload" not in result
    assert "token" not in result
