from pathlib import Path

import pytest

from vaultknox.config import expand_runtime_path
from vaultknox.hermes_tool import vault_tool
from vaultknox.vault import VaultError, VaultKnox

# Strong test password meeting requirements: 12+ chars, 3+ char classes, 40+ bits entropy
STRONG_PASSWORD = "CorrectHorse123!"
TEST_AGENT_ID = "test-agent"

# Default policy for tests - allows test-agent full access
TEST_POLICY_YAML = """
version: "2"
agents:
  test-agent:
    services:
      note:
        actions: ["get_metadata", "get_env", "get_credential", "add", "delete"]
      api_key:
        actions: ["get_metadata", "get_env", "get_credential", "add", "delete"]
      credential:
        actions: ["get_metadata", "get_env", "get_credential", "add", "delete"]
      card:
        actions: ["get_metadata", "get_env", "get_credential", "add", "delete"]
      oauth:
        actions: ["get_metadata", "get_env", "get_credential", "add", "delete"]
    raw_secret_access: true
    capabilities: ["list_credentials"]
"""


@pytest.fixture()
def runtime_dir(tmp_path: Path) -> Path:
    return tmp_path / ".runtime"


@pytest.fixture()
def vault_with_policy(runtime_dir: Path) -> VaultKnox:
    """Create a vault with test policy."""
    vault = VaultKnox(expand_runtime_path(runtime_dir))
    vault.initialize(STRONG_PASSWORD)
    vault.unlock(STRONG_PASSWORD)
    
    # Write test policy
    policy_path = runtime_dir / "policy.yaml"
    policy_path.write_text(TEST_POLICY_YAML)
    
    return vault


def test_hermes_wrapper_blocks_write_by_default(runtime_dir: Path) -> None:
    vault = VaultKnox(expand_runtime_path(runtime_dir))
    vault.initialize(STRONG_PASSWORD)

    with pytest.raises(VaultError):
        vault_tool(
            "add",
            runtime_dir=str(runtime_dir),
            master_password=STRONG_PASSWORD,
            secret_id="note_1",
            secret_type="note",
            label="Note",
            payload={"content": "secret"},
        )


def test_hermes_wrapper_allows_gated_write(runtime_dir: Path) -> None:
    vault = VaultKnox(expand_runtime_path(runtime_dir))
    vault.initialize(STRONG_PASSWORD)
    vault.unlock(STRONG_PASSWORD)
    
    # Write test policy
    policy_path = runtime_dir / "policy.yaml"
    policy_path.write_text(TEST_POLICY_YAML)

    result = vault_tool(
        "add",
        allow_write=True,
        runtime_dir=str(runtime_dir),
        agent_id=TEST_AGENT_ID,
        secret_id="note_1",
        secret_type="note",
        label="Note",
        payload={"content": "secret"},
    )

    assert result["id"] == "note_1"
    masked = vault_tool("get_masked", runtime_dir=str(runtime_dir), agent_id=TEST_AGENT_ID, secret_id="note_1")
    assert masked["type"] == "note"


def test_consume_token_via_hermes(runtime_dir: Path) -> None:
    vault = VaultKnox(expand_runtime_path(runtime_dir))
    vault.initialize(STRONG_PASSWORD)
    vault.unlock(STRONG_PASSWORD)
    
    # Write test policy
    policy_path = runtime_dir / "policy.yaml"
    policy_path.write_text(TEST_POLICY_YAML)
    
    vault.add_secret(STRONG_PASSWORD, "note_1", "note", "Test Note", {"content": "secret content"})
    token = vault.issue_token("note_1", "test")

    result = vault_tool("consume_token", runtime_dir=str(runtime_dir), agent_id=TEST_AGENT_ID, token=token)

    assert result["payload"]["content"] == "secret content"


def test_consume_token_already_used_raises(runtime_dir: Path) -> None:
    vault = VaultKnox(expand_runtime_path(runtime_dir))
    vault.initialize(STRONG_PASSWORD)
    vault.unlock(STRONG_PASSWORD)
    
    # Write test policy
    policy_path = runtime_dir / "policy.yaml"
    policy_path.write_text(TEST_POLICY_YAML)
    
    vault.add_secret(STRONG_PASSWORD, "note_1", "note", "Test Note", {"content": "secret content"})
    token = vault.issue_token("note_1", "test")
    vault_tool("consume_token", runtime_dir=str(runtime_dir), agent_id=TEST_AGENT_ID, token=token)

    with pytest.raises(VaultError):
        vault_tool("consume_token", runtime_dir=str(runtime_dir), agent_id=TEST_AGENT_ID, token=token)


def test_revoke_token_via_hermes_blocks_consume(runtime_dir: Path) -> None:
    vault = VaultKnox(expand_runtime_path(runtime_dir))
    vault.initialize(STRONG_PASSWORD)
    vault.unlock(STRONG_PASSWORD)
    
    # Write test policy
    policy_path = runtime_dir / "policy.yaml"
    policy_path.write_text(TEST_POLICY_YAML)
    
    vault.add_secret(STRONG_PASSWORD, "note_1", "note", "Test Note", {"content": "secret content"})
    token = vault.issue_token("note_1", "test")
    vault_tool("revoke_token", allow_write=True, runtime_dir=str(runtime_dir), agent_id=TEST_AGENT_ID, token=token)

    with pytest.raises(VaultError, match="revoked"):
        vault_tool("consume_token", runtime_dir=str(runtime_dir), agent_id=TEST_AGENT_ID, token=token)


def test_agent_actions_work_without_master_password_after_unlock(runtime_dir: Path) -> None:
    """Agent actions should work without master_password after operator unlock."""
    vault = VaultKnox(expand_runtime_path(runtime_dir))
    vault.initialize(STRONG_PASSWORD)
    vault.unlock(STRONG_PASSWORD)
    
    # Write test policy
    policy_path = runtime_dir / "policy.yaml"
    policy_path.write_text(TEST_POLICY_YAML)

    # Agent can now use session key - no master_password needed
    result = vault_tool(
        "add",
        allow_write=True,
        runtime_dir=str(runtime_dir),
        agent_id=TEST_AGENT_ID,
        secret_id="note_1",
        secret_type="note",
        label="Note",
        payload={"content": "secret"},
    )
    assert result["id"] == "note_1"

    # Also test get_masked works without master_password
    masked = vault_tool("get_masked", runtime_dir=str(runtime_dir), agent_id=TEST_AGENT_ID, secret_id="note_1")
    assert masked["id"] == "note_1"