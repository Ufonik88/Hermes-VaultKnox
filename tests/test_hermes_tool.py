from pathlib import Path

import pytest

from vaultknox.config import expand_runtime_path
from vaultknox.hermes_tool import vault_tool
from vaultknox.vault import VaultError, VaultKnox

# Strong test password meeting requirements: 12+ chars, 3+ char classes, 40+ bits entropy
STRONG_PASSWORD = "CorrectHorse123!"


@pytest.fixture()
def runtime_dir(tmp_path: Path) -> Path:
    return tmp_path / ".runtime"


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

    result = vault_tool(
        "add",
        allow_write=True,
        runtime_dir=str(runtime_dir),
        master_password=STRONG_PASSWORD,
        secret_id="note_1",
        secret_type="note",
        label="Note",
        payload={"content": "secret"},
    )

    assert result["id"] == "note_1"
    masked = vault_tool("get_masked", runtime_dir=str(runtime_dir), secret_id="note_1")
    assert masked["type"] == "note"


def test_consume_token_via_hermes(runtime_dir: Path) -> None:
    vault = VaultKnox(expand_runtime_path(runtime_dir))
    vault.initialize(STRONG_PASSWORD)
    vault.unlock(STRONG_PASSWORD)
    vault.add_secret(STRONG_PASSWORD, "note_1", "note", "Test Note", {"content": "secret content"})
    token = vault.issue_token("note_1", "test")

    result = vault_tool("consume_token", runtime_dir=str(runtime_dir), master_password=STRONG_PASSWORD, token=token)

    assert result["payload"]["content"] == "secret content"


def test_consume_token_already_used_raises(runtime_dir: Path) -> None:
    vault = VaultKnox(expand_runtime_path(runtime_dir))
    vault.initialize(STRONG_PASSWORD)
    vault.unlock(STRONG_PASSWORD)
    vault.add_secret(STRONG_PASSWORD, "note_1", "note", "Test Note", {"content": "secret content"})
    token = vault.issue_token("note_1", "test")
    vault_tool("consume_token", runtime_dir=str(runtime_dir), master_password=STRONG_PASSWORD, token=token)

    with pytest.raises(VaultError):
        vault_tool("consume_token", runtime_dir=str(runtime_dir), master_password=STRONG_PASSWORD, token=token)


def test_revoke_token_via_hermes_blocks_consume(runtime_dir: Path) -> None:
    vault = VaultKnox(expand_runtime_path(runtime_dir))
    vault.initialize(STRONG_PASSWORD)
    vault.unlock(STRONG_PASSWORD)
    vault.add_secret(STRONG_PASSWORD, "note_1", "note", "Test Note", {"content": "secret content"})
    token = vault.issue_token("note_1", "test")
    vault_tool("revoke_token", allow_write=True, runtime_dir=str(runtime_dir), master_password=STRONG_PASSWORD, token=token)

    with pytest.raises(VaultError, match="revoked"):
        vault_tool("consume_token", runtime_dir=str(runtime_dir), master_password=STRONG_PASSWORD, token=token)


def test_agent_actions_work_without_master_password_after_unlock(runtime_dir: Path) -> None:
    """Agent actions should work without master_password after operator unlock."""
    vault = VaultKnox(expand_runtime_path(runtime_dir))
    vault.initialize(STRONG_PASSWORD)
    vault.unlock(STRONG_PASSWORD)

    # Agent can now use session key - no master_password needed
    result = vault_tool(
        "add",
        allow_write=True,
        runtime_dir=str(runtime_dir),
        secret_id="note_1",
        secret_type="note",
        label="Note",
        payload={"content": "secret"},
    )
    assert result["id"] == "note_1"

    # Also test get_masked works without master_password
    masked = vault_tool("get_masked", runtime_dir=str(runtime_dir), secret_id="note_1")
    assert masked["id"] == "note_1"