from pathlib import Path

import pytest

from vaultknox.config import expand_runtime_path
from vaultknox.hermes_tool import vault_tool
from vaultknox.vault import VaultError, VaultKnox


@pytest.fixture()
def runtime_dir(tmp_path: Path) -> Path:
    return tmp_path / ".runtime"


def test_hermes_wrapper_blocks_write_by_default(runtime_dir: Path) -> None:
    vault = VaultKnox(expand_runtime_path(runtime_dir))
    vault.initialize("password")

    with pytest.raises(VaultError):
        vault_tool(
            "add",
            runtime_dir=str(runtime_dir),
            master_password="password",
            secret_id="note_1",
            secret_type="note",
            label="Note",
            payload={"content": "secret"},
        )


def test_hermes_wrapper_allows_gated_write(runtime_dir: Path) -> None:
    vault = VaultKnox(expand_runtime_path(runtime_dir))
    vault.initialize("password")
    vault.unlock("password")

    result = vault_tool(
        "add",
        allow_write=True,
        runtime_dir=str(runtime_dir),
        master_password="password",
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
    vault.initialize("password")
    vault.unlock("password")
    vault.add_secret("password", "note_1", "note", "Test Note", {"content": "secret content"})
    token = vault.issue_token("note_1", "test")

    result = vault_tool("consume_token", runtime_dir=str(runtime_dir), master_password="password", token=token)

    assert result["payload"]["content"] == "secret content"


def test_consume_token_already_used_raises(runtime_dir: Path) -> None:
    vault = VaultKnox(expand_runtime_path(runtime_dir))
    vault.initialize("password")
    vault.unlock("password")
    vault.add_secret("password", "note_1", "note", "Test Note", {"content": "secret content"})
    token = vault.issue_token("note_1", "test")
    vault_tool("consume_token", runtime_dir=str(runtime_dir), master_password="password", token=token)

    with pytest.raises(VaultError):
        vault_tool("consume_token", runtime_dir=str(runtime_dir), master_password="password", token=token)


def test_revoke_token_via_hermes_blocks_consume(runtime_dir: Path) -> None:
    vault = VaultKnox(expand_runtime_path(runtime_dir))
    vault.initialize("password")
    vault.unlock("password")
    vault.add_secret("password", "note_1", "note", "Test Note", {"content": "secret content"})
    token = vault.issue_token("note_1", "test")
    vault_tool("revoke_token", allow_write=True, runtime_dir=str(runtime_dir), master_password="password", token=token)

    with pytest.raises(VaultError, match="revoked"):
        vault_tool("consume_token", runtime_dir=str(runtime_dir), master_password="password", token=token)