from pathlib import Path

import pytest

from vaultknox.config import expand_runtime_path
from vaultknox.vault import VaultError, VaultKnox


@pytest.fixture()
def vault(tmp_path: Path) -> VaultKnox:
    return VaultKnox(expand_runtime_path(tmp_path / ".runtime"))


def test_initialize_add_and_mask(vault: VaultKnox) -> None:
    vault.initialize("correct horse battery staple", auto_lock_minutes=10)

    vault.add_secret(
        "correct horse battery staple",
        "revolut_card",
        "card",
        "Revolut Virtual Card",
        {
            "number": "4111111111111111",
            "expiry": "12/28",
            "cvv": "123",
            "holder": "DJ C",
            "bank": "Revolut",
        },
    )

    masked = vault.get_masked("revolut_card", purpose="booking")

    assert masked["metadata"]["last4"] == "1111"
    assert masked["token"].startswith("vlt_")


def test_invalid_password_tracks_failures(vault: VaultKnox) -> None:
    vault.initialize("correct horse battery staple")

    with pytest.raises(VaultError):
        vault.add_secret("wrong password", "x", "note", "Label", {"content": "secret"})

    assert vault.db.get_config("failed_attempts") == "1"


def test_token_single_use(vault: VaultKnox) -> None:
    vault.initialize("correct horse battery staple")
    vault.add_secret(
        "correct horse battery staple",
        "api_openai",
        "api_key",
        "OpenAI",
        {"key": "sk-test", "service": "OpenAI", "scope": "full"},
    )
    token = vault.issue_token("api_openai", "integration")

    resolved = vault.consume_token("correct horse battery staple", token)

    assert resolved["payload"]["key"] == "sk-test"
    with pytest.raises(VaultError):
        vault.consume_token("correct horse battery staple", token)