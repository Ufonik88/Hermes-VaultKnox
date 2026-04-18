from pathlib import Path

import pytest

from vaultknox.config import expand_runtime_path
from vaultknox.session import SessionStore
from vaultknox.vault import VaultError, VaultKnox


@pytest.fixture()
def vault(tmp_path: Path) -> VaultKnox:
    return VaultKnox(expand_runtime_path(tmp_path / ".runtime"))


def test_initialize_add_and_mask(vault: VaultKnox) -> None:
    vault.initialize("correct horse battery staple", auto_lock_minutes=10)
    vault.unlock("correct horse battery staple")

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
    vault.unlock("correct horse battery staple")
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


def test_change_password_reencrypts_entries(vault: VaultKnox) -> None:
    vault.initialize("old password")
    vault.add_secret(
        "old password",
        "private_note",
        "note",
        "Private Note",
        {"content": "top secret"},
    )

    vault.change_password("old password", "new password")

    with pytest.raises(VaultError):
        vault.get_secret("old password", "private_note")
    assert vault.get_secret("new password", "private_note")["payload"]["content"] == "top secret"


def test_export_and_import_round_trip(tmp_path: Path) -> None:
    source = VaultKnox(expand_runtime_path(tmp_path / "source"))
    destination = VaultKnox(expand_runtime_path(tmp_path / "destination"))
    source.initialize("correct horse battery staple")
    source.unlock("correct horse battery staple")
    source.add_secret(
        "correct horse battery staple",
        "api_openai",
        "api_key",
        "OpenAI",
        {"key": "sk-test", "service": "OpenAI", "scope": "full"},
    )

    export_file = tmp_path / "backup.vault"
    source.export_vault("correct horse battery staple", str(export_file))
    destination.import_vault("correct horse battery staple", str(export_file))

    destination.unlock("correct horse battery staple")
    imported = destination.get_masked("api_openai")
    assert imported["metadata"]["service"] == "OpenAI"


def test_import_rejects_tampered_backup(tmp_path: Path) -> None:
    source = VaultKnox(expand_runtime_path(tmp_path / "source"))
    destination = VaultKnox(expand_runtime_path(tmp_path / "destination"))
    source.initialize("correct horse battery staple")
    source.unlock("correct horse battery staple")
    source.add_secret(
        "correct horse battery staple",
        "api_openai",
        "api_key",
        "OpenAI",
        {"key": "sk-test", "service": "OpenAI", "scope": "full"},
    )
    export_file = tmp_path / "backup.vault"
    source.export_vault("correct horse battery staple", str(export_file))

    tampered = export_file.read_text(encoding="utf-8")
    tampered = tampered.replace('"signature":"', '"signature":"deadbeef')
    export_file.write_text(tampered, encoding="utf-8")

    with pytest.raises(VaultError, match="Backup integrity check failed"):
        destination.import_vault("correct horse battery staple", str(export_file))


def test_lockout_enforced_after_max_attempts(vault: VaultKnox) -> None:
    vault.initialize("correct horse battery staple", max_attempts=2, lockout_minutes=1)

    with pytest.raises(VaultError, match="Invalid master password"):
        vault.unlock("wrong")
    with pytest.raises(VaultError, match="Invalid master password"):
        vault.unlock("wrong")
    with pytest.raises(VaultError, match="temporarily locked"):
        vault.unlock("correct horse battery staple")


def test_token_expiry_is_enforced(vault: VaultKnox) -> None:
    vault.initialize("correct horse battery staple")
    vault.unlock("correct horse battery staple")
    vault.add_secret(
        "correct horse battery staple",
        "api_openai",
        "api_key",
        "OpenAI",
        {"key": "sk-test", "service": "OpenAI", "scope": "full"},
    )
    token = vault.issue_token("api_openai", "integration", token_ttl_seconds=0)

    with pytest.raises(VaultError, match="Token expired"):
        vault.consume_token("correct horse battery staple", token)


def test_corrupted_secret_payload_is_rejected(vault: VaultKnox) -> None:
    vault.initialize("correct horse battery staple")
    vault.add_secret(
        "correct horse battery staple",
        "private_note",
        "note",
        "Private Note",
        {"content": "top secret"},
    )
    with vault.db.connection() as conn:
        conn.execute("UPDATE secrets SET tag = ? WHERE id = ?", (b"x" * 16, "private_note"))

    with pytest.raises(VaultError, match="Secret decryption failed"):
        vault.get_secret("correct horse battery staple", "private_note")


def test_audit_log_does_not_contain_plaintext_secret(vault: VaultKnox) -> None:
    vault.initialize("correct horse battery staple")
    vault.unlock("correct horse battery staple")
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

    audit_text = vault.paths.audit_log_path.read_text(encoding="utf-8")
    assert "4111111111111111" not in audit_text
    assert '"cvv":"123"' not in audit_text


def test_stale_session_is_cleared(vault: VaultKnox) -> None:
    vault.initialize("correct horse battery staple")
    store = SessionStore(vault.paths.session_path, vault.paths.session_lock_path)
    store.write(auto_lock_minutes=5, owner_pid=-1)

    assert vault.status().unlocked is False