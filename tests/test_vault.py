from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from vaultknox.config import expand_runtime_path
from vaultknox.session import SessionStore
from vaultknox.vault import VaultError, VaultKnox

# Strong test password meeting requirements: 12+ chars, 3+ char classes, 40+ bits entropy
STRONG_PASSWORD = "CorrectHorse123!"


@pytest.fixture()
def vault(tmp_path: Path) -> VaultKnox:
    return VaultKnox(expand_runtime_path(tmp_path / ".runtime"))


def test_initialize_add_and_mask(vault: VaultKnox) -> None:
    vault.initialize(STRONG_PASSWORD, auto_lock_minutes=10)
    vault.unlock(STRONG_PASSWORD)

    vault.add_secret(
        STRONG_PASSWORD,
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

    masked = vault.get_masked(STRONG_PASSWORD, "revolut_card", purpose="booking")

    assert masked["metadata"]["last4"] == "1111"
    assert masked["token"].startswith("vlt_")


def test_invalid_password_tracks_failures(vault: VaultKnox) -> None:
    vault.initialize(STRONG_PASSWORD)

    with pytest.raises(VaultError):
        vault.add_secret("WrongPassword123!", "x", "note", "Label", {"content": "secret"})

    assert vault.db.get_config("failed_attempts") == "1"


def test_token_single_use(vault: VaultKnox) -> None:
    vault.initialize(STRONG_PASSWORD)
    vault.unlock(STRONG_PASSWORD)
    vault.add_secret(
        STRONG_PASSWORD,
        "api_openai",
        "api_key",
        "OpenAI",
        {"key": "sk-test", "service": "OpenAI", "scope": "full"},
    )
    token = vault.issue_token("api_openai", "integration")

    resolved = vault.consume_token(STRONG_PASSWORD, token)

    assert resolved["payload"]["key"] == "sk-test"
    with pytest.raises(VaultError):
        vault.consume_token(STRONG_PASSWORD, token)


def test_change_password_reencrypts_entries(vault: VaultKnox) -> None:
    vault.initialize(STRONG_PASSWORD)
    vault.add_secret(
        STRONG_PASSWORD,
        "private_note",
        "note",
        "Private Note",
        {"content": "top secret"},
    )

    vault.change_password(STRONG_PASSWORD, "NewPassword123!")

    with pytest.raises(VaultError):
        vault.get_secret(STRONG_PASSWORD, "private_note")
    assert vault.get_secret("NewPassword123!", "private_note")["payload"]["content"] == "top secret"


def test_export_and_import_round_trip(tmp_path: Path) -> None:
    source = VaultKnox(expand_runtime_path(tmp_path / "source"))
    destination = VaultKnox(expand_runtime_path(tmp_path / "destination"))
    source.initialize(STRONG_PASSWORD)
    source.unlock(STRONG_PASSWORD)
    source.add_secret(
        STRONG_PASSWORD,
        "api_openai",
        "api_key",
        "OpenAI",
        {"key": "sk-test", "service": "OpenAI", "scope": "full"},
    )

    export_file = tmp_path / "backup.vault"
    source.export_vault(STRONG_PASSWORD, str(export_file))
    destination.import_vault(STRONG_PASSWORD, str(export_file))

    destination.unlock(STRONG_PASSWORD)
    imported = destination.get_masked(STRONG_PASSWORD, "api_openai")
    assert imported["metadata"]["service"] == "OpenAI"


def test_import_rejects_tampered_backup(tmp_path: Path) -> None:
    source = VaultKnox(expand_runtime_path(tmp_path / "source"))
    destination = VaultKnox(expand_runtime_path(tmp_path / "destination"))
    source.initialize(STRONG_PASSWORD)
    source.unlock(STRONG_PASSWORD)
    source.add_secret(
        STRONG_PASSWORD,
        "api_openai",
        "api_key",
        "OpenAI",
        {"key": "sk-test", "service": "OpenAI", "scope": "full"},
    )
    export_file = tmp_path / "backup.vault"
    source.export_vault(STRONG_PASSWORD, str(export_file))

    tampered = export_file.read_text(encoding="utf-8")
    tampered = tampered.replace('"signature":"', '"signature":"deadbeef')
    export_file.write_text(tampered, encoding="utf-8")

    with pytest.raises(VaultError, match="Backup integrity check failed"):
        destination.import_vault(STRONG_PASSWORD, str(export_file))


def test_lockout_enforced_after_max_attempts(vault: VaultKnox) -> None:
    vault.initialize(STRONG_PASSWORD, max_attempts=2, lockout_minutes=1)

    with pytest.raises(VaultError, match="Invalid master password"):
        vault.unlock("wrong")
    with pytest.raises(VaultError, match="Invalid master password"):
        vault.unlock("wrong")
    with pytest.raises(VaultError, match="temporarily locked"):
        vault.unlock(STRONG_PASSWORD)


def test_token_expiry_is_enforced(vault: VaultKnox) -> None:
    vault.initialize(STRONG_PASSWORD)
    vault.unlock(STRONG_PASSWORD)
    vault.add_secret(
        STRONG_PASSWORD,
        "api_openai",
        "api_key",
        "OpenAI",
        {"key": "sk-test", "service": "OpenAI", "scope": "full"},
    )
    token = vault.issue_token("api_openai", "integration", token_ttl_seconds=0)

    with pytest.raises(VaultError, match="Token expired"):
        vault.consume_token(STRONG_PASSWORD, token)


def test_corrupted_secret_payload_is_rejected(vault: VaultKnox) -> None:
    vault.initialize(STRONG_PASSWORD)
    vault.add_secret(
        STRONG_PASSWORD,
        "private_note",
        "note",
        "Private Note",
        {"content": "top secret"},
    )
    with vault.db.connection() as conn:
        conn.execute("UPDATE secrets SET tag = ? WHERE id = ?", (b"x" * 16, "private_note"))

    with pytest.raises(VaultError, match="Secret decryption failed"):
        vault.get_secret(STRONG_PASSWORD, "private_note")


def test_audit_log_does_not_contain_plaintext_secret(vault: VaultKnox) -> None:
    vault.initialize(STRONG_PASSWORD)
    vault.unlock(STRONG_PASSWORD)
    vault.add_secret(
        STRONG_PASSWORD,
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


def test_metadata_stored_encrypted_but_returned_masked(vault: VaultKnox) -> None:
    vault.initialize(STRONG_PASSWORD)
    vault.unlock(STRONG_PASSWORD)
    vault.add_secret(
        STRONG_PASSWORD,
        "api_openai",
        "api_key",
        "OpenAI",
        {"key": "sk-test", "service": "OpenAI", "scope": "full"},
    )

    raw_metadata = vault.db.get_secret_row("api_openai")["metadata"]
    assert "OpenAI" not in raw_metadata
    assert "scope" not in raw_metadata

    masked = vault.get_masked(STRONG_PASSWORD, "api_openai")
    assert masked["metadata"] == {"service": "OpenAI", "scope": "full"}


def test_bulk_import_metadata_stored_encrypted(vault: VaultKnox) -> None:
    vault.initialize(STRONG_PASSWORD)
    vault.unlock(STRONG_PASSWORD)
    vault.bulk_import_secrets(
        STRONG_PASSWORD,
        [{"id": "bulk_key1", "type": "api_key", "label": "Key One", "data": {"key": "sk-1", "service": "Svc1"}}],
    )

    raw_metadata = vault.db.get_secret_row("bulk_key1")["metadata"]
    assert "Svc1" not in raw_metadata
    assert vault.get_masked(STRONG_PASSWORD, "bulk_key1")["metadata"]["service"] == "Svc1"


def test_expired_session_is_cleared(vault: VaultKnox) -> None:
    vault.initialize(STRONG_PASSWORD)
    store = SessionStore(vault.paths.session_path, vault.paths.session_lock_path)
    store.session_path.parent.mkdir(parents=True, exist_ok=True)
    expired_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    unlocked_at = expired_at - timedelta(minutes=5)
    store.session_path.write_text(
        (
            '{'
            f'"unlocked_at":"{unlocked_at.isoformat()}",' 
            f'"expires_at":"{expired_at.isoformat()}",' 
            f'"refreshed_at":"{expired_at.isoformat()}"'
            '}'
        ),
        encoding="utf-8",
    )

    assert vault.status().unlocked is False
    assert store.session_path.exists() is False


def test_corrupted_session_is_cleared(vault: VaultKnox) -> None:
    vault.initialize(STRONG_PASSWORD)
    store = SessionStore(vault.paths.session_path, vault.paths.session_lock_path)
    store.session_path.parent.mkdir(parents=True, exist_ok=True)
    store.session_path.write_text("not-json", encoding="utf-8")

    assert vault.status().unlocked is False
    assert store.session_path.exists() is False


def test_inject_to_env_sets_environment_variable(vault: VaultKnox, monkeypatch: pytest.MonkeyPatch) -> None:
    vault.initialize(STRONG_PASSWORD)
    vault.unlock(STRONG_PASSWORD)
    vault.add_secret(
        STRONG_PASSWORD,
        "api_openai",
        "api_key",
        "OpenAI Key",
        {"key": "sk-test-abc123", "service": "OpenAI"},
    )

    result = vault.inject_to_env(STRONG_PASSWORD, "api_openai", "TEST_OPENAI_KEY")

    assert result["injected"] == "TEST_OPENAI_KEY"
    assert result["secret_id"] == "api_openai"
    import os
    assert os.environ.get("TEST_OPENAI_KEY") == "sk-test-abc123"
    monkeypatch.delenv("TEST_OPENAI_KEY", raising=False)


def test_inject_to_env_credential_injects_password(vault: VaultKnox, monkeypatch: pytest.MonkeyPatch) -> None:
    vault.initialize(STRONG_PASSWORD)
    vault.unlock(STRONG_PASSWORD)
    vault.add_secret(
        STRONG_PASSWORD,
        "db_cred",
        "credential",
        "DB Password",
        {"username": "admin", "password": "s3cr3t!"},
    )

    vault.inject_to_env(STRONG_PASSWORD, "db_cred", "TEST_DB_PASSWORD")

    import os
    assert os.environ.get("TEST_DB_PASSWORD") == "s3cr3t!"
    monkeypatch.delenv("TEST_DB_PASSWORD", raising=False)


def test_revoke_token_prevents_consume(vault: VaultKnox) -> None:
    vault.initialize(STRONG_PASSWORD)
    vault.unlock(STRONG_PASSWORD)
    vault.add_secret(
        STRONG_PASSWORD,
        "api_openai",
        "api_key",
        "OpenAI",
        {"key": "sk-test", "service": "OpenAI"},
    )
    token = vault.issue_token("api_openai", "integration")

    vault.revoke_token(STRONG_PASSWORD, token, reason="test revocation")

    with pytest.raises(VaultError, match="revoked"):
        vault.consume_token(STRONG_PASSWORD, token)


def test_revoke_token_requires_valid_password(vault: VaultKnox) -> None:
    vault.initialize(STRONG_PASSWORD)
    vault.unlock(STRONG_PASSWORD)
    vault.add_secret(
        STRONG_PASSWORD,
        "api_openai",
        "api_key",
        "OpenAI",
        {"key": "sk-test", "service": "OpenAI"},
    )
    token = vault.issue_token("api_openai", "integration")

    with pytest.raises(VaultError):
        vault.revoke_token("WrongPassword123!", token)


def test_expired_secret_returns_expired_flag(vault: VaultKnox) -> None:
    from datetime import datetime, timedelta, timezone
    vault.initialize(STRONG_PASSWORD)
    vault.unlock(STRONG_PASSWORD)
    past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    vault.add_secret(
        STRONG_PASSWORD,
        "old_key",
        "api_key",
        "Old Key",
        {"key": "sk-expired", "service": "OldService"},
        expires_at=past,
    )

    result = vault.get_secret(STRONG_PASSWORD, "old_key")
    assert result["expired"] is True
    assert result["id"] == "old_key"
    assert "payload" not in result


def test_non_expired_secret_returns_payload(vault: VaultKnox) -> None:
    from datetime import datetime, timedelta, timezone
    vault.initialize(STRONG_PASSWORD)
    vault.unlock(STRONG_PASSWORD)
    future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    vault.add_secret(
        STRONG_PASSWORD,
        "fresh_key",
        "api_key",
        "Fresh Key",
        {"key": "sk-fresh", "service": "FreshService"},
        expires_at=future,
    )

    result = vault.get_secret(STRONG_PASSWORD, "fresh_key")
    assert "expired" not in result
    assert result["payload"]["key"] == "sk-fresh"


def test_secret_with_no_expiry_returns_payload(vault: VaultKnox) -> None:
    vault.initialize(STRONG_PASSWORD)
    vault.unlock(STRONG_PASSWORD)
    vault.add_secret(
        STRONG_PASSWORD,
        "permanent_key",
        "api_key",
        "Permanent Key",
        {"key": "sk-permanent", "service": "Forever"},
    )

    result = vault.get_secret(STRONG_PASSWORD, "permanent_key")
    assert result["payload"]["key"] == "sk-permanent"


def test_bulk_import_secrets(vault: VaultKnox) -> None:
    vault.initialize(STRONG_PASSWORD)
    vault.unlock(STRONG_PASSWORD)

    entries = [
        {"id": "bulk_key1", "type": "api_key", "label": "Key One", "data": {"key": "sk-1", "service": "Svc1"}},
        {"id": "bulk_key2", "type": "api_key", "label": "Key Two", "data": {"key": "sk-2", "service": "Svc2"}},
        {"id": "bulk_note", "type": "note", "label": "A Note", "data": {"content": "hello world"}},
    ]
    result = vault.bulk_import_secrets(STRONG_PASSWORD, entries)

    assert set(result["imported"]) == {"bulk_key1", "bulk_key2", "bulk_note"}
    assert result["skipped"] == []

    secret = vault.get_secret(STRONG_PASSWORD, "bulk_key1")
    assert secret["payload"]["key"] == "sk-1"


def test_bulk_import_duplicate_rolls_back_all(vault: VaultKnox) -> None:
    vault.initialize(STRONG_PASSWORD)
    vault.unlock(STRONG_PASSWORD)
    vault.add_secret(
        STRONG_PASSWORD,
        "existing",
        "api_key",
        "Existing",
        {"key": "sk-existing", "service": "Existing"},
    )

    entries = [
        {"id": "existing", "type": "api_key", "label": "Duplicate", "data": {"key": "sk-dup", "service": "Dup"}},
        {"id": "new_key", "type": "api_key", "label": "New", "data": {"key": "sk-new", "service": "New"}},
    ]
    with pytest.raises(VaultError, match="rolled back"):
        vault.bulk_import_secrets(STRONG_PASSWORD, entries)

    with pytest.raises(KeyError):
        vault.db.get_secret_row("new_key")


def test_bulk_import_validation_error_raises(vault: VaultKnox) -> None:
    vault.initialize(STRONG_PASSWORD)
    entries = [
        {"id": "bad", "type": "api_key", "label": "Bad", "data": {"service": "missing_key_field"}},
    ]
    with pytest.raises(VaultError, match="missing_key_field|key"):
        vault.bulk_import_secrets(STRONG_PASSWORD, entries)


def test_naive_timezone_token_expiry_is_handled_safely(vault: VaultKnox) -> None:
    vault.initialize(STRONG_PASSWORD)
    vault.unlock(STRONG_PASSWORD)
    vault.add_secret(
        STRONG_PASSWORD,
        "api_openai",
        "api_key",
        "OpenAI",
        {"key": "sk-test", "service": "OpenAI", "scope": "full"},
    )
    token = vault.issue_token("api_openai", "integration")
    with vault.db.connection() as conn:
        conn.execute(
            "UPDATE vault_tokens SET expires_at = ? WHERE token = ?",
            ("2000-01-01T00:00:00", token),
        )

    with pytest.raises(VaultError, match="expired"):
        vault.consume_token(STRONG_PASSWORD, token)


def test_naive_timezone_expiry_is_handled_safely(vault: VaultKnox) -> None:
    vault.initialize(STRONG_PASSWORD)
    vault.unlock(STRONG_PASSWORD)
    # Naive timezone ISO string (without offset)
    past_naive = "2000-01-01T00:00:00"
    vault.add_secret(
        STRONG_PASSWORD,
        "naive_expired_key",
        "api_key",
        "Naive Expired Key",
        {"key": "sk-naive-expired", "service": "NaiveSvc"},
        expires_at=past_naive,
    )

    # Retrieval should not raise TypeError and correctly detect it as expired
    result = vault.get_secret(STRONG_PASSWORD, "naive_expired_key")
    assert result["expired"] is True
    assert result["id"] == "naive_expired_key"
