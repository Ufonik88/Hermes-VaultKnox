import pytest

from vaultknox.types import ValidationError, build_metadata, validate_secret


def test_card_metadata_masks_number() -> None:
    payload = {
        "number": "4111111111111111",
        "expiry": "12/28",
        "cvv": "123",
        "holder": "DJ C",
        "bank": "Revolut",
    }

    validate_secret("card", payload)
    metadata = build_metadata("card", payload)

    assert metadata == {"last4": "1111", "expiry": "12/28", "bank": "Revolut"}


def test_invalid_card_is_rejected() -> None:
    with pytest.raises(ValidationError):
        validate_secret("card", {"number": "12", "expiry": "12/28", "cvv": "1", "holder": "X", "bank": "Y"})


def test_connection_string_metadata_strips_credentials() -> None:
    payload = {"value": "postgresql://user:secret@db.example.com:5432/mydb"}
    validate_secret("connection_string", payload)
    meta = build_metadata("connection_string", payload)
    assert meta["scheme"] == "postgresql"
    assert meta["host"] == "db.example.com"
    assert meta["port"] == 5432
    assert meta["has_credentials"] is True
    # password must NOT appear in metadata
    assert "secret" not in str(meta)


def test_connection_string_sqlite_no_host_ok() -> None:
    validate_secret("connection_string", {"value": "sqlite:///path/to/db.sqlite3"})


def test_connection_string_unsupported_scheme_rejected() -> None:
    with pytest.raises(ValidationError, match="Unsupported connection string scheme"):
        validate_secret("connection_string", {"value": "ftp://example.com/db"})


def test_connection_string_missing_value_rejected() -> None:
    with pytest.raises(ValidationError):
        validate_secret("connection_string", {})


def test_password_type_validates_value() -> None:
    validate_secret("password", {"value": "hunter2"})
    meta = build_metadata("password", {"value": "hunter2"})
    assert meta == {}


def test_password_type_empty_value_rejected() -> None:
    with pytest.raises(ValidationError):
        validate_secret("password", {"value": ""})


def test_password_type_missing_field_rejected() -> None:
    with pytest.raises(ValidationError):
        validate_secret("password", {})
