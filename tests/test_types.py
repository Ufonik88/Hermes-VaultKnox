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