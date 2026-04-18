from __future__ import annotations

from dataclasses import dataclass
from typing import Any


class ValidationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class SecretRecord:
    secret_id: str
    secret_type: str
    label: str
    payload: dict[str, Any]


ALLOWED_TYPES = {"card", "credential", "api_key", "note"}


def validate_secret(secret_type: str, payload: dict[str, Any]) -> None:
    if secret_type not in ALLOWED_TYPES:
        raise ValidationError(f"Unsupported secret type: {secret_type}")
    validator = {
        "card": _validate_card,
        "credential": _validate_credential,
        "api_key": _validate_api_key,
        "note": _validate_note,
    }[secret_type]
    validator(payload)


def build_metadata(secret_type: str, payload: dict[str, Any]) -> dict[str, Any]:
    if secret_type == "card":
        number = _required_str(payload, "number")
        expiry = _required_str(payload, "expiry")
        metadata = {
            "last4": number[-4:],
            "expiry": expiry,
        }
        if payload.get("bank"):
            metadata["bank"] = payload["bank"]
        return metadata
    if secret_type == "credential":
        metadata = {}
        if payload.get("username"):
            metadata["username_hint"] = payload["username"]
        if payload.get("url"):
            metadata["url"] = payload["url"]
        return metadata
    if secret_type == "api_key":
        return {
            "service": _required_str(payload, "service"),
            "scope": payload.get("scope"),
        }
    return {"kind": "note"}


def masked_view(secret_id: str, secret_type: str, label: str, metadata: dict[str, Any], token: str | None = None) -> dict[str, Any]:
    response = {
        "id": secret_id,
        "type": secret_type,
        "label": label,
        "metadata": metadata,
    }
    if token:
        response["token"] = token
    return response


def _validate_card(payload: dict[str, Any]) -> None:
    number = _required_str(payload, "number")
    cvv = _required_str(payload, "cvv")
    expiry = _required_str(payload, "expiry")
    _required_str(payload, "holder")
    _required_str(payload, "bank")
    if not number.isdigit() or len(number) < 12:
        raise ValidationError("Card number must contain at least 12 digits")
    if not cvv.isdigit() or len(cvv) not in {3, 4}:
        raise ValidationError("CVV must be 3 or 4 digits")
    if "/" not in expiry:
        raise ValidationError("Expiry must be in MM/YY format")


def _validate_credential(payload: dict[str, Any]) -> None:
    _required_str(payload, "username")
    _required_str(payload, "password")
    if payload.get("url") is not None:
        _required_str(payload, "url")


def _validate_api_key(payload: dict[str, Any]) -> None:
    _required_str(payload, "key")
    _required_str(payload, "service")


def _validate_note(payload: dict[str, Any]) -> None:
    _required_str(payload, "content")


def _required_str(payload: dict[str, Any], field: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"Field '{field}' must be a non-empty string")
    return value.strip()