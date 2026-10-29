from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit


class ValidationError(ValueError):
    """Raised when a secret validation fails."""
@dataclass(frozen=True, slots=True)
class SecretRecord:
    """Immutable data structure for a secret record."""
    secret_id: str
    secret_type: str
    label: str
    payload: dict[str, Any]
ALLOWED_TYPES = {"card", "credential", "api_key", "note", "connection_string", "password", "oauth"}
_CONNECTION_STRING_SCHEMES = {"postgresql", "postgres", "mysql", "mongodb", "redis", "amqp", "sqlite", "mssql", "mariadb"}
def validate_secret(secret_type: str, payload: dict[str, Any]) -> None:
    """
    Validate a secret record's type and payload.
    
    Args:
        secret_type: Type of secret (e.g., "credential", "api_key").
        payload: Secret data.
    
    Raises:
        ValidationError: If validation fails.
    """
    if secret_type not in ALLOWED_TYPES:
        raise ValidationError(f"Unsupported secret type: {secret_type}")
    
    validator = {
        "card": _validate_card,
        "credential": _validate_credential,
        "api_key": _validate_api_key,
        "note": _validate_note,
        "connection_string": _validate_connection_string,
        "password": _validate_password,
        "oauth": _validate_oauth,
    }[secret_type]
    validator(payload)
def build_metadata(secret_type: str, payload: dict[str, Any]) -> dict[str, Any]:
    """
    Build metadata for a secret based on its type.
    
    Args:
        secret_type: Type of secret.
        payload: Secret data.
    
    Returns:
        Metadata dictionary for the secret type.
    """
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
            # Store only first char + last char as hint, never full username
            username = payload["username"]
            if len(username) >= 2:
                metadata["username_hint"] = username[0] + "*" * (len(username) - 2) + username[-1]
            else:
                metadata["username_hint"] = "*" * len(username)
        
        if payload.get("url"):
            parsed = urlsplit(payload["url"])
            metadata["host"] = parsed.hostname or ""
        
        return metadata
    
    if secret_type == "api_key":
        return {
            "service": _required_str(payload, "service"),
            "scope": payload.get("scope"),
        }
    
    if secret_type == "connection_string":
        parsed = urlsplit(_required_str(payload, "value"))
        return {
            "scheme": parsed.scheme,
            "host": parsed.hostname or "",
            "port": parsed.port,
            "has_credentials": bool(parsed.username),
        }
    
    if secret_type == "password":
        return {}
    
    if secret_type == "oauth":
        metadata = {}
        provider_id = payload.get("provider_id")
        if isinstance(provider_id, str) and provider_id:
            metadata["service"] = provider_id
        
        if payload.get("expires_at"):
            metadata["expires_at"] = payload.get("expires_at")
        
        return metadata
    
    return {"kind": "note"}
def masked_view(secret_id: str, secret_type: str, label: str, metadata: dict[str, Any], token: str | None = None) -> dict[str, Any]:
    """
    Create a masked view of a secret for API responses.
    
    Args:
        secret_id: Unique identifier for the secret.
        secret_type: Type of secret.
        label: Human-readable label.
        metadata: Secret metadata.
        token: Optional token for the secret.
    
    Returns:
        Dictionary with masked secret information.
    """
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
    """Validate card secret payload."""
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
    """Validate credential secret payload."""
    _required_str(payload, "username")
    _required_str(payload, "password")
    if payload.get("url") is not None:
        _required_str(payload, "url")
def _validate_api_key(payload: dict[str, Any]) -> None:
    """Validate API key secret payload."""
    _required_str(payload, "key")
    _required_str(payload, "service")
def _validate_note(payload: dict[str, Any]) -> None:
    """Validate note secret payload."""
    _required_str(payload, "content")
def _validate_connection_string(payload: dict[str, Any]) -> None:
    """Validate connection string secret payload."""
    value = _required_str(payload, "value")
    parsed = urlsplit(value)
    if not parsed.scheme:
        raise ValidationError("Connection string must include a scheme (e.g. postgresql://)")
    
    if parsed.scheme not in _CONNECTION_STRING_SCHEMES:
        allowed = ", ".join(sorted(_CONNECTION_STRING_SCHEMES))
        raise ValidationError(f"Unsupported connection string scheme '{parsed.scheme}'. Allowed: {allowed}")
    
    if not parsed.netloc and parsed.scheme != "sqlite":
        raise ValidationError("Connection string must include a host")
def _validate_password(payload: dict[str, Any]) -> None:
    """Validate password secret payload."""
    _required_str(payload, "value")
def _validate_oauth(payload: dict[str, Any]) -> None:
    """Validate OAuth credential payload."""
    _required_str(payload, "provider_id")
    _required_str(payload, "access_token")
    # refresh_token is optional but recommended
    if payload.get("refresh_token") is not None:
        _required_str(payload, "refresh_token")
def _required_str(payload: dict[str, Any], field: str) -> str:
    """
    Extract and validate a required string field from a payload.
    
    Args:
        payload: Secret payload dictionary.
        field: Name of the field to extract.
    
    Returns:
        The string value of the field.
    
    Raises:
        ValidationError: If the field is missing or not a non-empty string.
    """
    value = payload.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"Field '{field}' must be a non-empty string")
    return value.strip()