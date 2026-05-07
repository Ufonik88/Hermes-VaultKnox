"""HTTP-based live verification of stored API keys against provider endpoints.

VaultKnox v0.3.0 — Credential Verifier Module

This module validates API keys that are already stored in the VaultKnox vault
by making HTTP requests to the appropriate provider endpoints.

Security: No secret values are logged or echoed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

import requests

# Timeout for HTTP requests (seconds)
DEFAULT_TIMEOUT = 5.0


@dataclass(frozen=True, slots=True)
class ProviderConfig:
    """Configuration for a credential verification provider."""

    name: str
    verify_url: str
    method: str = "GET"
    headers: dict[str, str] | None = None
    auth_type: str = "bearer"  # "bearer", "api_key", "basic"
    # For api_key auth type, which header name to use
    api_key_header: str | None = None
    # For basic auth, which payload fields contain credentials
    basic_username_field: str | None = None
    basic_password_field: str | None = None


@dataclass(frozen=True, slots=True)
class _VerificationResult:
    """Result of a credential verification attempt."""

    status: str  # "valid", "invalid", "billing_issue", "network_error", "timeout", "unknown"
    provider: str
    message: str | None = None
    http_status_code: int | None = None


# Provider verification function signature
# Takes the decrypted payload dict and returns a status string
ProviderVerifyFunc = Callable[[dict[str, Any]], _VerificationResult]

# Registry of provider verification functions
_PROVIDER_VERIFY_FUNCS: dict[str, ProviderVerifyFunc] = {}


# ----------------------------------------------------------------------
# Provider Registry
# ----------------------------------------------------------------------


def register_provider(
    service: str,
    verify_func: ProviderVerifyFunc,
) -> None:
    """Register a verification function for a service.

    Args:
        service: The service identifier (e.g., "openai", "anthropic").
        verify_func: A callable that takes a payload dict and returns _VerificationResult.
    """
    _PROVIDER_VERIFY_FUNCS[service.lower()] = verify_func


def get_provider(service: str) -> ProviderVerifyFunc | None:
    """Get the verification function for a service."""
    return _PROVIDER_VERIFY_FUNCS.get(service.lower())


def list_providers() -> list[str]:
    """List all registered service identifiers."""
    return list(_PROVIDER_VERIFY_FUNCS.keys())


# ----------------------------------------------------------------------
# Built-in Provider Implementations
# ----------------------------------------------------------------------


def _make_request(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    **kwargs: Any,
) -> tuple[requests.Response | None, str]:
    """Make an HTTP request and return (response, error_type)."""
    try:
        response = requests.request(
            method=method,
            url=url,
            headers=headers,
            timeout=timeout,
            **kwargs,
        )
        return response, "success"
    except requests.Timeout:
        return None, "timeout"
    except requests.RequestException:
        return None, "network_error"


def _verify_openai(payload: dict[str, Any]) -> _VerificationResult:
    """Verify an OpenAI API key."""
    api_key: str = payload.get("key", "")
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    response, error = _make_request(
        url="https://api.openai.com/v1/models",
        method="GET",
        headers=headers,
    )
    if error == "timeout":
        return _VerificationResult(status="timeout", provider="openai", message="Request timed out")
    if error == "network_error":
        return _VerificationResult(status="network_error", provider="openai", message="Network error occurred")
    if response is None:
        return _VerificationResult(status="unknown", provider="openai", message="Unexpected error")

    if response.status_code == 401:
        return _VerificationResult(status="invalid", provider="openai", http_status_code=401, message="Invalid API key")
    if response.status_code == 402:
        return _VerificationResult(status="billing_issue", provider="openai", http_status_code=402, message="Billing issue")
    if response.status_code == 200:
        return _VerificationResult(status="valid", provider="openai", http_status_code=200)
    # Handle rate limiting and other errors
    if response.status_code == 429:
        return _VerificationResult(status="billing_issue", provider="openai", http_status_code=429, message="Rate limited")
    return _VerificationResult(status="unknown", provider="openai", http_status_code=response.status_code, message=f"Unexpected response: {response.status_code}")


def _verify_anthropic(payload: dict[str, Any]) -> _VerificationResult:
    """Verify an Anthropic API key."""
    api_key: str = payload.get("key", "")
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "Content-Type": "application/json",
    }
    # Anthropic uses a lightweight endpoint for key validation
    response, error = _make_request(
        url="https://api.anthropic.com/v1/messages",
        method="POST",
        headers=headers,
        json={"model": "claude-3-haiku-20240307", "max_tokens": 1, "messages": []},
    )
    if error == "timeout":
        return _VerificationResult(status="timeout", provider="anthropic", message="Request timed out")
    if error == "network_error":
        return _VerificationResult(status="network_error", provider="anthropic", message="Network error occurred")
    if response is None:
        return _VerificationResult(status="unknown", provider="anthropic", message="Unexpected error")

    # Anthropic returns 401 for invalid keys, 402 for billing issues
    if response.status_code == 401:
        return _VerificationResult(status="invalid", provider="anthropic", http_status_code=401, message="Invalid API key")
    if response.status_code == 402:
        return _VerificationResult(status="billing_issue", provider="anthropic", http_status_code=402, message="Billing issue")
    if response.status_code == 201:
        return _VerificationResult(status="valid", provider="anthropic", http_status_code=201)
    # Handle rate limiting
    if response.status_code == 429:
        return _VerificationResult(status="billing_issue", provider="anthropic", http_status_code=429, message="Rate limited")
    return _VerificationResult(status="unknown", provider="anthropic", http_status_code=response.status_code, message=f"Unexpected response: {response.status_code}")


def _verify_github(payload: dict[str, Any]) -> _VerificationResult:
    """Verify a GitHub personal access token."""
    api_key: str = payload.get("key", "")
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    response, error = _make_request(
        url="https://api.github.com/user",
        method="GET",
        headers=headers,
    )
    if error == "timeout":
        return _VerificationResult(status="timeout", provider="github", message="Request timed out")
    if error == "network_error":
        return _VerificationResult(status="network_error", provider="github", message="Network error occurred")
    if response is None:
        return _VerificationResult(status="unknown", provider="github", message="Unexpected error")

    if response.status_code == 401:
        return _VerificationResult(status="invalid", provider="github", http_status_code=401, message="Invalid or expired token")
    if response.status_code == 200:
        return _VerificationResult(status="valid", provider="github", http_status_code=200)
    if response.status_code == 403:
        # Could be rate limiting or insufficient scopes
        return _VerificationResult(status="billing_issue", provider="github", http_status_code=403, message="Access forbidden or rate limited")
    return _VerificationResult(status="unknown", provider="github", http_status_code=response.status_code, message=f"Unexpected response: {response.status_code}")


def _verify_google_oauth(payload: dict[str, Any]) -> _VerificationResult:
    """Verify a Google OAuth access token."""
    access_token: str = payload.get("key", "")
    # Google's tokeninfo endpoint accepts the access token as a GET parameter
    response, error = _make_request(
        url=f"https://oauth2.googleapis.com/tokeninfo?access_token={access_token}",
        method="GET",
    )
    if error == "timeout":
        return _VerificationResult(status="timeout", provider="google_oauth", message="Request timed out")
    if error == "network_error":
        return _VerificationResult(status="network_error", provider="google_oauth", message="Network error occurred")
    if response is None:
        return _VerificationResult(status="unknown", provider="google_oauth", message="Unexpected error")

    if response.status_code == 200:
        return _VerificationResult(status="valid", provider="google_oauth", http_status_code=200)
    if response.status_code == 400:
        data = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
        error_desc = data.get("error_description", "invalid_token")
        if "invalid" in error_desc.lower() or "expired" in error_desc.lower():
            return _VerificationResult(status="invalid", provider="google_oauth", http_status_code=400, message=f"Invalid or expired token: {error_desc}")
        return _VerificationResult(status="billing_issue", provider="google_oauth", http_status_code=400, message=f"Token error: {error_desc}")
    return _VerificationResult(status="unknown", provider="google_oauth", http_status_code=response.status_code, message=f"Unexpected response: {response.status_code}")


def _verify_generic_bearer(payload: dict[str, Any], verify_url: str | None = None) -> _VerificationResult:
    """Verify a generic bearer token against a configurable URL.

    This provider requires the payload to contain:
    - key: The bearer token
    - verify_url: (optional) The URL to verify against; falls back to payload field
    """
    api_key: str = payload.get("key", "")
    url = verify_url or payload.get("verify_url")

    if not url:
        return _VerificationResult(status="unknown", provider="generic", message="No verify_url provided")

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Accept": "application/json",
    }
    response, error = _make_request(
        url=url,
        method="GET",
        headers=headers,
    )
    if error == "timeout":
        return _VerificationResult(status="timeout", provider="generic", message="Request timed out")
    if error == "network_error":
        return _VerificationResult(status="network_error", provider="generic", message="Network error occurred")
    if response is None:
        return _VerificationResult(status="unknown", provider="generic", message="Unexpected error")

    if response.status_code == 401:
        return _VerificationResult(status="invalid", provider="generic", http_status_code=401, message="Invalid bearer token")
    if response.status_code == 402:
        return _VerificationResult(status="billing_issue", provider="generic", http_status_code=402, message="Billing issue")
    if 200 <= response.status_code < 300:
        return _VerificationResult(status="valid", provider="generic", http_status_code=response.status_code)
    return _VerificationResult(status="unknown", provider="generic", http_status_code=response.status_code, message=f"Unexpected response: {response.status_code}")


# ----------------------------------------------------------------------
# Register built-in providers
# ----------------------------------------------------------------------

register_provider("openai", _verify_openai)
register_provider("anthropic", _verify_anthropic)
register_provider("github", _verify_github)
register_provider("google_oauth", _verify_google_oauth)


# ----------------------------------------------------------------------
# Main Verifier Class
# ----------------------------------------------------------------------


class CredentialVerifier:
    """HTTP-based credential verifier for VaultKnox.

    Verifies API keys stored in the vault by making live HTTP requests
    to the appropriate provider endpoints.

    Security: No secret values are logged or echoed.
    """

    def __init__(self, timeout: float = DEFAULT_TIMEOUT) -> None:
        """Initialize the verifier.

        Args:
            timeout: HTTP request timeout in seconds. Default is 5.0.
        """
        self.timeout = timeout

    def verify(self, secret_payload: dict[str, Any]) -> _VerificationResult:
        """Verify a credential against its provider.

        Accepts a secret payload dict as returned by vault.get_secret()['payload'].
        The payload must contain a 'service' field identifying the provider.

        Args:
            secret_payload: The decrypted payload dict containing:
                - key: The API key or token to verify
                - service: The service name (e.g., "openai", "anthropic")

        Returns:
            _VerificationResult with status and details.
            Status is one of: "valid", "invalid", "billing_issue", "network_error", "timeout", "unknown"
        """
        service = secret_payload.get("service", "").lower()
        if not service:
            return _VerificationResult(
                status="unknown",
                provider="unknown",
                message="No service specified in payload",
            )

        provider_func = get_provider(service)
        if provider_func is None:
            return _VerificationResult(
                status="unknown",
                provider=service,
                message=f"Unknown service: {service}. No verifier registered.",
            )

        try:
            return provider_func(secret_payload)
        except Exception as exc:
            return _VerificationResult(
                status="unknown",
                provider=service,
                message=f"Verification error: {exc}",
            )

    def verify_from_vault_response(self, vault_response: dict[str, Any]) -> _VerificationResult:
        """Verify a credential directly from vault.get_secret() response.

        This is a convenience method that extracts the payload from the
        vault response and verifies it.

        Args:
            vault_response: The response dict from vault.get_secret() containing:
                - type: The secret type (must be "api_key")
                - payload: The decrypted payload dict

        Returns:
            _VerificationResult with status and details.
        """
        secret_type = vault_response.get("type", "")
        if secret_type != "api_key":
            return _VerificationResult(
                status="unknown",
                provider="unknown",
                message=f"Unsupported secret type for verification: {secret_type}",
            )

        payload = vault_response.get("payload", {})
        return self.verify(payload)

    @staticmethod
    def register_service(service: str, verify_func: ProviderVerifyFunc) -> None:
        """Register a custom verification function for a service.

        This is a static method alias for register_provider().

        Args:
            service: The service identifier (e.g., "my_service").
            verify_func: A callable that takes a payload dict and returns _VerificationResult.
        """
        register_provider(service, verify_func)
