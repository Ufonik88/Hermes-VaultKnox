"""Common exceptions for VaultKnox."""

from __future__ import annotations


class VaultError(RuntimeError):
    """Base exception for VaultKnox errors."""
    pass


class AutonomousSecretsError(Exception):
    """Raised when an autonomous secrets operation fails."""
    pass


class OAuthError(Exception):
    """Base exception for OAuth errors."""
    pass


class OAuthTimeout(OAuthError):
    """Callback timed out."""
    pass


class OAuthDenied(OAuthError):
    """User denied authorization."""
    pass


class OAuthStateMismatch(OAuthError):
    """CSRF state mismatch."""
    pass


class OAuthTokenError(OAuthError):
    """Token exchange failed."""
    pass
