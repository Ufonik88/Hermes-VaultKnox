"""VaultKnox hooks package."""

from vaultknox.hooks.secret_guard import _REDACT_REPLACEMENT, handle

__all__ = ["handle", "_REDACT_REPLACEMENT"]
