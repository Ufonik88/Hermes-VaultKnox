"""Password strength validation for VaultKnox."""

from __future__ import annotations

import math
import re

from vaultknox.exceptions import VaultError


def estimate_entropy(password: str) -> float:
    """Estimate password entropy in bits using NIST SP 800-63B approximation."""
    # Character pool sizes
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_special = bool(re.search(r"[^a-zA-Z0-9]", password))

    pool_size = 0
    if has_lower:
        pool_size += 26
    if has_upper:
        pool_size += 26
    if has_digit:
        pool_size += 10
    if has_special:
        pool_size += 32  # common special chars

    if pool_size == 0:
        return 0.0

    # Entropy = log2(pool_size^length) = length * log2(pool_size)
    return len(password) * math.log2(pool_size)


def validate_password_strength(password: str) -> None:
    """
    Validate password meets minimum strength requirements.

    Requirements:
    - Minimum 12 characters
    - At least 3 character classes (lower, upper, digit, special)
    - At least 40 bits of estimated entropy

    Raises:
        VaultError: If password doesn't meet requirements
    """
    if len(password) < 12:
        raise VaultError("Password must be at least 12 characters long")

    # Check character classes
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_special = bool(re.search(r"[^a-zA-Z0-9]", password))

    char_classes = sum([has_lower, has_upper, has_digit, has_special])
    if char_classes < 3:
        raise VaultError("Password must contain at least 3 of: lowercase, uppercase, digits, special characters")

    # Check entropy
    entropy = estimate_entropy(password)
    if entropy < 40:
        raise VaultError(f"Password entropy too low ({entropy:.1f} bits). Minimum 40 bits required.")


def validate_password_strength_or_raise(password: str, skip_check: bool = False) -> None:
    """Validate password strength unless skip_check is True."""
    if not skip_check:
        validate_password_strength(password)
