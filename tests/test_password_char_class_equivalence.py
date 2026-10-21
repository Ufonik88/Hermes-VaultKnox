"""Behaviour-equivalence tests for the character-class refactor in ``passwords.py``.

The polish pass replaced ``re.search`` character-class probes with direct
string work. That is only a safe refactor if the two implementations agree on
*every* input, not just ASCII ones. These tests pin the pre-refactor semantics
(the regex versions) as the reference and assert the current implementation
matches it, including non-ASCII letters and non-ASCII decimal digits.
"""

from __future__ import annotations

import itertools
import math
import re

import pytest

from vaultknox.exceptions import VaultError
from vaultknox.passwords import (
    _char_classes,
    estimate_entropy,
    validate_password_strength,
)

# One representative per interesting Unicode category.
ALPHABET = [
    "a", "z",            # ASCII lowercase
    "A", "Z",            # ASCII uppercase
    "0", "9",            # ASCII digits
    "!", "_", " ",       # ASCII special
    "\u00e9",            # LATIN SMALL LETTER E WITH ACUTE  (str.islower() -> True)
    "\u00c9",            # LATIN CAPITAL LETTER E WITH ACUTE
    "\u00df",            # LATIN SMALL LETTER SHARP S
    "\u0663",            # ARABIC-INDIC DIGIT THREE (\d matches, isdecimal -> True)
    "\u00b2",            # SUPERSCRIPT TWO (isdigit -> True, but not \d)
    "\u6f22",            # CJK ideograph
    "\U0001f600",        # emoji
]


def _reference(password: str) -> tuple[bool, bool, bool, bool]:
    """The pre-refactor implementation, kept verbatim as the oracle."""
    return (
        bool(re.search(r"[a-z]", password)),
        bool(re.search(r"[A-Z]", password)),
        bool(re.search(r"\d", password)),
        bool(re.search(r"[^a-zA-Z0-9]", password)),
    )


@pytest.mark.parametrize("length", [1, 2, 3, 4])
def test_char_classes_match_reference_exhaustively(length: int) -> None:
    """Exhaustive agreement over all sequences up to four characters."""
    for combo in itertools.product(ALPHABET, repeat=length):
        password = "".join(combo)
        assert _char_classes(password) == _reference(password), (
            f"character-class drift for {password!r}: "
            f"got {_char_classes(password)}, reference {_reference(password)}"
        )


@pytest.mark.parametrize("password", ["", "a", "\u00e9\u00e9\u00e9\u00e9", "Stra\u00dfe12345678"])
def test_char_classes_match_reference_on_fixed_strings(password: str) -> None:
    assert _char_classes(password) == _reference(password)


def test_entropy_matches_reference_pool_sizes() -> None:
    """Entropy must depend only on the reference classes, not on Unicode intent."""
    for combo in itertools.product(ALPHABET, repeat=3):
        password = "".join(combo)
        lower, upper, digit, special = _reference(password)
        pool = 26 * lower + 26 * upper + 10 * digit + 32 * special
        expected = 0.0 if pool == 0 else len(password) * math.log2(pool)
        assert estimate_entropy(password) == pytest.approx(expected)


def test_non_ascii_letters_do_not_satisfy_lower_and_upper() -> None:
    """Regression: accented letters must not be promoted to ASCII lower/upper.

    Before the polish pass, ``"ÀÉÎõü1234567890"`` had only two counting
    character classes (digit + special) and was rejected. A ``str.islower()``
    based rewrite silently counted four and accepted it - loosening a security
    control.
    """
    password = "\u00c0\u00c9\u00ce\u00f5\u00fc1234567890"
    assert _reference(password) == (False, False, True, True)
    assert _char_classes(password) == (False, False, True, True)
    with pytest.raises(VaultError, match="at least 3 of"):
        validate_password_strength(password)


def test_sharp_s_counts_as_special_not_lower() -> None:
    password = "Stra\u00dfe12345678"
    assert _char_classes(password)[3] is True
    assert _reference(password)[3] is True
    # Previously valid (4 classes): digit + lower + upper + special.
    validate_password_strength(password)
