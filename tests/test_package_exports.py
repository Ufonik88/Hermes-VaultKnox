"""Verify the public vaultknox package surface matches __all__."""

from __future__ import annotations

import vaultknox


def test_version_is_semver_string() -> None:
    assert isinstance(vaultknox.__version__, str)
    parts = vaultknox.__version__.split(".")
    assert len(parts) == 3
    assert all(part.isdigit() for part in parts)


def test_public_exports_are_importable() -> None:
    for name in vaultknox.__all__:
        assert hasattr(vaultknox, name), f"vaultknox.__all__ lists {name!r} but it is not exported"


def test_autonomous_secrets_store_import() -> None:
    from vaultknox import AutonomousSecretsError, AutonomousSecretsStore

    assert AutonomousSecretsStore is not None
    assert issubclass(AutonomousSecretsError, Exception)