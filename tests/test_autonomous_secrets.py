"""
Tests for the autonomous (key-file-backed) secrets store.

Covers the v1->v2 migration crash-safety fix: the store file is the ONLY
file the migration rewrites, so an interrupted migration cannot strand a
key file that no longer matches the store (the previous design rewrote the
key file first and could permanently brick the pair).

Uses placeholder data only. No real secrets are used in these tests.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from vaultknox.autonomous_secrets import AutonomousSecretsStore
from vaultknox.exceptions import AutonomousSecretsError

DEMO_SECRETS = {"DEMO_ALPHA": "alpha-value", "DEMO_BETA": "beta-value"}


def _write_v1_store(store_dir: Path, fernet_key: bytes) -> None:
    """Write a v1 (Fernet) store and its key file into ``store_dir``."""
    store_dir.mkdir(parents=True, exist_ok=True)
    (store_dir / "master.key").write_bytes(fernet_key)
    token = Fernet(fernet_key).encrypt(json.dumps(DEMO_SECRETS).encode())
    (store_dir / "secrets.enc").write_bytes(token)


# =============================================================================
# Migration from a normal v1 store
# =============================================================================


def test_migration_round_trip_leaves_key_file_unchanged(tmp_path: Path) -> None:
    """First read migrates v1 -> v2; the key file bytes must not change."""
    store_dir = tmp_path / "encrypted-secrets"
    fernet_key = Fernet.generate_key()
    _write_v1_store(store_dir, fernet_key)

    store = AutonomousSecretsStore(store_dir)
    assert store._decrypt() == DEMO_SECRETS  # triggers migration

    # Key file untouched (crash safety), store now v2
    assert (store_dir / "master.key").read_bytes() == fernet_key
    header = json.loads((store_dir / "secrets.enc").read_text())
    assert header["v"] == 2

    # Second read is a plain v2 read (idempotent)
    assert store._decrypt() == DEMO_SECRETS


def test_migration_tolerates_raw_key_material(tmp_path: Path) -> None:
    """A key file holding raw (non-base64) key material is still recovered."""
    store_dir = tmp_path / "encrypted-secrets"
    store_dir.mkdir(parents=True)
    fernet_key = Fernet.generate_key()
    raw_key = base64.urlsafe_b64decode(fernet_key)
    # Store the raw key bytes, but encrypt the payload with the Fernet key.
    (store_dir / "master.key").write_bytes(raw_key)
    token = Fernet(fernet_key).encrypt(json.dumps(DEMO_SECRETS).encode())
    (store_dir / "secrets.enc").write_bytes(token)

    store = AutonomousSecretsStore(store_dir)
    assert store._decrypt() == DEMO_SECRETS


def test_interrupted_state_fails_cleanly_and_does_not_destroy_files(tmp_path: Path) -> None:
    """A half-migrated pair (new key file, v1 store) must raise, not crash silently."""
    store_dir = tmp_path / "encrypted-secrets"
    _write_v1_store(store_dir, Fernet.generate_key())
    # Simulate the interrupted migration: the key file was rewritten first.
    (store_dir / "master.key").write_bytes(b"\x42" * 32)
    store_before = (store_dir / "secrets.enc").read_bytes()

    store = AutonomousSecretsStore(store_dir)
    with pytest.raises(AutonomousSecretsError):
        store._decrypt()

    # Nothing was overwritten while failing
    assert (store_dir / "secrets.enc").read_bytes() == store_before


# =============================================================================
# v2 store lifecycle via the public API
# =============================================================================


def test_v2_lifecycle_set_get_list_delete(tmp_path: Path) -> None:
    store_dir = tmp_path / "encrypted-secrets"
    store = AutonomousSecretsStore(store_dir)

    store.initialize()
    assert store.list_keys() == []

    store.set("DEMO_ONE", "value-one")
    store.set("DEMO_TWO", "value-two")
    assert store.get("DEMO_ONE") == "value-one"
    assert store.list_keys() == ["DEMO_ONE", "DEMO_TWO"]

    store.delete("DEMO_ONE")
    assert store.list_keys() == ["DEMO_TWO"]
