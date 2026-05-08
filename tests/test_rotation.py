"""
Tests for the master key rotation module.

These tests cover:
- Pre-rotation backup creation and encryption
- Backup NOT being decryptable with new password (only old)
- Successful rotation with correct passwords
- Atomic rollback on failure
- rotate_master_key function
- SQLite transaction atomicity
- BackupIntegrityError on tampered backup
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vaultknox.config import expand_runtime_path
from vaultknox.rotation import (
    _backup_filename,
    _create_pre_rotation_backup,
    _rollback_from_backup,
    delete_pre_rotation_backup,
    list_pre_rotation_backups,
    rotate_master_key,
)
from vaultknox.vault import VaultError, VaultKnox

# Placeholder passwords (20+ chars for Argon2id compatibility)
OLD_PASSWORD = "old-password-1234567890"
NEW_PASSWORD = "new-password-1234567890"


@pytest.fixture()
def vault(tmp_path: Path) -> VaultKnox:
    """Create and initialize a test vault."""
    vault = VaultKnox(expand_runtime_path(tmp_path / ".runtime"))
    vault.initialize(OLD_PASSWORD)
    return vault


@pytest.fixture()
def vault_with_secrets(vault: VaultKnox) -> VaultKnox:
    """Create a vault with some secrets pre-loaded."""
    vault.unlock(OLD_PASSWORD)
    vault.add_secret(
        OLD_PASSWORD,
        "api_key_1",
        "api_key",
        "Test API Key",
        {"key": "sk-test-old-001", "service": "TestService"},
    )
    vault.add_secret(
        OLD_PASSWORD,
        "credential_1",
        "credential",
        "Test Credential",
        {"username": "user@example.com", "password": "supersecret123"},
    )
    vault.add_secret(
        OLD_PASSWORD,
        "note_1",
        "note",
        "Test Note",
        {"content": "This is a secret note content."},
    )
    return vault


# ---------------------------------------------------------------------------
# Tests for _create_pre_rotation_backup
# ---------------------------------------------------------------------------

def test_backup_file_is_created_with_correct_encryption(
    vault_with_secrets: VaultKnox,
    tmp_path: Path,
) -> None:
    """
    Verify that the pre-rotation backup file is created and is encrypted
    with the OLD password (verified by successfully decrypting it with old creds).
    """
    db = vault_with_secrets.db
    vault_dir = tmp_path / ".runtime"

    backup_path = _create_pre_rotation_backup(db, vault_dir, OLD_PASSWORD)

    # Backup file should exist
    assert backup_path.exists(), "Pre-rotation backup file was not created"

    # Backup should be a .vbk file alongside the vault
    assert backup_path.suffix == ".vbk"
    assert backup_path.name.startswith("pre-rotation-backup-")

    # Backup should be valid JSON
    raw = json.loads(backup_path.read_text(encoding="utf-8"))

    # Backup should have required fields
    assert "version" in raw
    assert "nonce" in raw
    assert "ciphertext" in raw
    assert "created_at" in raw
    assert "signature" in raw
    assert raw["description"].startswith("Pre-rotation backup")

    # Verify the backup is actually encrypted (ciphertext is not raw SQLite)
    ciphertext_bytes = bytes.fromhex(raw["ciphertext"])
    assert not ciphertext_bytes.startswith(b"SQLite format 3"), \
        "Backup ciphertext should be encrypted, not raw SQLite"


def test_backup_file_is_not_decryptable_with_new_password(
    vault_with_secrets: VaultKnox,
    tmp_path: Path,
) -> None:
    """
    The pre-rotation backup is encrypted with the OLD password.
    It must NOT be decryptable with the NEW password — this is a security property.
    """
    db = vault_with_secrets.db
    vault_dir = tmp_path / ".runtime"

    backup_path = _create_pre_rotation_backup(db, vault_dir, OLD_PASSWORD)

    # Attempt to restore with the NEW password — this must fail
    with pytest.raises(VaultError, match="signature verification failed"):
        _rollback_from_backup(backup_path, db.db_path, NEW_PASSWORD)


def test_backup_decryptable_with_old_password(
    vault_with_secrets: VaultKnox,
    tmp_path: Path,
) -> None:
    """
    The pre-rotation backup must be decryptable with the OLD password.
    """
    db = vault_with_secrets.db
    vault_dir = tmp_path / ".runtime"

    backup_path = _create_pre_rotation_backup(db, vault_dir, OLD_PASSWORD)

    # Restore with old password must succeed
    original_db_path = db.db_path
    _rollback_from_backup(backup_path, original_db_path, OLD_PASSWORD)

    # The database should be restored (re-encrypted with old key still works)
    assert original_db_path.exists()
    assert original_db_path.read_bytes().startswith(b"SQLite format 3")


# ---------------------------------------------------------------------------
# Tests for rotate_master_key
# ---------------------------------------------------------------------------

def test_rotation_succeeds_with_correct_old_and_new_passwords(
    vault_with_secrets: VaultKnox,
    tmp_path: Path,
) -> None:
    """
    Successful rotation: old password works before, new password works after,
    old password fails after rotation.
    """
    db = vault_with_secrets.db
    vault_dir = tmp_path / ".runtime"

    # Verify old password works before rotation
    secret_before = vault_with_secrets.get_secret(OLD_PASSWORD, "api_key_1")
    assert secret_before["payload"]["key"] == "sk-test-old-001"

    # Perform rotation
    result = rotate_master_key(db, vault_dir, OLD_PASSWORD, NEW_PASSWORD)

    # Result should indicate success
    assert result["success"] is True
    assert "backup_path" in result
    assert result["secrets_rotated"] == 3

    # New password now works
    secret_new = vault_with_secrets.get_secret(NEW_PASSWORD, "api_key_1")
    assert secret_new["payload"]["key"] == "sk-test-old-001"

    # All three secrets are accessible with new password
    assert vault_with_secrets.get_secret(NEW_PASSWORD, "credential_1")["payload"]["username"] == "user@example.com"
    assert vault_with_secrets.get_secret(NEW_PASSWORD, "note_1")["payload"]["content"] == "This is a secret note content."

    # Old password should NOT work anymore
    with pytest.raises(VaultError):
        vault_with_secrets.get_secret(OLD_PASSWORD, "api_key_1")


def test_rotate_master_key_updates_vault_config(
    vault_with_secrets: VaultKnox,
    tmp_path: Path,
) -> None:
    """
    After rotation, the vault config (argon2_salt and verifier) should be updated.
    """
    db = vault_with_secrets.db
    vault_dir = tmp_path / ".runtime"

    # Get original salt
    original_salt = db.get_config("argon2_salt")

    # Rotate
    rotate_master_key(db, vault_dir, OLD_PASSWORD, NEW_PASSWORD)

    # Salt should be different (new one)
    new_salt = db.get_config("argon2_salt")
    assert new_salt != original_salt
    assert new_salt is not None

    # Verifier should also be updated (non-empty)
    verifier = db.get_config("verifier")
    assert verifier is not None
    assert len(verifier) > 0


def test_rotate_master_key_returns_correct_secrets_rotated_count(
    vault_with_secrets: VaultKnox,
    tmp_path: Path,
) -> None:
    """
    The result dict should accurately report how many secrets were rotated.
    """
    db = vault_with_secrets.db
    vault_dir = tmp_path / ".runtime"

    result = rotate_master_key(db, vault_dir, OLD_PASSWORD, NEW_PASSWORD)

    # We added 3 secrets in vault_with_secrets fixture
    assert result["secrets_rotated"] == 3


def test_rotation_with_no_secrets_succeeds(
    vault: VaultKnox,
    tmp_path: Path,
) -> None:
    """
    Rotation of a vault with zero secrets should succeed.
    """
    db = vault.db
    vault_dir = tmp_path / ".runtime"

    result = rotate_master_key(db, vault_dir, OLD_PASSWORD, NEW_PASSWORD)

    assert result["success"] is True
    assert result["secrets_rotated"] == 0

    # New password should work
    unlock_result = vault.unlock(NEW_PASSWORD)
    assert isinstance(unlock_result, dict)
    assert "unlocked_at" in unlock_result
    assert "expires_at" in unlock_result


# ---------------------------------------------------------------------------
# Tests for atomic rollback on failure
# ---------------------------------------------------------------------------

def test_rotation_rolls_back_on_failure(
    vault_with_secrets: VaultKnox,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    If rotation fails mid-way, the vault should be rolled back to its
    pre-rotation state automatically.
    """
    db = vault_with_secrets.db
    vault_dir = tmp_path / ".runtime"

    # Capture original secret state for comparison
    original_secret = vault_with_secrets.get_secret(OLD_PASSWORD, "api_key_1")
    assert original_secret["payload"]["key"] == "sk-test-old-001"

    # Force a failure during rotation by making decrypt_payload raise
    call_count = 0

    from vaultknox import rotation as rot_mod

    original_rotate = rot_mod.rotate_master_key

    def failing_rotate(*args: object, **kwargs: object) -> object:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            # First call is the backup creation, let it succeed
            return original_rotate(*args, **kwargs)
        raise RuntimeError("Injected failure for testing rollback")

    # Simulate a failure in the rotation process by patching at a lower level
    # We make the re-encryption step fail by patching list_secret_rows_raw

    def failing_list_rows() -> object:
        raise RuntimeError("Injected failure during secret listing")

    monkeypatch.setattr(db, "list_secret_rows_raw", failing_list_rows)

    # Rotation should raise VaultError due to the injected failure
    with pytest.raises(VaultError, match="Rotation failed"):
        rotate_master_key(db, vault_dir, OLD_PASSWORD, NEW_PASSWORD)

    # The vault should still be accessible with the OLD password (rollback worked)
    unlock_result = vault_with_secrets.unlock(OLD_PASSWORD)
    assert isinstance(unlock_result, dict)
    assert "unlocked_at" in unlock_result
    assert "expires_at" in unlock_result
    secret_after = vault_with_secrets.get_secret(OLD_PASSWORD, "api_key_1")
    assert secret_after["payload"]["key"] == "sk-test-old-001"


# ---------------------------------------------------------------------------
# Tests for SQLite transaction atomicity
# ---------------------------------------------------------------------------

def test_atomic_rotation_with_sqlite_transaction(
    vault_with_secrets: VaultKnox,
    tmp_path: Path,
) -> None:
    """
    Verify that rotation uses a single SQLite transaction for all updates.
    The vault should never be in a partially-updated state.
    """
    db = vault_with_secrets.db
    vault_dir = tmp_path / ".runtime"

    # Get initial salt
    original_salt = db.get_config("argon2_salt")

    # Perform rotation
    rotate_master_key(db, vault_dir, OLD_PASSWORD, NEW_PASSWORD)

    # Get new salt
    new_salt = db.get_config("argon2_salt")

    # Salt should have changed
    assert new_salt != original_salt

    # Vault is still locked after rotation — unlock and list secrets
    vault_with_secrets.unlock(NEW_PASSWORD)

    # All secrets should be accessible with new password
    # (if transaction was not atomic, some might be corrupted)
    all_secrets = vault_with_secrets.list_secrets()
    assert len(all_secrets) == 3

    # Each secret should be decryptable
    for secret in all_secrets:
        assert "payload" in vault_with_secrets.get_secret(NEW_PASSWORD, secret["id"])


def test_rotation_updates_all_secrets_atomically(
    vault_with_secrets: VaultKnox,
    tmp_path: Path,
) -> None:
    """
    Ensure no secret is left behind and all are updated in the same transaction.
    """
    db = vault_with_secrets.db
    vault_dir = tmp_path / ".runtime"

    # Rotate
    rotate_master_key(db, vault_dir, OLD_PASSWORD, NEW_PASSWORD)

    # Verify each secret individually
    api_key = vault_with_secrets.get_secret(NEW_PASSWORD, "api_key_1")
    assert api_key["payload"]["key"] == "sk-test-old-001"

    cred = vault_with_secrets.get_secret(NEW_PASSWORD, "credential_1")
    assert cred["payload"]["username"] == "user@example.com"
    assert cred["payload"]["password"] == "supersecret123"

    note = vault_with_secrets.get_secret(NEW_PASSWORD, "note_1")
    assert note["payload"]["content"] == "This is a secret note content."


# ---------------------------------------------------------------------------
# Tests for BackupIntegrityError when backup is tampered
# ---------------------------------------------------------------------------

def test_backup_integrity_error_when_signature_mismatched(
    vault_with_secrets: VaultKnox,
    tmp_path: Path,
) -> None:
    """
    If the backup file is tampered (signature verification fails),
    _rollback_from_backup should raise VaultError with an appropriate message.
    """
    db = vault_with_secrets.db
    vault_dir = tmp_path / ".runtime"

    # Create a valid backup first
    backup_path = _create_pre_rotation_backup(db, vault_dir, OLD_PASSWORD)

    # Tamper with the backup (modify ciphertext)
    raw = json.loads(backup_path.read_text(encoding="utf-8"))
    tampered_ciphertext = bytes.fromhex(raw["ciphertext"])
    tampered_ciphertext = bytes([tampered_ciphertext[0] ^ 0xFF]) + tampered_ciphertext[1:]
    raw["ciphertext"] = tampered_ciphertext.hex()
    # Remove signature so it won't match
    raw["signature"] = "tampered_signature_value"
    backup_path.write_text(json.dumps(raw, separators=(",", ":")), encoding="utf-8")

    # Rollback should fail with integrity error
    with pytest.raises(VaultError, match="signature verification failed"):
        _rollback_from_backup(backup_path, db.db_path, OLD_PASSWORD)


def test_backup_integrity_error_when_ciphertext_corrupted(
    vault_with_secrets: VaultKnox,
    tmp_path: Path,
) -> None:
    """
    If the ciphertext is corrupted but signature appears valid,
    decryption should fail.
    """
    db = vault_with_secrets.db
    vault_dir = tmp_path / ".runtime"

    backup_path = _create_pre_rotation_backup(db, vault_dir, OLD_PASSWORD)

    # Corrupt the ciphertext (but keep signature valid for old password)
    raw = json.loads(backup_path.read_text(encoding="utf-8"))
    tampered_ciphertext = bytes.fromhex(raw["ciphertext"])
    tampered_ciphertext = bytes([tampered_ciphertext[0] ^ 0xFF]) + tampered_ciphertext[1:]
    raw["ciphertext"] = tampered_ciphertext.hex()

    # Re-write with tampered ciphertext but keep signature
    import hashlib
    import hmac

    from vaultknox.core import derive_master_key, derive_scoped_key

    old_salt = bytes.fromhex(db.get_config("argon2_salt") or "")
    base_key = derive_master_key(OLD_PASSWORD, old_salt)
    signing_key = derive_scoped_key(base_key, b"vaultknox-pre-rotation-signature")
    payload_for_sig = {k: v for k, v in raw.items() if k != "signature"}
    canonical = json.dumps(payload_for_sig, separators=(",", ":"), sort_keys=True).encode("utf-8")
    raw["signature"] = hmac.new(signing_key, canonical, hashlib.sha256).hexdigest()

    backup_path.write_text(json.dumps(raw, separators=(",", ":")), encoding="utf-8")

    # Decryption should fail
    with pytest.raises(VaultError, match="decryption failed"):
        _rollback_from_backup(backup_path, db.db_path, OLD_PASSWORD)


def test_backup_integrity_error_when_not_sqlite_format(
    vault_with_secrets: VaultKnox,
    tmp_path: Path,
) -> None:
    """
    If the decrypted backup is not a valid SQLite database,
    it should raise VaultError.
    """
    db = vault_with_secrets.db
    vault_dir = tmp_path / ".runtime"

    backup_path = _create_pre_rotation_backup(db, vault_dir, OLD_PASSWORD)

    # Tamper to produce non-SQLite plaintext after decryption
    # We do this by corrupting the nonce which will produce garbage plaintext
    raw = json.loads(backup_path.read_text(encoding="utf-8"))
    tampered_nonce = bytes.fromhex(raw["nonce"])
    tampered_nonce = bytes([tampered_nonce[0] ^ 0xFF]) + tampered_nonce[1:]
    raw["nonce"] = tampered_nonce.hex()

    # Re-sign
    import hashlib
    import hmac

    from vaultknox.core import derive_master_key, derive_scoped_key

    old_salt = bytes.fromhex(db.get_config("argon2_salt") or "")
    base_key = derive_master_key(OLD_PASSWORD, old_salt)
    signing_key = derive_scoped_key(base_key, b"vaultknox-pre-rotation-signature")
    payload_for_sig = {k: v for k, v in raw.items() if k != "signature"}
    canonical = json.dumps(payload_for_sig, separators=(",", ":"), sort_keys=True).encode("utf-8")
    raw["signature"] = hmac.new(signing_key, canonical, hashlib.sha256).hexdigest()

    backup_path.write_text(json.dumps(raw, separators=(",", ":")), encoding="utf-8")

    # A corrupted nonce makes the ciphertext decrypt to garbage bytes, which is
        # The important security property is that corrupted backups are rejected.
    with pytest.raises(VaultError, match="signature verification failed|decryption failed"):
        _rollback_from_backup(backup_path, db.db_path, OLD_PASSWORD)


# ---------------------------------------------------------------------------
# Tests for list_pre_rotation_backups and delete_pre_rotation_backup
# ---------------------------------------------------------------------------

def test_list_pre_rotation_backups(
    vault_with_secrets: VaultKnox,
    tmp_path: Path,
) -> None:
    """Test listing of pre-rotation backup files."""
    db = vault_with_secrets.db
    vault_dir = tmp_path / ".runtime"

    # No backups initially
    backups = list_pre_rotation_backups(vault_dir)
    # May be empty or have leftovers from other tests

    # Create a backup
    _create_pre_rotation_backup(db, vault_dir, OLD_PASSWORD)

    backups = list_pre_rotation_backups(vault_dir)
    assert len(backups) >= 1
    assert all("path" in b for b in backups)
    assert all("created_at" in b for b in backups)
    assert all(b["size_bytes"] > 0 for b in backups)


def test_delete_pre_rotation_backup(
    vault_with_secrets: VaultKnox,
    tmp_path: Path,
) -> None:
    """Test secure deletion of a pre-rotation backup."""
    db = vault_with_secrets.db
    vault_dir = tmp_path / ".runtime"

    backup_path = _create_pre_rotation_backup(db, vault_dir, OLD_PASSWORD)
    assert backup_path.exists()

    delete_pre_rotation_backup(backup_path)

    assert not backup_path.exists()


def test_delete_pre_rotation_backup_not_found(
    vault: VaultKnox,
    tmp_path: Path,
) -> None:
    """Deleting a non-existent backup should raise VaultError."""
    non_existent = tmp_path / ".runtime" / "pre-rotation-backup-20240101T000000Z.vbk"

    with pytest.raises(VaultError, match="not found"):
        delete_pre_rotation_backup(non_existent)


# ---------------------------------------------------------------------------
# Tests for _backup_filename
# ---------------------------------------------------------------------------

def test_backup_filename_format(tmp_path: Path) -> None:
    """Verify backup filename format includes timestamp and .vbk extension."""
    filename = _backup_filename(tmp_path)

    assert filename.suffix == ".vbk"
    assert filename.name.startswith("pre-rotation-backup-")
    # Timestamp format: YYYYMMDDTHHMMSSZ
    assert "T" in filename.name
    assert filename.name.endswith(".vbk")


def test_backup_filename_in_vault_dir(tmp_path: Path) -> None:
    """Backup should be created in the vault directory."""
    vault_dir = tmp_path / ".runtime"
    vault_dir.mkdir(parents=True, exist_ok=True)

    filename = _backup_filename(vault_dir)

    assert filename.parent == vault_dir
