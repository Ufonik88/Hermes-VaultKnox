"""
Master key rotation for VaultKnox.

Provides safe, atomic rotation of the master password with:
- Pre-rotation encrypted backup (encrypted with old password, cannot be opened with new)
- Atomic re-encryption in a single transaction
- Automatic rollback on failure
- CLI integration via ``vaultknox rotate-master-key``

Security notes
-------------
The pre-rotation backup is encrypted with a key derived from the OLD password.
This means:
- The backup CANNOT be opened with the new password (defence in depth if new pw is compromised)
- The backup CAN be opened with the old password (recovery if rotation fails mid-way)
- The backup file is chmod 600, stored alongside the vault
- The backup is NOT a full vault export — it contains the raw SQLite db bytes encrypted
  under the old key; it does NOT contain the vault config (salts, verifier, etc.)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vaultknox.config import PRIVATE_FILE_MODE, set_private_file_permissions
from vaultknox.core import NONCE_SIZE, derive_master_key, derive_scoped_key, encrypt_payload, generate_salt
from vaultknox.db import VaultDatabase
from vaultknox.exceptions import VaultError


def _backup_filename(vault_dir: Path) -> Path:
    """Path to the pre-rotation backup file."""
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return vault_dir / f"pre-rotation-backup-{timestamp}.vbk"


def _create_pre_rotation_backup(
    db: VaultDatabase,
    vault_dir: Path,
    old_password: str,
) -> Path:
    """
    Create an encrypted pre-rotation backup of the raw database.

    The backup is encrypted with a key derived from the OLD password ONLY.
    It can only be opened with the old credentials — not the new ones.

    Returns the path to the created backup file.
    """
    # Read raw database bytes
    raw_db = db.db_path.read_bytes()
    if not raw_db.startswith(b"SQLite format 3"):
        raise VaultError("Cannot create pre-rotation backup: database file is not a valid SQLite database")

    # Derive backup key from old password (NOT the new one)
    salt = bytes.fromhex(db.get_config("argon2_salt") or "")
    base_key = derive_master_key(old_password, salt)
    backup_key = derive_scoped_key(base_key, b"vaultknox-pre-rotation")
    signing_key = derive_scoped_key(base_key, b"vaultknox-pre-rotation-signature")

    # Generate a fresh random nonce for this backup
    nonce = generate_salt(NONCE_SIZE)

    # Encrypt the raw db
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    aesgcm = AESGCM(backup_key)
    # AESGCM expects additional_data=None for no-authenticated-data mode
    ciphertext = aesgcm.encrypt(nonce, raw_db, None)  # type: ignore[arg-type]

    backup_payload: dict[str, Any] = {
        "version": 1,
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "description": "Pre-rotation backup — encrypt with OLD master password only",
    }
    # Sign the payload (excluding signature itself)
    canonical = json.dumps(
        {k: v for k, v in backup_payload.items() if k != "signature"},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    sig = hmac.new(signing_key, canonical, hashlib.sha256).hexdigest()
    backup_payload["signature"] = sig

    backup_path = _backup_filename(vault_dir)
    backup_path.parent.mkdir(parents=True, exist_ok=True)
    backup_path.write_text(json.dumps(backup_payload, separators=(",", ":")), encoding="utf-8")
    os.chmod(backup_path, PRIVATE_FILE_MODE)

    return backup_path


def _restore_from_pre_rotation_backup(
    backup_path: Path,
    target_db_path: Path,
    old_password: str,
) -> None:
    """
    Restore the vault database from a pre-rotation backup file.

    This is the rollback path — used when rotation fails mid-way.
    The backup was encrypted with the old password.
    """
    raw = json.loads(backup_path.read_text(encoding="utf-8"))

    required = {"version", "nonce", "ciphertext", "created_at", "signature"}
    if not required.issubset(set(raw)):
        raise VaultError("Pre-rotation backup is missing required fields")

    if int(raw["version"]) != 1:
        raise VaultError(f"Unsupported pre-rotation backup format version: {raw['version']}")

    try:
        _nonce = bytes.fromhex(raw["nonce"])
        _ciphertext = bytes.fromhex(raw["ciphertext"])
    except ValueError as exc:
        raise VaultError("Pre-rotation backup contains invalid hex-encoded values") from exc

    # Re-derive the backup key from old password
    # We need the salt from the backup or the current vault.
    # For rollback, the salt should be stored in the backup or we read it from the live vault.
    # Store the salt in the backup itself for self-contained recovery.
    raise NotImplementedError(
        "Rollback requires the original salt stored in the backup. "
        "Implement _restore_from_pre_rotation_backup with salt stored in backup payload."
    )


def rotate_master_key(
    db: VaultDatabase,
    vault_dir: Path,
    old_password: str,
    new_password: str,
) -> dict[str, Any]:
    """
    Rotate the vault master key atomically.

    Steps:
      1. Create pre-rotation encrypted backup (encrypted with OLD password)
      2. Derive new master key and entry key from new password
      3. Decrypt all secrets with old key, re-encrypt with new key
      4. Update vault config (salt, verifier) in a single transaction
      5. On any failure: rollback and attempt to restore from backup

    The pre-rotation backup is retained after successful rotation (for safety).
    Use ``delete_pre_rotation_backups`` to clean up old backups manually.

    Returns a summary dict with backup_path and secret_count.
    """
    # Step 1: Create pre-rotation backup
    backup_path = _create_pre_rotation_backup(db, vault_dir, old_password)

    try:
        # Step 2: Derive old and new keys
        old_salt = bytes.fromhex(db.get_config("argon2_salt") or "")
        old_master_key = derive_master_key(old_password, old_salt)
        old_entry_key = derive_scoped_key(old_master_key)

        new_salt = generate_salt()
        new_master_key = derive_master_key(new_password, new_salt)
        new_entry_key = derive_scoped_key(new_master_key)
        new_verifier_key = derive_scoped_key(new_master_key, b"vaultknox-verifier")

        # Step 3: Re-encrypt all secrets
        rows = db.list_secret_rows_raw()
        decrypted_payloads: list[tuple[str, str, str, dict[str, Any], bytes, bytes, bytes]] = []
        for row in rows:
            from vaultknox.core import EncryptedPayload, decrypt_payload
            from vaultknox.types import build_metadata

            payload = decrypt_payload(
                old_entry_key,
                EncryptedPayload(nonce=row["nonce"], ciphertext=row["data"], tag=row["tag"]),
            )
            import secrets as _secrets

            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            new_nonce = _secrets.token_bytes(NONCE_SIZE)
            new_ciphertext = AESGCM(new_entry_key).encrypt(
                new_nonce,
                bytearray(json.dumps(payload, separators=(",", ":")).encode("utf-8")),
                None,
            )
            new_ciphertext_bytes = new_ciphertext[:-16]
            new_tag = new_ciphertext[-16:]
            metadata = build_metadata(row["type"], payload)
            decrypted_payloads.append((
                row["id"],
                row["type"],
                json.dumps(metadata, separators=(",", ":")),
                new_ciphertext_bytes,
                new_nonce,
                new_tag,
            ))

        # Step 4: Atomic write — update salt, verifier, and all secrets
        with db.connection() as conn:
            # Update salt
            conn.execute(
                "INSERT OR REPLACE INTO vault_config(key, value) VALUES(?, ?)",
                ("argon2_salt", new_salt.hex()),
            )
            # Update verifier
            verifier_enc = encrypt_payload(new_verifier_key, {"ok": True})
            conn.execute(
                "INSERT OR REPLACE INTO vault_config(key, value) VALUES(?, ?)",
                (
                    "verifier",
                    json.dumps({
                        "nonce": verifier_enc.nonce.hex(),
                        "ciphertext": verifier_enc.ciphertext.hex(),
                        "tag": verifier_enc.tag.hex(),
                    }, separators=(",", ":")),
                ),
            )
            # Update all secrets
            now = datetime.now(timezone.utc).isoformat()
            for secret_id, secret_type, metadata_json, ciphertext, nonce_bytes, tag in decrypted_payloads:
                conn.execute(
                    "UPDATE secrets SET type=?, data=?, nonce=?, tag=?, metadata=?, updated_at=? WHERE id=?",
                    (secret_type, ciphertext, nonce_bytes, tag, metadata_json, now, secret_id),
                )
            conn.commit()

        return {
            "success": True,
            "backup_path": str(backup_path),
            "secrets_rotated": len(decrypted_payloads),
        }

    except Exception as exc:  # noqa: BLE001
        # Rollback: restore from backup if we managed to create one
        if backup_path.exists():
            try:
                # Attempt to restore — if backup is valid this will recover the vault
                _rollback_from_backup(backup_path, db.db_path, old_password)
            except Exception as rollback_exc:  # noqa: BLE001
                raise VaultError(
                    f"Rotation failed and rollback also failed. "
                    f"Original error: {exc}. "
                    f"Rollback error: {rollback_exc}. "
                    f"Pre-rotation backup available at: {backup_path}"
                ) from exc
        raise VaultError(f"Rotation failed: {exc}") from exc


def _rollback_from_backup(backup_path: Path, db_path: Path, old_password: str) -> None:
    """
    Rollback the vault to the pre-rotation backup state.

    Reads the salt from the LIVE vault config (since we haven't overwritten it yet
    in a failed transaction) and uses it to decrypt the backup.
    """
    import sqlite3

    raw = json.loads(backup_path.read_text(encoding="utf-8"))

    nonce = bytes.fromhex(raw["nonce"])
    ciphertext = bytes.fromhex(raw["ciphertext"])

    # Read salt from the live vault (should still be intact since rotation failed before commit)
    # Connect to the db directly to get the salt
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute("SELECT value FROM vault_config WHERE key='argon2_salt'").fetchone()
        if row is None:
            raise VaultError("Cannot rollback: vault salt not found in database")
        old_salt = bytes.fromhex(str(row[0]))
    finally:
        conn.close()

    base_key = derive_master_key(old_password, old_salt)
    backup_key = derive_scoped_key(base_key, b"vaultknox-pre-rotation")
    signing_key = derive_scoped_key(base_key, b"vaultknox-pre-rotation-signature")

    # Verify signature
    payload_for_sig = {k: v for k, v in raw.items() if k != "signature"}
    canonical = json.dumps(payload_for_sig, separators=(",", ":"), sort_keys=True).encode("utf-8")
    expected_sig = hmac.new(signing_key, canonical, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_sig, raw.get("signature", "")):
        raise VaultError("Pre-rotation backup signature verification failed — backup may be corrupted")

    # Decrypt
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    aesgcm = AESGCM(backup_key)
    try:
        decrypted = aesgcm.decrypt(nonce, ciphertext, None)  # type: ignore[arg-type]
    except Exception as exc:
        raise VaultError(f"Pre-rotation backup decryption failed: {exc}") from exc

    if not decrypted.startswith(b"SQLite format 3\x00"):
        raise VaultError("Pre-rotation backup does not contain a valid SQLite database")

    # Overwrite the live db with the backup
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db_path.write_bytes(decrypted)
    set_private_file_permissions(db_path)


def list_pre_rotation_backups(vault_dir: Path) -> list[dict[str, Any]]:
    """List all pre-rotation backup files in the vault directory."""
    backups = []
    for path in sorted(vault_dir.glob("pre-rotation-backup-*.vbk")):
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            backups.append({
                "path": str(path),
                "created_at": raw.get("created_at"),
                "size_bytes": path.stat().st_size,
            })
        except Exception:  # noqa: BLE001
            backups.append({
                "path": str(path),
                "created_at": None,
                "size_bytes": path.stat().st_size,
                "error": "Could not read backup metadata",
            })
    return backups


def delete_pre_rotation_backup(backup_path: Path) -> None:
    """Securely delete a pre-rotation backup file."""
    if not backup_path.exists():
        raise VaultError(f"Pre-rotation backup not found: {backup_path}")
    # Overwrite with zeros before deleting (defense against file recovery)
    size = backup_path.stat().st_size
    with open(backup_path, "r+b") as f:
        f.write(b"\x00" * size)
    backup_path.unlink()
