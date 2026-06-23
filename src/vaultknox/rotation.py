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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vaultknox.config import create_private_dir, set_private_file_permissions, write_private_file
from vaultknox.core import (
    NONCE_SIZE,
    EncryptedPayload,
    decrypt_payload,
    derive_metadata_key,
    derive_master_key,
    derive_search_key,
    derive_scoped_key,
    encrypt_metadata,
    encrypt_payload,
    encrypt_search_token,
    generate_salt,
)
from vaultknox.db import VaultDatabase
from vaultknox.exceptions import VaultError
from vaultknox.types import build_metadata


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
        "version": 2,
        "salt": salt.hex(),
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
    create_private_dir(backup_path.parent)
    write_private_file(backup_path, json.dumps(backup_payload, separators=(",", ":")))

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
    Supports both v1 (legacy, reads salt from live vault) and v2 (self-contained) formats.
    """
    raw = json.loads(backup_path.read_text(encoding="utf-8"))

    required = {"version", "nonce", "ciphertext", "created_at", "signature"}
    if not required.issubset(set(raw)):
        raise VaultError("Pre-rotation backup is missing required fields")

    version = int(raw["version"])
    if version not in (1, 2):
        raise VaultError(f"Unsupported pre-rotation backup format version: {version}")

    try:
        nonce = bytes.fromhex(raw["nonce"])
        ciphertext = bytes.fromhex(raw["ciphertext"])
    except ValueError as exc:
        raise VaultError("Pre-rotation backup contains invalid hex-encoded values") from exc

    # Get salt: v2 stores it in backup, v1 reads from live vault
    if version == 2:
        try:
            salt = bytes.fromhex(raw["salt"])
        except (KeyError, ValueError) as exc:
            raise VaultError("Pre-rotation backup v2 missing or invalid salt") from exc
    else:
        # v1 fallback: read salt from live vault
        import sqlite3
        conn = sqlite3.connect(target_db_path)
        try:
            row = conn.execute("SELECT value FROM vault_config WHERE key='argon2_salt'").fetchone()
            if row is None:
                raise VaultError("Cannot rollback: vault salt not found in database")
            salt = bytes.fromhex(str(row[0]))
        finally:
            conn.close()

    base_key = derive_master_key(old_password, salt)
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
    target_db_path.parent.mkdir(parents=True, exist_ok=True)
    target_db_path.write_bytes(decrypted)
    set_private_file_permissions(target_db_path)


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
        new_metadata_key = derive_metadata_key(new_entry_key)
        new_search_key = derive_search_key(new_entry_key)

        # Step 3: Re-encrypt all secrets
        rows = db.list_secret_rows_raw()
        decrypted_payloads: list[tuple[str, str, str, bytes, bytes, bytes, str | None]] = []
        for row in rows:
            payload = decrypt_payload(
                old_entry_key,
                EncryptedPayload(nonce=row["nonce"], ciphertext=row["data"], tag=row["tag"]),
            )
            encrypted = encrypt_payload(new_entry_key, payload)
            metadata = encrypt_metadata(new_metadata_key, build_metadata(row["type"], payload))
            search_tokens = []
            for field_name, field_value in payload.items():
                if isinstance(field_value, str) and field_value:
                    search_tokens.append(encrypt_search_token(new_search_key, f"{field_name}:{field_value}"))
            decrypted_payloads.append((
                row["id"],
                row["type"],
                metadata,
                encrypted.ciphertext,
                encrypted.nonce,
                encrypted.tag,
                ",".join(search_tokens) if search_tokens else None,
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
            for secret_id, secret_type, metadata_json, ciphertext, nonce_bytes, tag, search_tokens in decrypted_payloads:
                conn.execute(
                    "UPDATE secrets SET type=?, data=?, nonce=?, tag=?, metadata=?, updated_at=?, search_tokens=? WHERE id=?",
                    (secret_type, ciphertext, nonce_bytes, tag, metadata_json, now, search_tokens, secret_id),
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

    Uses the self-contained backup (v2) which includes the salt, or falls back
    to reading from the live vault for v1 backups.
    """
    _restore_from_pre_rotation_backup(backup_path, db_path, old_password)


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
