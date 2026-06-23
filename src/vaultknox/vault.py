from __future__ import annotations

import atexit
import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from vaultknox.audit import write_audit_event
from vaultknox.config import (
    DEFAULT_AUTO_LOCK_MINUTES,
    DEFAULT_KDF_PARAMS,
    DEFAULT_LOCKOUT_MINUTES,
    DEFAULT_MAX_ATTEMPTS,
    DEFAULT_TOKEN_TTL_SECONDS,
    VaultPaths,
    create_private_dir,
    set_private_file_permissions,
    write_private_file,
)
from vaultknox.core import (
    NONCE_SIZE,
    EncryptedPayload,
    decrypt_payload,
    decrypt_metadata,
    derive_metadata_key,
    derive_master_key,
    derive_search_key,
    derive_scoped_key,
    encrypt_metadata,
    encrypt_payload,
    encrypt_search_token,
    generate_salt,
    generate_token,
    validate_kdf_params,
)
from vaultknox.db import VaultDatabase
from vaultknox.exceptions import VaultError
from vaultknox.oauth import DEFAULT_PROVIDERS, OAuthTokenError, StoredOAuth, refresh_access_token
from vaultknox.passwords import validate_password_strength_or_raise
from vaultknox.rotation import rotate_master_key
from vaultknox.session import SessionStore
from vaultknox.types import build_metadata, masked_view, validate_secret

# Primary value field per secret type used by inject_to_env
_ENV_FIELD_BY_TYPE: dict[str, str] = {
    "api_key": "key",
    "credential": "password",
    "note": "content",
    "card": "number",
    "password": "value",
    "connection_string": "value",
}


def _safe_env_pop(var_name: str) -> None:
    """Safely remove an injected env var at exit; ignore if already absent."""
    try:
        os.environ.pop(var_name, None)
    except Exception:
        pass


def _parse_utc_datetime(value: str) -> datetime:
    """Parse an ISO 8601 string and ensure it is timezone-aware in UTC if naive."""
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


@dataclass(slots=True)
class VaultStatus:
    initialized: bool
    unlocked: bool
    secret_count: int
    auto_lock_minutes: int


class VaultKnox:
    def __init__(self, paths: VaultPaths) -> None:
        self.paths = paths
        self.db = VaultDatabase(paths.db_path)
        self.sessions = SessionStore(paths.session_path, paths.session_lock_path, paths.session_path.with_name("session.key"))

    def initialize(
        self,
        password: str,
        auto_lock_minutes: int = DEFAULT_AUTO_LOCK_MINUTES,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        lockout_minutes: int = DEFAULT_LOCKOUT_MINUTES,
        skip_password_check: bool = False,
        kdf_params: dict[str, Any] | None = None,
    ) -> None:
        if self.paths.db_path.exists():
            raise VaultError("Vault already initialized")
        validate_password_strength_or_raise(password, skip_password_check)
        if kdf_params is not None:
            validate_kdf_params(kdf_params)
        self.db.initialize()
        salt = generate_salt()
        master_key = derive_master_key(password, salt, kdf_params)
        verification = encrypt_payload(derive_scoped_key(master_key, b"vaultknox-verifier"), {"ok": True})
        self.db.set_config("vault_version", "1")
        self.db.set_config("argon2_salt", salt.hex())
        self.db.set_config("kdf_params", json.dumps(kdf_params or DEFAULT_KDF_PARAMS, separators=(",", ":")))
        self.db.set_config("verifier", json.dumps({"nonce": verification.nonce.hex(), "ciphertext": verification.ciphertext.hex(), "tag": verification.tag.hex()}, separators=(",", ":")))
        self.db.set_config("auto_lock_minutes", str(auto_lock_minutes))
        self.db.set_config("max_attempts", str(max_attempts))
        self.db.set_config("lockout_minutes", str(lockout_minutes))
        self.db.set_config("failed_attempts", "0")
        self.db.set_config("locked_until", "")
        write_audit_event(self.paths.audit_log_path, "init", "success")

    def status(self) -> VaultStatus:
        initialized = self.paths.db_path.exists()
        count = self.db.count_secrets() if initialized else 0
        try:
            auto_lock = int(self.db.get_config("auto_lock_minutes") or DEFAULT_AUTO_LOCK_MINUTES)
        except Exception:
            auto_lock = DEFAULT_AUTO_LOCK_MINUTES
        return VaultStatus(initialized=initialized, unlocked=self.sessions.is_unlocked(), secret_count=count, auto_lock_minutes=auto_lock)

    def unlock(self, password: str) -> dict[str, Any]:
        self._verify_password(password)
        auto_lock_minutes = int(self.db.get_config("auto_lock_minutes") or DEFAULT_AUTO_LOCK_MINUTES)
        # Derive entry key and store in session
        salt = bytes.fromhex(self.db.get_config("argon2_salt") or "")
        kdf_params_str = self.db.get_config("kdf_params")
        kdf_params = json.loads(kdf_params_str) if kdf_params_str else DEFAULT_KDF_PARAMS
        master_key = derive_master_key(password, salt, kdf_params)
        entry_key = derive_scoped_key(master_key)
        state = self.sessions.write(auto_lock_minutes, entry_key=entry_key)
        write_audit_event(self.paths.audit_log_path, "unlock", "success")
        return {"unlocked_at": state.unlocked_at, "expires_at": state.expires_at}

    def lock(self) -> None:
        self.sessions.clear()
        write_audit_event(self.paths.audit_log_path, "lock", "success")

    def list_secrets(self) -> list[dict[str, Any]]:
        self._require_unlocked()
        rows = self.db.list_secrets()
        meta_key = derive_metadata_key(self._session_entry_key())
        secrets: list[dict[str, Any]] = []
        for row in rows:
            secret = dict(row)
            secret["metadata"] = self._decode_metadata(meta_key, secret.get("metadata"))
            secrets.append(secret)
        return secrets

    def add_secret(self, password: str | None, secret_id: str, secret_type: str, label: str, payload: dict[str, Any], expires_at: str | None = None) -> dict[str, Any]:
        key = self._session_entry_key() if password is None else self._entry_key(password)
        validate_secret(secret_type, payload)
        metadata = build_metadata(secret_type, payload)
        
        # Encrypt metadata
        meta_key = derive_metadata_key(key)
        metadata_encrypted = encrypt_metadata(meta_key, metadata)
        
        encrypted = encrypt_payload(key, payload)
        
        # Generate search tokens for encrypted search index
        search_key = derive_search_key(key)
        search_tokens = []
        for field_name, field_value in payload.items():
            if isinstance(field_value, str) and field_value:
                token = encrypt_search_token(search_key, f"{field_name}:{field_value}")
                search_tokens.append(token)
        search_tokens_str = ",".join(search_tokens) if search_tokens else None
        
        self.db.insert_secret(secret_id, secret_type, label, encrypted.ciphertext, encrypted.nonce, encrypted.tag, metadata_encrypted, expires_at, search_tokens_str)
        write_audit_event(self.paths.audit_log_path, "add", "success", secret_id=secret_id)
        return masked_view(secret_id, secret_type, label, metadata)

    def update_secret(self, password: str | None, secret_id: str, secret_type: str, label: str, payload: dict[str, Any], expires_at: str | None = None) -> dict[str, Any]:
        key = self._session_entry_key() if password is None else self._entry_key(password)
        validate_secret(secret_type, payload)
        metadata = build_metadata(secret_type, payload)
        
        # Encrypt metadata
        meta_key = derive_metadata_key(key)
        metadata_encrypted = encrypt_metadata(meta_key, metadata)
        
        encrypted = encrypt_payload(key, payload)
        
        # Generate search tokens for encrypted search index
        search_key = derive_search_key(key)
        search_tokens = []
        for field_name, field_value in payload.items():
            if isinstance(field_value, str) and field_value:
                token = encrypt_search_token(search_key, f"{field_name}:{field_value}")
                search_tokens.append(token)
        search_tokens_str = ",".join(search_tokens) if search_tokens else None
        
        self.db.update_secret(secret_id, secret_type, label, encrypted.ciphertext, encrypted.nonce, encrypted.tag, metadata_encrypted, expires_at, search_tokens_str)
        write_audit_event(self.paths.audit_log_path, "update", "success", secret_id=secret_id)
        return masked_view(secret_id, secret_type, label, metadata)

    def get_secret(self, password: str | None, secret_id: str) -> dict[str, Any]:
        key = self._session_entry_key() if password is None else self._entry_key(password)
        row = self.db.get_secret_row(secret_id)
        expires_at = row["expires_at"] if "expires_at" in row.keys() else None
        if expires_at and _parse_utc_datetime(expires_at) <= datetime.now(timezone.utc):
            write_audit_event(self.paths.audit_log_path, "get_raw", "expired", secret_id=secret_id)
            return {"expired": True, "expires_at": expires_at, "id": secret_id}
        encrypted = EncryptedPayload(nonce=row["nonce"], ciphertext=row["data"], tag=row["tag"])
        try:
            secret = decrypt_payload(key, encrypted)
        except (InvalidTag, ValueError, KeyError) as exc:
            write_audit_event(self.paths.audit_log_path, "get_raw", "failure", secret_id=secret_id)
            raise VaultError("Secret decryption failed; data may be corrupted") from exc
        
        # Decrypt metadata
        meta_key = derive_metadata_key(key)
        metadata_encrypted = row["metadata"]
        if metadata_encrypted:
            try:
                metadata = decrypt_metadata(meta_key, metadata_encrypted)
            except Exception:
                metadata = {}
        else:
            metadata = {}
        
        write_audit_event(self.paths.audit_log_path, "get_raw", "success", secret_id=secret_id)
        if row["type"] == "oauth":
            secret = self._maybe_refresh_oauth_secret(key, row, secret)
        return {
            "id": row["id"],
            "type": row["type"],
            "label": row["label"],
            "payload": secret,
            "metadata": metadata,
        }

    def _maybe_refresh_oauth_secret(self, key: bytes, row: Any, payload: dict[str, Any]) -> dict[str, Any]:
        """Refresh OAuth tokens on read when near expiry and credentials are present."""
        try:
            oauth_secret = StoredOAuth.from_payload(str(row["id"]), str(row["label"]), payload)
        except Exception:
            return payload

        if not oauth_secret.needs_refresh:
            return payload

        provider = DEFAULT_PROVIDERS.get(oauth_secret.provider_id)
        client_id = payload.get("client_id")
        client_secret = payload.get("client_secret")
        refresh_token_value = oauth_secret.refresh_token

        if not provider or not isinstance(client_id, str) or not isinstance(client_secret, str) or not refresh_token_value:
            return payload

        try:
            refreshed = refresh_access_token(
                refresh_token=refresh_token_value,
                client_id=client_id,
                client_secret=client_secret,
                token_url=provider.token_url,
            )
            new_payload = dict(payload)
            new_payload["access_token"] = refreshed.access_token
            new_payload["token_type"] = refreshed.token_type
            new_payload["refresh_token"] = refreshed.refresh_token or refresh_token_value
            if refreshed.expires_in:
                new_payload["expires_at"] = (datetime.now(timezone.utc) + timedelta(seconds=refreshed.expires_in)).isoformat()
            encrypted = encrypt_payload(key, new_payload)
            metadata = build_metadata("oauth", new_payload)
            metadata_encrypted = encrypt_metadata(derive_metadata_key(key), metadata)
            self.db.update_secret_crypto(str(row["id"]), encrypted.ciphertext, encrypted.nonce, encrypted.tag, metadata_encrypted)
            write_audit_event(self.paths.audit_log_path, "oauth_refresh", "success", secret_id=str(row["id"]))
            return new_payload
        except OAuthTokenError:
            failed_payload = dict(payload)
            failed_payload["refresh_failed"] = True
            write_audit_event(self.paths.audit_log_path, "oauth_refresh", "failure", secret_id=str(row["id"]))
            return failed_payload

    def get_masked(self, password: str | None, secret_id: str, purpose: str | None = None, token_ttl_seconds: int = DEFAULT_TOKEN_TTL_SECONDS) -> dict[str, Any]:
        key = self._session_entry_key() if password is None else self._entry_key(password)
        self._require_unlocked()
        row = self.db.get_secret_row(secret_id)
        expires_at = row["expires_at"] if "expires_at" in row.keys() else None
        if expires_at and _parse_utc_datetime(expires_at) <= datetime.now(timezone.utc):
            write_audit_event(self.paths.audit_log_path, "get_masked", "expired", secret_id=secret_id)
            return {"expired": True, "expires_at": expires_at, "id": secret_id}
        
        meta_key = derive_metadata_key(key)
        metadata = self._decode_metadata(meta_key, row["metadata"])
        
        token = None
        if purpose:
            token = self.issue_token(secret_id, purpose, token_ttl_seconds)
        write_audit_event(self.paths.audit_log_path, "get_masked", "success", secret_id=secret_id, details={"token": bool(token)})
        return masked_view(row["id"], row["type"], row["label"], metadata, token=token)

    def delete_secret(self, password: str | None, secret_id: str) -> None:
        if password is None:
            self._session_entry_key()  # Verify session is valid
        else:
            self._verify_password(password)
        self.db.delete_secret(secret_id)
        write_audit_event(self.paths.audit_log_path, "delete", "success", secret_id=secret_id)

    def issue_token(self, secret_id: str, purpose: str, token_ttl_seconds: int = DEFAULT_TOKEN_TTL_SECONDS) -> str:
        self._require_unlocked()
        self.db.get_secret_row(secret_id)
        token = generate_token()
        expires_at = (datetime.now(timezone.utc) + timedelta(seconds=token_ttl_seconds)).isoformat()
        self.db.store_token(token, secret_id, purpose, expires_at)
        write_audit_event(self.paths.audit_log_path, "issue_token", "success", secret_id=secret_id, details={"purpose": purpose})
        return token

    def export_vault(self, password: str, export_file: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        self._verify_password(password)
        backup_salt = generate_salt()
        backup_key = derive_scoped_key(derive_master_key(password, backup_salt), b"vaultknox-backup")
        signing_key = derive_scoped_key(derive_master_key(password, backup_salt), b"vaultknox-backup-signature")
        nonce = generate_salt(NONCE_SIZE)
        encrypted = AESGCM(backup_key).encrypt(nonce, self.paths.db_path.read_bytes(), None)
        backup_payload = {
            "version": 2,
            "salt": backup_salt.hex(),
            "nonce": nonce.hex(),
            "ciphertext": encrypted.hex(),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "metadata": metadata or {},
        }
        backup = dict(backup_payload)
        backup["signature"] = self._backup_signature(signing_key, backup_payload)
        export_path = self.paths.base_dir / export_file if not Path(export_file).is_absolute() else Path(export_file)
        create_private_dir(export_path.parent)
        write_private_file(export_path, json.dumps(backup, separators=(",", ":")))
        write_audit_event(self.paths.audit_log_path, "export", "success", details={"file": str(export_path)})
        return {"exported_to": str(export_path)}

    def import_vault(self, password: str, import_file: str, force: bool = False) -> dict[str, Any]:
        import_path = self.paths.base_dir / import_file if not Path(import_file).is_absolute() else Path(import_file)
        if self.paths.db_path.exists() and not force:
            raise VaultError("Vault already exists. Use force mode to replace it")
        try:
            backup = json.loads(import_path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            raise VaultError("Backup file is not valid JSON") from exc

        required_fields = {"version", "salt", "nonce", "ciphertext", "created_at", "metadata", "signature"}
        if not required_fields.issubset(set(backup)):
            raise VaultError("Backup file is missing required integrity fields")

        if int(backup["version"]) < 2:
            raise VaultError("Unsupported backup format version")

        try:
            backup_salt = bytes.fromhex(backup["salt"])
            nonce = bytes.fromhex(backup["nonce"])
            ciphertext = bytes.fromhex(backup["ciphertext"])
        except ValueError as exc:
            raise VaultError("Backup file contains invalid hex-encoded values") from exc

        base_key = derive_master_key(password, backup_salt)
        backup_key = derive_scoped_key(base_key, b"vaultknox-backup")
        signing_key = derive_scoped_key(base_key, b"vaultknox-backup-signature")

        backup_payload = {
            "version": backup["version"],
            "salt": backup["salt"],
            "nonce": backup["nonce"],
            "ciphertext": backup["ciphertext"],
            "created_at": backup["created_at"],
            "metadata": backup["metadata"],
        }
        expected_signature = self._backup_signature(signing_key, backup_payload)
        if not hmac.compare_digest(expected_signature, backup["signature"]):
            raise VaultError("Backup integrity check failed")

        try:
            decrypted_db = AESGCM(backup_key).decrypt(nonce, ciphertext, None)
        except Exception as exc:  # noqa: BLE001
            raise VaultError("Backup decryption failed") from exc

        if not decrypted_db.startswith(b"SQLite format 3\x00"):
            raise VaultError("Backup payload is not a valid SQLite database")

        self.paths.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.paths.db_path.write_bytes(decrypted_db)
        set_private_file_permissions(self.paths.db_path)
        self.sessions.clear()
        self._verify_password(password)
        write_audit_event(self.paths.audit_log_path, "import", "success", details={"file": str(import_path)})
        return {"imported_from": str(import_path)}

    def change_password(self, current_password: str, new_password: str, skip_password_check: bool = False) -> None:
        validate_password_strength_or_raise(new_password, skip_password_check)
        result = rotate_master_key(self.db, self.paths.base_dir, current_password, new_password)
        write_audit_event(self.paths.audit_log_path, "change_password", "success", details={"secrets_rotated": result["secrets_rotated"]})

    def consume_token(self, password: str | None, token: str) -> dict[str, Any]:
        if self.db.is_token_revoked(token):
            raise VaultError("Token has been revoked")
        try:
            row = self.db.get_token_row(token)
        except KeyError:
            raise VaultError("Token not found or already used") from None
        if row["used_at"] is not None:
            raise VaultError("Token already used")
        if _parse_utc_datetime(row["expires_at"]) <= datetime.now(timezone.utc):
            raise VaultError("Token expired")
        secret = self.get_secret(password, row["secret_id"])
        self.db.mark_token_used(token)
        self.db.delete_token(token)
        write_audit_event(self.paths.audit_log_path, "consume_token", "success", secret_id=row["secret_id"])
        return secret

    def inject_to_env(self, password: str | None, secret_id: str, env_var: str) -> dict[str, Any]:
        secret = self.get_secret(password, secret_id)
        field = _ENV_FIELD_BY_TYPE.get(secret["type"])
        if field is None or field not in secret["payload"]:
            raise VaultError(f"Cannot determine primary value field for secret type '{secret['type']}'")
        os.environ[env_var] = secret["payload"][field]
        atexit.register(_safe_env_pop, env_var)
        write_audit_event(self.paths.audit_log_path, "inject_env", "success", secret_id=secret_id, details={"env_var": env_var})
        return {"injected": env_var, "secret_id": secret_id}

    def revoke_token(self, password: str | None, token: str, reason: str | None = None) -> dict[str, Any]:
        if password is None:
            self._session_entry_key()  # Verify session is valid
        else:
            self._verify_password(password)
        self.db.revoke_token(token, reason)
        write_audit_event(self.paths.audit_log_path, "revoke_token", "success", details={"token_prefix": token[:8]})
        return {"revoked": True}

    def cleanup_expired_tokens(self) -> dict[str, Any]:
        """Remove expired tokens from the database. Returns count of deleted tokens."""
        count = self.db.cleanup_expired_tokens()
        write_audit_event(self.paths.audit_log_path, "cleanup_expired_tokens", "success", details={"deleted_count": count})
        return {"deleted_count": count}

    def bulk_import_secrets(self, password: str | None, entries: list[dict[str, Any]]) -> dict[str, Any]:
        """Import multiple secrets in a single operation. All entries are validated before any are written."""
        key = self._session_entry_key() if password is None else self._entry_key(password)
        search_key = derive_search_key(key)
        prepared: list[tuple[str, str, str, str, EncryptedPayload, str | None, str | None]] = []
        for i, entry in enumerate(entries):
            try:
                secret_id = entry["id"]
                secret_type = entry["type"]
                label = entry["label"]
                payload = entry["data"]
                expires_at = entry.get("expires_at")
            except KeyError as exc:
                raise VaultError(f"Entry {i}: missing required field {exc}") from exc
            try:
                validate_secret(secret_type, payload)
            except Exception as exc:  # noqa: BLE001
                raise VaultError(f"Entry {i} ('{secret_id}'): {exc}") from exc
            metadata = build_metadata(secret_type, payload)
            metadata_encrypted = encrypt_metadata(derive_metadata_key(key), metadata)
            encrypted = encrypt_payload(key, payload)
            
            # Generate search tokens
            search_tokens = []
            for field_name, field_value in payload.items():
                if isinstance(field_value, str) and field_value:
                    token = encrypt_search_token(search_key, f"{field_name}:{field_value}")
                    search_tokens.append(token)
            search_tokens_str = ",".join(search_tokens) if search_tokens else None
            
            prepared.append((secret_id, secret_type, label, metadata_encrypted, encrypted, expires_at, search_tokens_str))

        imported: list[str] = []
        try:
            with self.db.connection() as conn:
                for secret_id, secret_type, label, metadata, encrypted, expires_at, search_tokens_str in prepared:
                    now = datetime.now(timezone.utc).isoformat()
                    conn.execute(
                        "INSERT INTO secrets(id, type, label, data, nonce, tag, created_at, updated_at, metadata, expires_at, search_tokens) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            secret_id,
                            secret_type,
                            label,
                            encrypted.ciphertext,
                            encrypted.nonce,
                            encrypted.tag,
                            now,
                            now,
                            metadata,
                            expires_at,
                            search_tokens_str,
                        ),
                    )
                    imported.append(secret_id)
        except Exception as exc:  # noqa: BLE001
            write_audit_event(
                self.paths.audit_log_path,
                "bulk_import",
                "failure",
                details={"error": str(exc), "requested": len(prepared)},
            )
            raise VaultError(f"Bulk import failed and was rolled back: {exc}") from exc

        write_audit_event(self.paths.audit_log_path, "bulk_import", "success", details={"imported": len(imported), "skipped": 0})
        return {"imported": imported, "skipped": []}

    def _entry_key(self, password: str) -> bytes:
        self._verify_password(password)
        salt = bytes.fromhex(self.db.get_config("argon2_salt") or "")
        kdf_params_str = self.db.get_config("kdf_params")
        kdf_params = json.loads(kdf_params_str) if kdf_params_str else DEFAULT_KDF_PARAMS
        master_key = derive_master_key(password, salt, kdf_params)
        return derive_scoped_key(master_key)

    def _session_entry_key(self) -> bytes:
        """Get the entry key from the session store."""
        key = self.sessions.get_session_key()
        if key is None:
            raise VaultError("Vault is locked; run unlock first")
        return key

    def _decode_metadata(self, meta_key: bytes, metadata: Any) -> dict[str, Any]:
        if not metadata:
            return {}
        if isinstance(metadata, dict):
            return metadata
        if not isinstance(metadata, str):
            return {}
        try:
            return decrypt_metadata(meta_key, metadata)
        except Exception:
            pass
        try:
            decoded = json.loads(metadata)
        except Exception:
            return {}
        return decoded if isinstance(decoded, dict) else {}

    def _require_unlocked(self) -> None:
        if not self.sessions.is_unlocked():
            raise VaultError("Vault is locked; run unlock first")

    def _verify_password(self, password: str) -> None:
        if not self.paths.db_path.exists():
            raise VaultError("Vault is not initialized")
        self._check_lockout()
        salt = bytes.fromhex(self.db.get_config("argon2_salt") or "")
        kdf_params_str = self.db.get_config("kdf_params")
        kdf_params = json.loads(kdf_params_str) if kdf_params_str else DEFAULT_KDF_PARAMS
        verifier_key = derive_scoped_key(derive_master_key(password, salt, kdf_params), b"vaultknox-verifier")
        verifier_data = json.loads(self.db.get_config("verifier") or "{}")
        try:
            decrypt_payload(
                verifier_key,
                EncryptedPayload(
                    nonce=bytes.fromhex(verifier_data["nonce"]),
                    ciphertext=bytes.fromhex(verifier_data["ciphertext"]),
                    tag=bytes.fromhex(verifier_data["tag"]),
                ),
            )
        except Exception as exc:  # noqa: BLE001
            self._register_failed_attempt()
            write_audit_event(self.paths.audit_log_path, "verify_password", "failure")
            raise VaultError("Invalid master password") from exc
        self.db.set_config("failed_attempts", "0")
        self.db.set_config("locked_until", "")

    def _check_lockout(self) -> None:
        locked_until = self.db.get_config("locked_until")
        if locked_until and _parse_utc_datetime(locked_until) > datetime.now(timezone.utc):
            raise VaultError("Vault is temporarily locked after repeated failed attempts")

    def _register_failed_attempt(self) -> None:
        failed_attempts = int(self.db.get_config("failed_attempts") or "0") + 1
        max_attempts = int(self.db.get_config("max_attempts") or DEFAULT_MAX_ATTEMPTS)
        lockout_minutes = int(self.db.get_config("lockout_minutes") or DEFAULT_LOCKOUT_MINUTES)
        self.db.set_config("failed_attempts", str(failed_attempts))
        if failed_attempts >= max_attempts:
            locked_until = datetime.now(timezone.utc) + timedelta(minutes=lockout_minutes)
            self.db.set_config("locked_until", locked_until.isoformat())

    def _backup_signature(self, signing_key: bytes, backup_payload: dict[str, Any]) -> str:
        canonical = json.dumps(backup_payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        return hmac.new(signing_key, canonical, hashlib.sha256).hexdigest()
