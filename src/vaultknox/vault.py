from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from vaultknox.audit import write_audit_event
from vaultknox.config import DEFAULT_AUTO_LOCK_MINUTES, DEFAULT_LOCKOUT_MINUTES, DEFAULT_MAX_ATTEMPTS, DEFAULT_TOKEN_TTL_SECONDS, VaultPaths
from vaultknox.core import EncryptedPayload, decrypt_payload, derive_master_key, derive_scoped_key, encrypt_payload, generate_salt, generate_token
from vaultknox.db import VaultDatabase
from vaultknox.session import SessionStore
from vaultknox.types import build_metadata, masked_view, validate_secret


class VaultError(RuntimeError):
    pass


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
        self.sessions = SessionStore(paths.session_path)

    def initialize(self, password: str, auto_lock_minutes: int = DEFAULT_AUTO_LOCK_MINUTES, max_attempts: int = DEFAULT_MAX_ATTEMPTS, lockout_minutes: int = DEFAULT_LOCKOUT_MINUTES) -> None:
        if self.paths.db_path.exists():
            raise VaultError("Vault already initialized")
        self.db.initialize()
        salt = generate_salt()
        master_key = derive_master_key(password, salt)
        verification = encrypt_payload(derive_scoped_key(master_key, b"vaultknox-verifier"), {"ok": True})
        self.db.set_config("vault_version", "1")
        self.db.set_config("argon2_salt", salt.hex())
        self.db.set_config("kdf_params", json.dumps({"time_cost": 3, "memory_cost": 65536, "parallelism": 4, "hash_len": 32, "type": "argon2id"}, separators=(",", ":")))
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
        auto_lock = int(self.db.get_config("auto_lock_minutes") or DEFAULT_AUTO_LOCK_MINUTES)
        return VaultStatus(initialized=initialized, unlocked=self.sessions.is_unlocked(), secret_count=count, auto_lock_minutes=auto_lock)

    def unlock(self, password: str) -> dict[str, Any]:
        self._verify_password(password)
        auto_lock_minutes = int(self.db.get_config("auto_lock_minutes") or DEFAULT_AUTO_LOCK_MINUTES)
        state = self.sessions.write(auto_lock_minutes)
        write_audit_event(self.paths.audit_log_path, "unlock", "success")
        return {"unlocked_at": state.unlocked_at, "expires_at": state.expires_at}

    def lock(self) -> None:
        self.sessions.clear()
        write_audit_event(self.paths.audit_log_path, "lock", "success")

    def list_secrets(self) -> list[dict[str, Any]]:
        return self.db.list_secrets()

    def add_secret(self, password: str, secret_id: str, secret_type: str, label: str, payload: dict[str, Any]) -> dict[str, Any]:
        key = self._entry_key(password)
        validate_secret(secret_type, payload)
        metadata = build_metadata(secret_type, payload)
        encrypted = encrypt_payload(key, payload)
        self.db.insert_secret(secret_id, secret_type, label, encrypted.ciphertext, encrypted.nonce, encrypted.tag, metadata)
        write_audit_event(self.paths.audit_log_path, "add", "success", secret_id=secret_id)
        return masked_view(secret_id, secret_type, label, metadata)

    def update_secret(self, password: str, secret_id: str, secret_type: str, label: str, payload: dict[str, Any]) -> dict[str, Any]:
        key = self._entry_key(password)
        validate_secret(secret_type, payload)
        metadata = build_metadata(secret_type, payload)
        encrypted = encrypt_payload(key, payload)
        self.db.update_secret(secret_id, secret_type, label, encrypted.ciphertext, encrypted.nonce, encrypted.tag, metadata)
        write_audit_event(self.paths.audit_log_path, "update", "success", secret_id=secret_id)
        return masked_view(secret_id, secret_type, label, metadata)

    def get_secret(self, password: str, secret_id: str) -> dict[str, Any]:
        key = self._entry_key(password)
        row = self.db.get_secret_row(secret_id)
        encrypted = EncryptedPayload(nonce=row["nonce"], ciphertext=row["data"], tag=row["tag"])
        secret = decrypt_payload(key, encrypted)
        write_audit_event(self.paths.audit_log_path, "get_raw", "success", secret_id=secret_id)
        return {
            "id": row["id"],
            "type": row["type"],
            "label": row["label"],
            "payload": secret,
        }

    def get_masked(self, secret_id: str, purpose: str | None = None, token_ttl_seconds: int = DEFAULT_TOKEN_TTL_SECONDS) -> dict[str, Any]:
        row = self.db.get_secret_row(secret_id)
        metadata = json.loads(row["metadata"])
        token = None
        if purpose:
            token = self.issue_token(secret_id, purpose, token_ttl_seconds)
        write_audit_event(self.paths.audit_log_path, "get_masked", "success", secret_id=secret_id, details={"token": bool(token)})
        return masked_view(row["id"], row["type"], row["label"], metadata, token=token)

    def delete_secret(self, secret_id: str) -> None:
        self.db.delete_secret(secret_id)
        write_audit_event(self.paths.audit_log_path, "delete", "success", secret_id=secret_id)

    def issue_token(self, secret_id: str, purpose: str, token_ttl_seconds: int = DEFAULT_TOKEN_TTL_SECONDS) -> str:
        self.db.get_secret_row(secret_id)
        token = generate_token()
        expires_at = (datetime.now(timezone.utc) + timedelta(seconds=token_ttl_seconds)).isoformat()
        self.db.store_token(token, secret_id, purpose, expires_at)
        write_audit_event(self.paths.audit_log_path, "issue_token", "success", secret_id=secret_id, details={"purpose": purpose})
        return token

    def consume_token(self, password: str, token: str) -> dict[str, Any]:
        row = self.db.get_token_row(token)
        if row["used_at"] is not None:
            raise VaultError("Token already used")
        if datetime.fromisoformat(row["expires_at"]) <= datetime.now(timezone.utc):
            raise VaultError("Token expired")
        secret = self.get_secret(password, row["secret_id"])
        self.db.mark_token_used(token)
        write_audit_event(self.paths.audit_log_path, "consume_token", "success", secret_id=row["secret_id"])
        return secret

    def _entry_key(self, password: str) -> bytes:
        self._verify_password(password)
        salt = bytes.fromhex(self.db.get_config("argon2_salt") or "")
        master_key = derive_master_key(password, salt)
        return derive_scoped_key(master_key)

    def _verify_password(self, password: str) -> None:
        if not self.paths.db_path.exists():
            raise VaultError("Vault is not initialized")
        self._check_lockout()
        salt = bytes.fromhex(self.db.get_config("argon2_salt") or "")
        verifier_key = derive_scoped_key(derive_master_key(password, salt), b"vaultknox-verifier")
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
        if locked_until and datetime.fromisoformat(locked_until) > datetime.now(timezone.utc):
            raise VaultError("Vault is temporarily locked after repeated failed attempts")

    def _register_failed_attempt(self) -> None:
        failed_attempts = int(self.db.get_config("failed_attempts") or "0") + 1
        max_attempts = int(self.db.get_config("max_attempts") or DEFAULT_MAX_ATTEMPTS)
        lockout_minutes = int(self.db.get_config("lockout_minutes") or DEFAULT_LOCKOUT_MINUTES)
        self.db.set_config("failed_attempts", str(failed_attempts))
        if failed_attempts >= max_attempts:
            locked_until = datetime.now(timezone.utc) + timedelta(minutes=lockout_minutes)
            self.db.set_config("locked_until", locked_until.isoformat())