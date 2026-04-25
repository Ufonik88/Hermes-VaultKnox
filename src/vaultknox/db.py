from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS secrets (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    label TEXT NOT NULL,
    data BLOB NOT NULL,
    nonce BLOB NOT NULL,
    tag BLOB NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    metadata TEXT NOT NULL,
    expires_at TEXT
);

CREATE TABLE IF NOT EXISTS vault_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vault_tokens (
    token TEXT PRIMARY KEY,
    secret_id TEXT NOT NULL,
    purpose TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT,
    FOREIGN KEY(secret_id) REFERENCES secrets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS vault_tokens_revoked (
    token TEXT PRIMARY KEY,
    revoked_at TEXT NOT NULL,
    reason TEXT
);
"""

MIGRATIONS = """
CREATE TABLE IF NOT EXISTS vault_tokens_revoked (
    token TEXT PRIMARY KEY,
    revoked_at TEXT NOT NULL,
    reason TEXT
);
"""

# Applied once per connection via ALTER TABLE (idempotent via exception suppression)
_COLUMN_MIGRATIONS: list[str] = [
    "ALTER TABLE secrets ADD COLUMN expires_at TEXT",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class VaultDatabase:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self._schema_current = False

    def initialize(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as conn:
            conn.executescript(SCHEMA)
            rows = conn.execute("PRAGMA integrity_check").fetchall()
            if len(rows) != 1 or rows[0][0] != "ok":
                raise RuntimeError(f"SQLite integrity check failed after initialization: {[r[0] for r in rows]}")
        os.chmod(self.db_path, 0o600)

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = NORMAL")
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA secure_delete = ON")
            if not self._schema_current:
                conn.executescript(MIGRATIONS)
                for stmt in _COLUMN_MIGRATIONS:
                    try:
                        conn.execute(stmt)
                    except sqlite3.OperationalError:
                        pass  # column already exists
                conn.commit()
                self._schema_current = True
            yield conn
            conn.commit()
        finally:
            conn.close()

    def get_config(self, key: str) -> str | None:
        with self.connection() as conn:
            row = conn.execute("SELECT value FROM vault_config WHERE key = ?", (key,)).fetchone()
            return None if row is None else str(row["value"])

    def set_config(self, key: str, value: str) -> None:
        with self.connection() as conn:
            conn.execute(
                "INSERT INTO vault_config(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

    def insert_secret(self, secret_id: str, secret_type: str, label: str, ciphertext: bytes, nonce: bytes, tag: bytes, metadata: dict[str, Any], expires_at: str | None = None) -> None:
        now = utc_now()
        with self.connection() as conn:
            conn.execute(
                "INSERT INTO secrets(id, type, label, data, nonce, tag, created_at, updated_at, metadata, expires_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (secret_id, secret_type, label, ciphertext, nonce, tag, now, now, json.dumps(metadata, separators=(",", ":")), expires_at),
            )

    def update_secret(self, secret_id: str, secret_type: str, label: str, ciphertext: bytes, nonce: bytes, tag: bytes, metadata: dict[str, Any], expires_at: str | None = None) -> None:
        with self.connection() as conn:
            conn.execute(
                "UPDATE secrets SET type = ?, label = ?, data = ?, nonce = ?, tag = ?, updated_at = ?, metadata = ?, expires_at = ? WHERE id = ?",
                (secret_type, label, ciphertext, nonce, tag, utc_now(), json.dumps(metadata, separators=(",", ":")), expires_at, secret_id),
            )
            if conn.total_changes == 0:
                raise KeyError(f"Secret not found: {secret_id}")

    def get_secret_row(self, secret_id: str) -> sqlite3.Row:
        with self.connection() as conn:
            row = conn.execute("SELECT * FROM secrets WHERE id = ?", (secret_id,)).fetchone()
            if row is None:
                raise KeyError(f"Secret not found: {secret_id}")
            return row

    def list_secrets(self) -> list[dict[str, Any]]:
        with self.connection() as conn:
            rows = conn.execute("SELECT id, type, label, metadata, created_at, updated_at, expires_at FROM secrets ORDER BY updated_at DESC").fetchall()
        return [dict(row) | {"metadata": json.loads(row["metadata"])} for row in rows]

    def delete_secret(self, secret_id: str) -> None:
        with self.connection() as conn:
            conn.execute("DELETE FROM secrets WHERE id = ?", (secret_id,))
            if conn.total_changes == 0:
                raise KeyError(f"Secret not found: {secret_id}")

    def list_secret_rows_raw(self) -> list[sqlite3.Row]:
        with self.connection() as conn:
            return conn.execute("SELECT id, type, label, data, nonce, tag, metadata FROM secrets").fetchall()

    def update_secret_crypto(self, secret_id: str, ciphertext: bytes, nonce: bytes, tag: bytes, metadata: dict[str, Any]) -> None:
        with self.connection() as conn:
            conn.execute(
                "UPDATE secrets SET data = ?, nonce = ?, tag = ?, metadata = ?, updated_at = ? WHERE id = ?",
                (ciphertext, nonce, tag, json.dumps(metadata, separators=(",", ":")), utc_now(), secret_id),
            )
            if conn.total_changes == 0:
                raise KeyError(f"Secret not found: {secret_id}")

    def store_token(self, token: str, secret_id: str, purpose: str, expires_at: str) -> None:
        with self.connection() as conn:
            conn.execute(
                "INSERT INTO vault_tokens(token, secret_id, purpose, created_at, expires_at, used_at) VALUES(?, ?, ?, ?, ?, NULL)",
                (token, secret_id, purpose, utc_now(), expires_at),
            )

    def mark_token_used(self, token: str) -> None:
        with self.connection() as conn:
            conn.execute("UPDATE vault_tokens SET used_at = ? WHERE token = ? AND used_at IS NULL", (utc_now(), token))
            if conn.total_changes == 0:
                raise KeyError(f"Token not available: {token}")

    def get_token_row(self, token: str) -> sqlite3.Row:
        with self.connection() as conn:
            row = conn.execute("SELECT * FROM vault_tokens WHERE token = ?", (token,)).fetchone()
            if row is None:
                raise KeyError(f"Token not found: {token}")
            return row

    def count_secrets(self) -> int:
        with self.connection() as conn:
            row = conn.execute("SELECT COUNT(*) AS count FROM secrets").fetchone()
            return int(row["count"])

    def revoke_token(self, token: str, reason: str | None = None) -> None:
        with self.connection() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO vault_tokens_revoked(token, revoked_at, reason) VALUES(?, ?, ?)",
                (token, utc_now(), reason),
            )

    def is_token_revoked(self, token: str) -> bool:
        with self.connection() as conn:
            row = conn.execute("SELECT token FROM vault_tokens_revoked WHERE token = ?", (token,)).fetchone()
            return row is not None

    def vacuum(self) -> None:
        with self.connection() as conn:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        # VACUUM must run outside a transaction
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("VACUUM")
        finally:
            conn.close()