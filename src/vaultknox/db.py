from __future__ import annotations

import json
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
    metadata TEXT NOT NULL
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
"""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class VaultDatabase:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path

    def initialize(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA foreign_keys = ON")
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

    def insert_secret(self, secret_id: str, secret_type: str, label: str, ciphertext: bytes, nonce: bytes, tag: bytes, metadata: dict[str, Any]) -> None:
        now = utc_now()
        with self.connection() as conn:
            conn.execute(
                "INSERT INTO secrets(id, type, label, data, nonce, tag, created_at, updated_at, metadata) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (secret_id, secret_type, label, ciphertext, nonce, tag, now, now, json.dumps(metadata, separators=(",", ":"))),
            )

    def update_secret(self, secret_id: str, secret_type: str, label: str, ciphertext: bytes, nonce: bytes, tag: bytes, metadata: dict[str, Any]) -> None:
        with self.connection() as conn:
            conn.execute(
                "UPDATE secrets SET type = ?, label = ?, data = ?, nonce = ?, tag = ?, updated_at = ?, metadata = ? WHERE id = ?",
                (secret_type, label, ciphertext, nonce, tag, utc_now(), json.dumps(metadata, separators=(",", ":")), secret_id),
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
            rows = conn.execute("SELECT id, type, label, metadata, created_at, updated_at FROM secrets ORDER BY updated_at DESC").fetchall()
        return [dict(row) | {"metadata": json.loads(row["metadata"])} for row in rows]

    def delete_secret(self, secret_id: str) -> None:
        with self.connection() as conn:
            conn.execute("DELETE FROM secrets WHERE id = ?", (secret_id,))
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