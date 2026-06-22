from __future__ import annotations

import fcntl
import json
import os
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

from vaultknox.config import create_private_dir, set_private_file_permissions, write_private_file
from vaultknox.core import KEY_SIZE, derive_scoped_key


@dataclass(frozen=True, slots=True)
class SessionState:
    unlocked_at: str
    expires_at: str
    refreshed_at: str
    owner_uid: int | None = None
    pid: int | None = None


class SessionStore:
    def __init__(self, session_path: Path, lock_path: Path, session_key_path: Path | None = None) -> None:
        self.session_path = session_path
        self.lock_path = lock_path
        self.session_key_path = session_key_path or session_path.with_name("session.key")

    @contextmanager
    def lock(self) -> Iterator[None]:
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open("a", encoding="utf-8") as handle:
            set_private_file_permissions(self.lock_path)
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def write(self, auto_lock_minutes: int, entry_key: bytes | None = None, owner_uid: int | None = None, pid: int | None = None) -> SessionState:
        with self.lock():
            now = datetime.now(timezone.utc)
            expires_at = now + timedelta(minutes=auto_lock_minutes)
            state = SessionState(
                unlocked_at=now.isoformat(),
                expires_at=expires_at.isoformat(),
                refreshed_at=now.isoformat(),
                owner_uid=owner_uid or os.getuid(),
                pid=pid,
            )
            create_private_dir(self.session_path.parent)
            write_private_file(self.session_path, json.dumps(asdict(state), separators=(",", ":")))
            # Write session key if provided
            if entry_key is not None:
                write_private_file(self.session_key_path, entry_key)
            return state

    def read(self) -> SessionState | None:
        with self.lock():
            return self._read_unlocked()

    def clear(self) -> None:
        with self.lock():
            self._clear_unlocked()

    def is_unlocked(self) -> bool:
        with self.lock():
            state = self._read_unlocked()
            if state is None:
                return False
            expires_at = datetime.fromisoformat(state.expires_at)
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if expires_at <= datetime.now(timezone.utc):
                self._clear_unlocked()
                return False
            return True

    def get_session_key(self) -> bytes | None:
        """Get the session entry key if session is unlocked and valid."""
        with self.lock():
            state = self._read_unlocked()
            if state is None:
                return None
            expires_at = datetime.fromisoformat(state.expires_at)
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if expires_at <= datetime.now(timezone.utc):
                self._clear_unlocked()
                return None
            # Check UID binding
            if state.owner_uid is not None and state.owner_uid != os.getuid():
                return None
            # Check PID binding if enabled
            if state.pid is not None and state.pid != os.getpid():
                return None
            # Read session key
            if not self.session_key_path.exists():
                return None
            try:
                return self.session_key_path.read_bytes()
            except Exception:
                return None

    def _read_unlocked(self) -> SessionState | None:
        if not self.session_path.exists():
            return None
        try:
            data = json.loads(self.session_path.read_text(encoding="utf-8"))
            return SessionState(**data)
        except Exception:  # noqa: BLE001
            self._clear_unlocked()
            return None

    def _clear_unlocked(self) -> None:
        if self.session_path.exists():
            self.session_path.unlink()
        if self.session_key_path.exists():
            self.session_key_path.unlink()