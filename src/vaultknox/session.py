from __future__ import annotations

import fcntl
import json
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

from vaultknox.config import set_private_file_permissions


@dataclass(frozen=True, slots=True)
class SessionState:
    unlocked_at: str
    expires_at: str
    refreshed_at: str


class SessionStore:
    def __init__(self, session_path: Path, lock_path: Path) -> None:
        self.session_path = session_path
        self.lock_path = lock_path

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

    def write(self, auto_lock_minutes: int) -> SessionState:
        with self.lock():
            now = datetime.now(timezone.utc)
            expires_at = now + timedelta(minutes=auto_lock_minutes)
            state = SessionState(
                unlocked_at=now.isoformat(),
                expires_at=expires_at.isoformat(),
                refreshed_at=now.isoformat(),
            )
            self.session_path.parent.mkdir(parents=True, exist_ok=True)
            self.session_path.write_text(json.dumps(asdict(state), separators=(",", ":")), encoding="utf-8")
            set_private_file_permissions(self.session_path)
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
            if datetime.fromisoformat(state.expires_at) <= datetime.now(timezone.utc):
                self._clear_unlocked()
                return False
            return True

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