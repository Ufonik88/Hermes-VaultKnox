from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path


@dataclass(frozen=True, slots=True)
class SessionState:
    unlocked_at: str
    expires_at: str


class SessionStore:
    def __init__(self, session_path: Path) -> None:
        self.session_path = session_path

    def write(self, auto_lock_minutes: int) -> SessionState:
        unlocked_at = datetime.now(timezone.utc)
        expires_at = unlocked_at + timedelta(minutes=auto_lock_minutes)
        state = SessionState(unlocked_at=unlocked_at.isoformat(), expires_at=expires_at.isoformat())
        self.session_path.parent.mkdir(parents=True, exist_ok=True)
        self.session_path.write_text(json.dumps(state.__dict__, separators=(",", ":")), encoding="utf-8")
        return state

    def read(self) -> SessionState | None:
        if not self.session_path.exists():
            return None
        data = json.loads(self.session_path.read_text(encoding="utf-8"))
        return SessionState(**data)

    def clear(self) -> None:
        if self.session_path.exists():
            self.session_path.unlink()

    def is_unlocked(self) -> bool:
        state = self.read()
        if state is None:
            return False
        return datetime.fromisoformat(state.expires_at) > datetime.now(timezone.utc)