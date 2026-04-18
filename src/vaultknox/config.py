from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_AUTO_LOCK_MINUTES = 15
DEFAULT_TOKEN_TTL_SECONDS = 300
DEFAULT_LOCKOUT_MINUTES = 30
DEFAULT_MAX_ATTEMPTS = 5
PRIVATE_FILE_MODE = 0o600


@dataclass(slots=True)
class VaultPaths:
    base_dir: Path

    @property
    def db_path(self) -> Path:
        return self.base_dir / "secrets.db"

    @property
    def audit_log_path(self) -> Path:
        return self.base_dir / "audit.log"

    @property
    def session_path(self) -> Path:
        return self.base_dir / "session.json"

    @property
    def session_lock_path(self) -> Path:
        return self.base_dir / "session.lock"


def expand_runtime_path(path: str | Path | None = None) -> VaultPaths:
    if path is None:
        path = Path.home() / ".hermes" / "vaultknox"
    return VaultPaths(Path(path).expanduser().resolve())


def set_private_file_permissions(path: Path) -> None:
    if path.exists():
        os.chmod(path, PRIVATE_FILE_MODE)
