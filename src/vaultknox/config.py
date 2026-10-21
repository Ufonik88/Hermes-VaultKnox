from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from vaultknox.core import DEFAULT_KDF_PARAMS as _DEFAULT_KDF_PARAMS

DEFAULT_AUTO_LOCK_MINUTES = 15
DEFAULT_TOKEN_TTL_SECONDS = 300
DEFAULT_LOCKOUT_MINUTES = 30
DEFAULT_MAX_ATTEMPTS = 5
PRIVATE_FILE_MODE = 0o600
PRIVATE_DIR_MODE = 0o700
DEFAULT_KDF_PARAMS = _DEFAULT_KDF_PARAMS

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


def expand_runtime_path(path: str | Path | None = None, profile: str | None = None) -> VaultPaths:
    if path is None:
        base = Path.home() / ".hermes"
        if profile:
            path = base / "vaultknox-profiles" / profile
        else:
            path = base / "vaultknox"
    return VaultPaths(Path(path).expanduser().resolve())


def set_private_file_permissions(path: Path) -> None:
    if path.exists():
        os.chmod(path, PRIVATE_FILE_MODE)


def create_private_dir(path: Path) -> None:
    """Create a directory with restrictive permissions (0o700)."""
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, PRIVATE_DIR_MODE)


def write_private_file(path: Path, data: str | bytes, encoding: str = "utf-8") -> None:
    """Write a file atomically with restrictive permissions (0o600)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    # Write to a temporary file first, then atomically rename
    import tempfile
    if isinstance(data, str):
        data_bytes = data.encode(encoding)
    else:
        data_bytes = data
    with tempfile.NamedTemporaryFile(
        mode="wb",
        dir=path.parent,
        delete=False,
        prefix=f".{path.name}.",
        suffix=".tmp",
    ) as tmp:
        tmp.write(data_bytes)
        tmp_path = Path(tmp.name)
    try:
        os.chmod(tmp_path, PRIVATE_FILE_MODE)
        os.replace(tmp_path, path)
    except Exception:
        try:
            tmp_path.unlink()
        except Exception:
            pass
        raise
