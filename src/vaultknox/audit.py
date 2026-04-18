from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


AUDIT_MAX_BYTES = 1_048_576
AUDIT_MAX_BACKUPS = 5


def write_audit_event(audit_log_path: Path, action: str, status: str, secret_id: str | None = None, details: dict[str, Any] | None = None) -> None:
    audit_log_path.parent.mkdir(parents=True, exist_ok=True)
    _rotate_audit_log_if_needed(audit_log_path)
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "status": status,
    }
    if secret_id:
        event["secret_id"] = secret_id
    if details:
        event["details"] = details
    with audit_log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, separators=(",", ":")) + "\n")
    os.chmod(audit_log_path, 0o600)


def _rotate_audit_log_if_needed(audit_log_path: Path) -> None:
    if not audit_log_path.exists():
        return
    if audit_log_path.stat().st_size < AUDIT_MAX_BYTES:
        return

    oldest_backup = audit_log_path.with_name(f"{audit_log_path.name}.{AUDIT_MAX_BACKUPS}")
    if oldest_backup.exists():
        oldest_backup.unlink()

    for index in range(AUDIT_MAX_BACKUPS - 1, 0, -1):
        src = audit_log_path.with_name(f"{audit_log_path.name}.{index}")
        dst = audit_log_path.with_name(f"{audit_log_path.name}.{index + 1}")
        if src.exists():
            src.rename(dst)

    audit_log_path.rename(audit_log_path.with_name(f"{audit_log_path.name}.1"))