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
            os.replace(src, dst)

    os.replace(audit_log_path, audit_log_path.with_name(f"{audit_log_path.name}.1"))
    audit_log_path.touch()
    os.chmod(audit_log_path, 0o600)


# ------------------------------------------------------------------
# Audit log query interface
# ------------------------------------------------------------------


def query_audit_log(
    audit_log_path: Path,
    *,
    action: str | None = None,
    status: str | None = None,
    secret_id: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    """
    Read and filter the audit log.

    Args:
        audit_log_path: Path to the audit log file.
        action: Filter by action name (exact match, e.g. "unlock", "add_secret").
        status: Filter by status (exact match, e.g. "success", "failure").
        secret_id: Filter by secret ID (exact match).
        since: Only events at or after this UTC datetime.
        until: Only events at or before this UTC datetime.
        limit: Maximum number of events to return (most recent first).

    Returns:
        List of matching audit event dicts, newest first.
    """
    events: list[dict[str, Any]] = []

    # Collect all log files (main + backups, newest first)
    all_logs: list[Path] = []
    if audit_log_path.exists():
        all_logs.append(audit_log_path)
    # Backups are numbered oldest → newest (e.g. .1 is newest backup, .5 is oldest)
    # We want newest-first overall, so load backups in reverse order
    backups = sorted(
        audit_log_path.parent.glob(f"{audit_log_path.name}.*"),
        key=lambda p: p.name,
    )
    for backup in reversed(backups):
        if backup.name.endswith(str(AUDIT_MAX_BACKUPS)):
            continue  # Skip the .5 (oldest) placeholder
        all_logs.append(backup)

    for log_path in all_logs:
        try:
            for line in log_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue  # Skip malformed lines

                # Apply filters
                if action is not None and event.get("action") != action:
                    continue
                if status is not None and event.get("status") != status:
                    continue
                if secret_id is not None and event.get("secret_id") != secret_id:
                    continue

                ts_str = event.get("timestamp", "")
                if ts_str and (since is not None or until is not None):
                    try:
                        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    except ValueError:
                        continue
                    if since is not None and ts < since:
                        continue
                    if until is not None and ts > until:
                        continue

                events.append(event)
        except (OSError, IOError):
            continue  # Skip unreadable log files

    # Sort newest first
    events.sort(key=lambda e: e.get("timestamp", ""), reverse=True)

    if limit is not None and limit > 0:
        events = events[:limit]

    return events