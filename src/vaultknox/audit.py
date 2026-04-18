from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def write_audit_event(audit_log_path: Path, action: str, status: str, secret_id: str | None = None, details: dict[str, Any] | None = None) -> None:
    audit_log_path.parent.mkdir(parents=True, exist_ok=True)
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