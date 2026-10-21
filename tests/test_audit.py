import os
from pathlib import Path

from vaultknox import audit


def test_audit_file_permissions_are_restricted(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.log"

    audit.write_audit_event(audit_path, "status", "success")

    mode = os.stat(audit_path).st_mode & 0o777
    assert mode == 0o600


def test_audit_rotation_creates_backups(tmp_path: Path, monkeypatch) -> None:
    audit_path = tmp_path / "audit.log"
    monkeypatch.setattr(audit, "AUDIT_MAX_BYTES", 120)
    monkeypatch.setattr(audit, "AUDIT_MAX_BACKUPS", 2)

    for index in range(20):
        audit.write_audit_event(audit_path, "event", "success", details={"index": index, "payload": "x" * 40})

    assert audit_path.exists()
    assert (tmp_path / "audit.log.1").exists()
