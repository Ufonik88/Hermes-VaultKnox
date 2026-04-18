import os
from pathlib import Path

from vaultknox.config import PRIVATE_FILE_MODE, expand_runtime_path
from vaultknox.vault import VaultKnox


def test_runtime_files_use_private_permissions(tmp_path: Path) -> None:
    runtime_dir = tmp_path / ".runtime"
    backup_file = tmp_path / "backup.vault"
    vault = VaultKnox(expand_runtime_path(runtime_dir))

    vault.initialize("correct horse battery staple")
    vault.unlock("correct horse battery staple")
    vault.add_secret(
        "correct horse battery staple",
        "demo_card",
        "card",
        "Demo Card",
        {
            "number": "4111111111111111",
            "expiry": "12/28",
            "cvv": "123",
            "holder": "DJ C",
            "bank": "Revolut",
        },
    )
    vault.export_vault("correct horse battery staple", str(backup_file))

    assert os.stat(vault.paths.db_path).st_mode & 0o777 == PRIVATE_FILE_MODE
    assert os.stat(vault.paths.session_path).st_mode & 0o777 == PRIVATE_FILE_MODE
    assert os.stat(vault.paths.session_lock_path).st_mode & 0o777 == PRIVATE_FILE_MODE
    assert os.stat(backup_file).st_mode & 0o777 == PRIVATE_FILE_MODE