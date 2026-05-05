"""
VaultKnox Autonomous Secrets — Encrypted credential store for Hermes Agent.

Provides AES-256-GCM (Fernet) encrypted credential storage backed by a local key
file on disk. Unlike the master-password vault, this store is designed for
*autonomous* operation: scripts, cron jobs, and tools can read credentials
without manual unlock — the key file *is* the unlock mechanism.

Security model (same as SSH private keys):
  1. The ``master.key`` file has owner-only permissions (chmod 600).
  2. The encrypted ``secrets.enc`` file is safe for backups, git, and session logs.
  3. If an attacker gains root-level filesystem access, they can read the key file
     and decrypt — this is an accepted trade-off for full autonomy.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet


class AutonomousSecretsError(Exception):
    """Raised when an autonomous secrets operation fails."""


class AutonomousSecretsStore:
    """
    Encrypted credential store backed by a key file.

    Directory layout::

        ~/.hermes/encrypted-secrets/
        ├── master.key          # Fernet AES-256 key (chmod 600)
        └── secrets.enc         # Encrypted JSON blob

    """

    #: Default location where the key file and encrypted store live,
    #: relative to the Hermes home directory.
    DEFAULT_SUBDIR = "encrypted-secrets"

    def __init__(self, base_dir: str | os.PathLike | None = None) -> None:
        self._base_dir = Path(base_dir) if base_dir else self._find_default_dir()
        self._key_path = self._base_dir / "master.key"
        self._secrets_path = self._base_dir / "secrets.enc"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @staticmethod
    def is_available() -> bool:
        """Return True if the encrypted secrets store exists and is initialised."""
        default = Path.home() / ".hermes" / AutonomousSecretsStore.DEFAULT_SUBDIR
        key = default / "master.key"
        secrets = default / "secrets.enc"
        return key.exists() and secrets.exists()

    def initialize(self, force: bool = False) -> str:
        """
        Create a fresh key file and empty encrypted store.

        Raises ``AutonomousSecretsError`` if the store already exists and
        ``force`` is not set.
        """
        if self._base_dir.exists() and not force:
            raise AutonomousSecretsError(
                f"Store already exists at {self._base_dir}. "
                "Use force=True to overwrite."
            )
        self._base_dir.mkdir(parents=True, exist_ok=True)
        key = Fernet.generate_key()
        self._key_path.write_bytes(key)
        self._key_path.chmod(0o600)
        empty_encrypted = Fernet(key).encrypt(json.dumps({}).encode())
        self._secrets_path.write_bytes(empty_encrypted)
        self._secrets_path.chmod(0o600)
        return f"Initialised autonomous secrets store at {self._base_dir}"

    @property
    def key_path(self) -> Path:
        return self._key_path

    @property
    def secrets_path(self) -> Path:
        return self._secrets_path

    def get(self, key: str) -> str:
        """Retrieve a single secret value."""
        secrets = self._decrypt()
        if key not in secrets:
            raise AutonomousSecretsError(f"Secret '{key}' not found")
        return secrets[key]

    def set(self, key: str, value: str) -> None:
        """Add or update a secret."""
        secrets = self._decrypt()
        secrets[key] = value
        self._encrypt(secrets)

    def delete(self, key: str) -> None:
        """Remove a secret by key."""
        secrets = self._decrypt()
        if key not in secrets:
            raise AutonomousSecretsError(f"Secret '{key}' not found")
        del secrets[key]
        self._encrypt(secrets)

    def list_keys(self) -> list[str]:
        """Return all secret key names (without revealing values)."""
        return sorted(self._decrypt().keys())

    def list_secrets(self) -> dict[str, str]:
        """Return all secrets (key → value). Use with caution — contains plaintext."""
        return dict(self._decrypt())

    def dump_env(self) -> str:
        """Return shell-safe ``export KEY='value'`` lines."""
        secrets = self._decrypt()
        lines: list[str] = []
        for key, value in sorted(secrets.items()):
            safe = value.replace("'", "'\\''")
            lines.append(f"export {key}='{safe}'")
        return "\n".join(lines)

    def dump_json(self) -> str:
        """Return all secrets as formatted JSON."""
        return json.dumps(self._decrypt(), indent=2)

    def to_dict(self) -> dict[str, str]:
        """Return all secrets as a plain dict."""
        return dict(self._decrypt())

    def populate_from(self, env_file: str | os.PathLike, *, overwrite: bool = False) -> dict[str, str]:
        """
        Populate the encrypted store from a `.env` file.

        Returns a dict of ``{key: "stored" | "skipped"}`` for reporting.
        """
        env_path = Path(env_file)
        if not env_path.exists():
            raise AutonomousSecretsError(f"Environment file not found: {env_path}")
        secrets = self._decrypt()
        results: dict[str, str] = {}
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip("'\"")
            if not key or not value:
                continue
            if key in secrets and not overwrite:
                results[key] = "skipped (exists)"
                continue
            secrets[key] = value
            results[key] = "stored"
        self._encrypt(secrets)
        return results

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_key(self) -> bytes:
        if not self._key_path.exists():
            raise AutonomousSecretsError(
                f"Master key not found at {self._key_path}. "
                "Run 'hermes-secrets init' or 'hermes vault secrets init' first."
            )
        return self._key_path.read_bytes()

    def _decrypt(self) -> dict[str, str]:
        if not self._secrets_path.exists() or self._secrets_path.stat().st_size == 0:
            return {}
        key = self._load_key()
        fernet = Fernet(key)
        raw = self._secrets_path.read_bytes()
        if raw.strip() in (b"{}", b""):
            return {}
        try:
            return json.loads(fernet.decrypt(raw))
        except Exception as exc:
            raise AutonomousSecretsError(
                f"Failed to decrypt secrets store: {exc}. "
                "The key file may be corrupted."
            ) from exc

    def _encrypt(self, secrets: dict[str, str]) -> None:
        key = self._load_key()
        fernet = Fernet(key)
        plaintext = json.dumps(secrets, indent=2, sort_keys=True).encode()
        encrypted = fernet.encrypt(plaintext)
        self._secrets_path.write_bytes(encrypted)
        self._secrets_path.chmod(0o600)

    @staticmethod
    def _find_default_dir() -> Path:
        return Path.home() / ".hermes" / AutonomousSecretsStore.DEFAULT_SUBDIR


# ------------------------------------------------------------------
# Convenience helpers (for use in scripts)
# ------------------------------------------------------------------

def get_secret(key: str, base_dir: str | os.PathLike | None = None) -> str:
    """One-liner: get a single secret by key."""
    store = AutonomousSecretsStore(base_dir)
    return store.get(key)


def export_env(base_dir: str | os.PathLike | None = None, *, safe: bool = True) -> None:
    """
    Export all secrets directly into ``os.environ``.

    Useful for modules that need to access secrets via ``os.environ``
    before any Hermes startup code runs.
    """
    store = AutonomousSecretsStore(base_dir)
    secrets = store.list_secrets()
    for key, value in secrets.items():
        os.environ[key] = value


# ------------------------------------------------------------------
# CLI entry point (used by ``hermes-secrets`` script)
# ------------------------------------------------------------------

def cli_main() -> None:
    """Simple CLI entry point — delegates to ``vaultknox.cli.secrets_main``."""
    # Avoid circular import by deferring
    from vaultknox.cli import secrets_main  # type: ignore[import-untyped]
    secrets_main()
