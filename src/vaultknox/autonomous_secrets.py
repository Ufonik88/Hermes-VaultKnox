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
from datetime import datetime
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet

from vaultknox.config import create_private_dir, write_private_file


from vaultknox.exceptions import AutonomousSecretsError


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

    # Default suffixes that identify credential env var names.
    CREDENTIAL_SUFFIXES: tuple[str, ...] = ("_KEY", "_TOKEN", "_SECRET", "_PASSWORD", "_CREDENTIALS")

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
        create_private_dir(self._base_dir)
        key = Fernet.generate_key()
        write_private_file(self._key_path, key)
        empty_encrypted = Fernet(key).encrypt(json.dumps({}).encode())
        write_private_file(self._secrets_path, empty_encrypted)
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

    def auto_seal(
        self,
        env_file: str | os.PathLike | None = None,
        *,
        dry_run: bool = False,
        strip_plaintext: bool = False,
    ) -> dict[str, Any]:
        """
        **Auto-Seal**: automatically find and encrypt any credential keys
        in ``.env`` that aren't yet in the encrypted store.

        This is the "set-and-forget" safety net. Run periodically (via cron),
        or on-demand after adding new API keys.

        How it works:
        1. Reads the Hermes ``.env`` file.
        2. Identifies keys ending in credential suffixes
           (``_KEY``, ``_TOKEN``, ``_SECRET``, ``_PASSWORD``, ``_CREDENTIALS``).
        3. Cross-references with the encrypted store.
        4. Encrypts any new keys.
        5. Optionally replaces plaintext values in ``.env`` with a
           ``# auto-sealed`` comment.

        Args:
            env_file: Path to the ``.env`` file. Defaults to
                      ``~/.hermes/.env``.
            dry_run: If True, only report what would be done — don't
                     actually encrypt or modify anything.
            strip_plaintext: If True, replace the value in ``.env`` with
                             a ``# auto-sealed`` comment after encrypting.
                             **Caution**: Hermes reads ``.env`` at startup,
                             so only enable this if you're using the
                             ``load_secrets.sh`` bootstrap.

        Returns:
            A dict with keys ``encrypted``, ``skipped``, ``errors``, and
            ``dry_run``.
        """
        if env_file is None:
            env_file = Path.home() / ".hermes" / ".env"
        env_path = Path(env_file)

        if not env_path.exists():
            return {"encrypted": [], "skipped": [], "errors": [f"File not found: {env_path}"], "dry_run": dry_run}

        current = self._decrypt()
        results: dict[str, Any] = {
            "encrypted": [],
            "skipped": [],
            "errors": [],
            "dry_run": dry_run,
            "scanned_at": datetime.now().isoformat(),
        }

        lines = env_path.read_text(encoding="utf-8").splitlines(keepends=True)
        new_lines = list(lines) if strip_plaintext else None

        for i, line in enumerate(lines):
            raw = line.strip()
            if not raw or raw.startswith("#") or "=" not in raw:
                continue

            key, _, value = raw.partition("=")
            key = key.strip()
            value = value.strip().strip("'\"")

            if not key or not value:
                continue

            # Check if this is a credential key
            is_credential = any(key.upper().endswith(suffix) for suffix in self.CREDENTIAL_SUFFIXES)
            if not is_credential:
                continue

            # Check if already in encrypted store
            if key in current:
                results["skipped"].append({"key": key, "reason": "already encrypted"})
                continue

            # Check if value looks valid (at least 8 chars, not a placeholder)
            if len(value) < 8 or value in ("placeholder", "changeme", "your-key-here", ""):
                results["skipped"].append({"key": key, "reason": "placeholder or too short"})
                continue

            if dry_run:
                results["encrypted"].append({"key": key, "value_preview": value[:8] + "...", "action": "would encrypt"})
                continue

            # Encrypt it
            try:
                current[key] = value
                results["encrypted"].append({"key": key, "value_preview": value[:8] + "...", "action": "encrypted"})
            except Exception as exc:
                results["errors"].append({"key": key, "error": str(exc)})
                continue

            # Optionally strip plaintext from .env
            if strip_plaintext and new_lines is not None:
                new_lines[i] = f"# {key}=[auto-sealed by Hermes VaultKnox v0.2.0]\n"

        # Write the encrypted store (if not dry run and we have changes)
        if not dry_run and results["encrypted"]:
            self._encrypt(current)

        # Write the stripped .env (if requested)
        if strip_plaintext and new_lines is not None and not dry_run:
            env_path.write_text("".join(new_lines), encoding="utf-8")

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
        write_private_file(self._secrets_path, encrypted)

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
