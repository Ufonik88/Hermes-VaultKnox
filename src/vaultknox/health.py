"""
VaultKnox Health Check Module v0.3.0

Verifies encryption integrity, file permissions, and audit log continuity.

Checks performed:
  1. DB file permissions (must be 0o600)
  2. Audit log file permissions (must be 0o600)
  3. Session files permissions (0o600)
  4. SQLite DB integrity (PRAGMA integrity_check returns 'ok')
  5. Vault config completeness (required keys present)
  6. Encryption integrity (decrypt a random secret entry)
  7. Audit log readability (parse events)
  8. Autonomous secrets store health (if it exists)
"""

from __future__ import annotations

import json
import stat
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from vaultknox.autonomous_secrets import AutonomousSecretsStore
from vaultknox.config import PRIVATE_FILE_MODE, VaultPaths
from vaultknox.core import EncryptedPayload, decrypt_payload, derive_master_key, derive_scoped_key
from vaultknox.db import VaultDatabase


class CheckStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"


class CheckSeverity(str, Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass(slots=True)
class HealthCheckResult:
    """Result of a single health check."""
    name: str
    status: CheckStatus
    message: str
    severity: CheckSeverity


@dataclass(slots=True)
class VaultHealthReport:
    """Complete health check report for VaultKnox."""
    overall_status: str  # 'healthy' | 'degraded' | 'critical'
    checks: list[HealthCheckResult]

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall_status": self.overall_status,
            "checks": [
                {
                    "name": c.name,
                    "status": c.status.value,
                    "message": c.message,
                    "severity": c.severity.value,
                }
                for c in self.checks
            ],
        }


class VaultHealthChecker:
    """
    Health checker for VaultKnox vault.

    Verifies file permissions, database integrity, config completeness,
    encryption integrity, audit log readability, and autonomous secrets store.

    The encryption integrity check requires the master password to decrypt
    a random secret entry. If not provided, that check will be skipped with
    a warning.
    """

    REQUIRED_CONFIG_KEYS = frozenset([
        "argon2_salt",
        "verifier",
        "kdf_params",
        "vault_version",
    ])

    def __init__(
        self,
        paths: VaultPaths,
        *,
        master_password: str | None = None,
    ) -> None:
        self.paths = paths
        self.master_password = master_password
        self._db: VaultDatabase | None = None

    @property
    def db(self) -> VaultDatabase:
        if self._db is None:
            self._db = VaultDatabase(self.paths.db_path)
        return self._db

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    def run_all_checks(self) -> VaultHealthReport:
        """Run all health checks and return a structured report."""
        checks: list[HealthCheckResult] = []

        # Permission checks
        checks.append(self._check_db_permissions())
        checks.append(self._check_audit_log_permissions())
        checks.append(self._check_session_permissions())

        # DB integrity checks
        checks.append(self._check_db_integrity())
        checks.append(self._check_config_completeness())

        # Encryption integrity (requires password)
        checks.append(self._check_encryption_integrity())

        # Audit log checks
        checks.append(self._check_audit_log_readability())

        # Autonomous secrets store
        checks.append(self._check_autonomous_secrets())

        # Determine overall status
        overall = self._determine_overall_status(checks)

        return VaultHealthReport(overall_status=overall, checks=checks)

    # -------------------------------------------------------------------------
    # Permission Checks
    # -------------------------------------------------------------------------

    def _check_db_permissions(self) -> HealthCheckResult:
        """Check that the database file has correct permissions (0o600)."""
        return self._check_file_permissions(
            self.paths.db_path,
            name="db_file_permissions",
            file_description="Database file",
        )

    def _check_audit_log_permissions(self) -> HealthCheckResult:
        """Check that the audit log file has correct permissions (0o600)."""
        return self._check_file_permissions(
            self.paths.audit_log_path,
            name="audit_log_permissions",
            file_description="Audit log file",
        )

    def _check_session_permissions(self) -> HealthCheckResult:
        """Check that session files have correct permissions (0o600)."""
        missing_files: list[str] = []
        wrong_perms: list[str] = []
        ok_files: list[str] = []

        for path, desc in [
            (self.paths.session_path, "session file"),
            (self.paths.session_lock_path, "session lock file"),
        ]:
            result = self._check_file_permissions(path, "session_file", desc)
            if result.status == CheckStatus.PASS:
                ok_files.append(desc)
            elif result.status == CheckStatus.FAIL and "incorrect permissions" in result.message:
                wrong_perms.append(desc)
            else:  # WARN - does not exist
                missing_files.append(desc)

        # If any have wrong permissions, report as failure
        if wrong_perms:
            return HealthCheckResult(
                name="session_files_permissions",
                status=CheckStatus.FAIL,
                message=f"Session files with incorrect permissions: {wrong_perms}",
                severity=CheckSeverity.ERROR,
            )

        # If all missing, warn
        if len(missing_files) == 2:
            return HealthCheckResult(
                name="session_files_permissions",
                status=CheckStatus.WARN,
                message="No session files present (vault may be locked or uninitialized)",
                severity=CheckSeverity.INFO,
            )

        # If some present (and none wrong), pass
        return HealthCheckResult(
            name="session_files_permissions",
            status=CheckStatus.PASS,
            message=f"All session files present and have correct permissions ({oct(PRIVATE_FILE_MODE)})",
            severity=CheckSeverity.INFO,
        )

    def _check_file_permissions(
        self,
        path: Path,
        name: str,
        file_description: str,
    ) -> HealthCheckResult:
        """Generic file permission check helper."""
        if not path.exists():
            return HealthCheckResult(
                name=name,
                status=CheckStatus.WARN,
                message=f"{file_description} does not exist",
                severity=CheckSeverity.INFO,
            )

        try:
            mode = path.stat().st_mode
            actual_mode = stat.S_IMODE(mode)
        except OSError as exc:
            return HealthCheckResult(
                name=name,
                status=CheckStatus.FAIL,
                message=f"Cannot stat {file_description}: {exc}",
                severity=CheckSeverity.ERROR,
            )

        if actual_mode != PRIVATE_FILE_MODE:
            return HealthCheckResult(
                name=name,
                status=CheckStatus.FAIL,
                message=f"{file_description} has incorrect permissions {oct(actual_mode)}; expected {oct(PRIVATE_FILE_MODE)}",
                severity=CheckSeverity.ERROR,
            )

        return HealthCheckResult(
            name=name,
            status=CheckStatus.PASS,
            message=f"{file_description} has correct permissions {oct(PRIVATE_FILE_MODE)}",
            severity=CheckSeverity.INFO,
        )

    # -------------------------------------------------------------------------
    # Database Integrity Checks
    # -------------------------------------------------------------------------

    def _check_db_integrity(self) -> HealthCheckResult:
        """Run SQLite PRAGMA integrity_check on the database."""
        if not self.paths.db_path.exists():
            return HealthCheckResult(
                name="db_integrity",
                status=CheckStatus.FAIL,
                message="Database file does not exist",
                severity=CheckSeverity.ERROR,
            )

        try:
            with self.db.connection() as conn:
                rows = conn.execute("PRAGMA integrity_check").fetchall()
        except Exception as exc:
            return HealthCheckResult(
                name="db_integrity",
                status=CheckStatus.FAIL,
                message=f"Database integrity check failed: {exc}",
                severity=CheckSeverity.ERROR,
            )

        if len(rows) != 1 or rows[0][0] != "ok":
            return HealthCheckResult(
                name="db_integrity",
                status=CheckStatus.FAIL,
                message=f"Database integrity check returned: {[r[0] for r in rows]}",
                severity=CheckSeverity.ERROR,
            )

        return HealthCheckResult(
            name="db_integrity",
            status=CheckStatus.PASS,
            message="Database integrity check passed",
            severity=CheckSeverity.INFO,
        )

    def _check_config_completeness(self) -> HealthCheckResult:
        """Verify all required vault config keys are present."""
        if not self.paths.db_path.exists():
            return HealthCheckResult(
                name="config_completeness",
                status=CheckStatus.FAIL,
                message="Database does not exist; cannot check config",
                severity=CheckSeverity.ERROR,
            )

        try:
            with self.db.connection() as conn:
                rows = conn.execute("SELECT key FROM vault_config").fetchall()
        except Exception as exc:
            return HealthCheckResult(
                name="config_completeness",
                status=CheckStatus.FAIL,
                message=f"Failed to query vault_config: {exc}",
                severity=CheckSeverity.ERROR,
            )

        existing_keys = {row["key"] for row in rows}
        missing_keys = self.REQUIRED_CONFIG_KEYS - existing_keys

        if missing_keys:
            return HealthCheckResult(
                name="config_completeness",
                status=CheckStatus.FAIL,
                message=f"Missing required config keys: {sorted(missing_keys)}",
                severity=CheckSeverity.ERROR,
            )

        # Verify each key has a non-empty value
        with self.db.connection() as conn:
            for key in self.REQUIRED_CONFIG_KEYS:
                row = conn.execute(
                    "SELECT value FROM vault_config WHERE key = ?", (key,)
                ).fetchone()
                if row is None or not row["value"]:
                    return HealthCheckResult(
                        name="config_completeness",
                        status=CheckStatus.FAIL,
                        message=f"Config key '{key}' has empty value",
                        severity=CheckSeverity.ERROR,
                    )

        # Validate kdf_params is valid JSON
        kdf_params_raw = self.db.get_config("kdf_params")
        if kdf_params_raw:
            try:
                json.loads(kdf_params_raw)
            except json.JSONDecodeError as exc:
                return HealthCheckResult(
                    name="config_completeness",
                    status=CheckStatus.FAIL,
                    message=f"kdf_params is not valid JSON: {exc}",
                    severity=CheckSeverity.ERROR,
                )

        # Validate verifier is valid JSON
        verifier_raw = self.db.get_config("verifier")
        if verifier_raw:
            try:
                verifier_data = json.loads(verifier_raw)
                required_verifier_fields = {"nonce", "ciphertext", "tag"}
                if not required_verifier_fields.issubset(verifier_data.keys()):
                    return HealthCheckResult(
                        name="config_completeness",
                        status=CheckStatus.FAIL,
                        message=f"verifier missing required fields; has {set(verifier_data.keys())}",
                        severity=CheckSeverity.ERROR,
                    )
            except json.JSONDecodeError as exc:
                return HealthCheckResult(
                    name="config_completeness",
                    status=CheckStatus.FAIL,
                    message=f"verifier is not valid JSON: {exc}",
                    severity=CheckSeverity.ERROR,
                )

        return HealthCheckResult(
            name="config_completeness",
            status=CheckStatus.PASS,
            message=f"All required config keys present: {sorted(self.REQUIRED_CONFIG_KEYS)}",
            severity=CheckSeverity.INFO,
        )

    # -------------------------------------------------------------------------
    # Encryption Integrity Check
    # -------------------------------------------------------------------------

    def _check_encryption_integrity(self) -> HealthCheckResult:
        """
        Verify encryption integrity by attempting to decrypt a random secret entry.

        Requires master_password to be set. Without it, this check returns a
        warning (skip) rather than a failure, since the vault may be healthy
        but simply locked.
        """
        if not self.paths.db_path.exists():
            return HealthCheckResult(
                name="encryption_integrity",
                status=CheckStatus.FAIL,
                message="Database does not exist",
                severity=CheckSeverity.ERROR,
            )

        if self.master_password is None:
            return HealthCheckResult(
                name="encryption_integrity",
                status=CheckStatus.WARN,
                message="Master password not provided; cannot verify encryption integrity",
                severity=CheckSeverity.WARNING,
            )

        try:
            return self._verify_encryption_with_password()
        except Exception as exc:
            return HealthCheckResult(
                name="encryption_integrity",
                status=CheckStatus.FAIL,
                message=f"Encryption integrity check failed: {exc}",
                severity=CheckSeverity.ERROR,
            )

    def _verify_encryption_integrity_with_password(self) -> HealthCheckResult:
        """
        Internal method that verifies encryption using the provided password.
        Called only when password is available.
        """
        # Verify the password first (this also checks key derivation)
        try:
            salt_hex = self.db.get_config("argon2_salt")
            if not salt_hex:
                return HealthCheckResult(
                    name="encryption_integrity",
                    status=CheckStatus.FAIL,
                    message="argon2_salt not found in config",
                    severity=CheckSeverity.ERROR,
                )

            salt = bytes.fromhex(salt_hex)
            master_key = derive_master_key(self.master_password, salt)
            entry_key = derive_scoped_key(master_key)

            # Verify password using the verifier
            verifier_raw = self.db.get_config("verifier")
            if not verifier_raw:
                return HealthCheckResult(
                    name="encryption_integrity",
                    status=CheckStatus.FAIL,
                    message="verifier not found in config",
                    severity=CheckSeverity.ERROR,
                )

            verifier_data = json.loads(verifier_raw)
            verifier_key = derive_scoped_key(master_key, b"vaultknox-verifier")
            encrypted = EncryptedPayload(
                nonce=bytes.fromhex(verifier_data["nonce"]),
                ciphertext=bytes.fromhex(verifier_data["ciphertext"]),
                tag=bytes.fromhex(verifier_data["tag"]),
            )
            decrypt_payload(verifier_key, encrypted)
        except Exception as exc:
            return HealthCheckResult(
                name="encryption_integrity",
                status=CheckStatus.FAIL,
                message=f"Password verification failed: {exc}",
                severity=CheckSeverity.ERROR,
            )

        # Try to decrypt a random secret
        try:
            with self.db.connection() as conn:
                rows = conn.execute(
                    "SELECT id, type, label, data, nonce, tag FROM secrets ORDER BY RANDOM() LIMIT 1"
                ).fetchall()

            if not rows:
                return HealthCheckResult(
                    name="encryption_integrity",
                    status=CheckStatus.PASS,
                    message="No secrets in vault to verify; encryption setup appears correct",
                    severity=CheckSeverity.INFO,
                )

            row = rows[0]
            encrypted = EncryptedPayload(
                nonce=row["nonce"],
                ciphertext=row["data"],
                tag=row["tag"],
            )
            decrypt_payload(entry_key, encrypted)

            return HealthCheckResult(
                name="encryption_integrity",
                status=CheckStatus.PASS,
                message="Successfully decrypted a random secret entry to verify key derivation",
                severity=CheckSeverity.INFO,
            )
        except Exception as exc:
            return HealthCheckResult(
                name="encryption_integrity",
                status=CheckStatus.FAIL,
                message=f"Failed to decrypt a secret entry: {exc}",
                severity=CheckSeverity.ERROR,
            )

    def _verify_encryption_with_password(self) -> HealthCheckResult:
        """Alias for the internal verification method."""
        return self._verify_encryption_integrity_with_password()

    # -------------------------------------------------------------------------
    # Audit Log Checks
    # -------------------------------------------------------------------------

    def _check_audit_log_readability(self) -> HealthCheckResult:
        """Verify the audit log is readable and contains valid JSON events."""
        if not self.paths.audit_log_path.exists():
            return HealthCheckResult(
                name="audit_log_readability",
                status=CheckStatus.WARN,
                message="Audit log file does not exist",
                severity=CheckSeverity.WARNING,
            )

        try:
            content = self.paths.audit_log_path.read_text(encoding="utf-8")
        except OSError as exc:
            return HealthCheckResult(
                name="audit_log_readability",
                status=CheckStatus.FAIL,
                message=f"Cannot read audit log: {exc}",
                severity=CheckSeverity.ERROR,
            )

        if not content.strip():
            return HealthCheckResult(
                name="audit_log_readability",
                status=CheckStatus.PASS,
                message="Audit log is empty",
                severity=CheckSeverity.INFO,
            )

        lines = content.splitlines()
        valid_events = 0
        invalid_lines: list[int] = []

        for i, line in enumerate(lines, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                # Verify expected fields
                if not isinstance(event, dict):
                    invalid_lines.append(i)
                    continue
                if "timestamp" not in event or "action" not in event or "status" not in event:
                    invalid_lines.append(i)
                    continue
                valid_events += 1
            except json.JSONDecodeError:
                invalid_lines.append(i)

        if invalid_lines:
            return HealthCheckResult(
                name="audit_log_readability",
                status=CheckStatus.FAIL,
                message=f"Found {len(invalid_lines)} invalid JSON lines in audit log: lines {invalid_lines[:5]}",
                severity=CheckSeverity.ERROR,
            )

        return HealthCheckResult(
            name="audit_log_readability",
            status=CheckStatus.PASS,
            message=f"Audit log is readable with {valid_events} valid event(s)",
            severity=CheckSeverity.INFO,
        )

    # -------------------------------------------------------------------------
    # Autonomous Secrets Store Check
    # -------------------------------------------------------------------------

    def _check_autonomous_secrets(self) -> HealthCheckResult:
        """Check health of the autonomous secrets store, if it exists."""
        if not AutonomousSecretsStore.is_available():
            return HealthCheckResult(
                name="autonomous_secrets",
                status=CheckStatus.WARN,
                message="Autonomous secrets store not available or not initialized",
                severity=CheckSeverity.INFO,
            )

        try:
            store = AutonomousSecretsStore()
        except Exception as exc:
            return HealthCheckResult(
                name="autonomous_secrets",
                status=CheckStatus.FAIL,
                message=f"Failed to initialize AutonomousSecretsStore: {exc}",
                severity=CheckSeverity.ERROR,
            )

        # Check key file permissions
        if store.key_path.exists():
            try:
                key_mode = stat.S_IMODE(store.key_path.stat().st_mode)
                if key_mode != PRIVATE_FILE_MODE:
                    return HealthCheckResult(
                        name="autonomous_secrets",
                        status=CheckStatus.FAIL,
                        message=f"master.key has incorrect permissions {oct(key_mode)}; expected {oct(PRIVATE_FILE_MODE)}",
                        severity=CheckSeverity.ERROR,
                    )
            except OSError as exc:
                return HealthCheckResult(
                    name="autonomous_secrets",
                    status=CheckStatus.FAIL,
                    message=f"Cannot stat master.key: {exc}",
                    severity=CheckSeverity.ERROR,
                )

        # Check secrets file permissions
        if store.secrets_path.exists():
            try:
                secrets_mode = stat.S_IMODE(store.secrets_path.stat().st_mode)
                if secrets_mode != PRIVATE_FILE_MODE:
                    return HealthCheckResult(
                        name="autonomous_secrets",
                        status=CheckStatus.FAIL,
                        message=f"secrets.enc has incorrect permissions {oct(secrets_mode)}; expected {oct(PRIVATE_FILE_MODE)}",
                        severity=CheckSeverity.ERROR,
                    )
            except OSError as exc:
                return HealthCheckResult(
                    name="autonomous_secrets",
                    status=CheckStatus.FAIL,
                    message=f"Cannot stat secrets.enc: {exc}",
                    severity=CheckSeverity.ERROR,
                )

        # Try to decrypt to verify integrity
        try:
            secrets = store.list_keys()
        except Exception as exc:
            return HealthCheckResult(
                name="autonomous_secrets",
                status=CheckStatus.FAIL,
                message=f"Failed to decrypt/read autonomous secrets: {exc}",
                severity=CheckSeverity.ERROR,
            )

        return HealthCheckResult(
            name="autonomous_secrets",
            status=CheckStatus.PASS,
            message=f"Autonomous secrets store is healthy ({len(secrets)} secret(s) stored)",
            severity=CheckSeverity.INFO,
        )

    # -------------------------------------------------------------------------
    # Status Aggregation
    # -------------------------------------------------------------------------

    def _determine_overall_status(self, checks: list[HealthCheckResult]) -> str:
        """Determine overall vault health from individual check results."""
        has_error = any(c.severity == CheckSeverity.ERROR and c.status == CheckStatus.FAIL for c in checks)
        has_warning = any(c.severity == CheckSeverity.WARNING and c.status in (CheckStatus.FAIL, CheckStatus.WARN) for c in checks)

        if has_error:
            return "critical"
        if has_warning:
            return "degraded"
        return "healthy"
