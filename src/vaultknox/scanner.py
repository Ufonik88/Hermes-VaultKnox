"""Secret scanner for VaultKnox v0.3.0.

Scans files for plaintext secrets, bad file permissions, and duplicate
credentials. Designed to be safe for large files (streams/limits content)
and CLI-friendly (structured findings output).

Usage:
    from vaultknox.scanner import SecretScanner

    scanner = SecretScanner()
    findings = scanner.scan()
    for f in findings:
        print(f"{f.severity}: {f.file_path}:{f.line_number} — {f.detector_name}")
"""

from __future__ import annotations

import hashlib
import math
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, NamedTuple

from vaultknox.detectors import DETECTORS, PLACEHOLDER_ALLOWLIST, Detector

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Files older than this are still scanned, but skipped if they have no secrets
# and we want to limit scan time. Not currently enforced for simplicity.
MAX_FILE_SIZE_FOR_FULL_SCAN = 10 * 1024 * 1024  # 10 MB — above this, stream
MAX_LINE_LENGTH = 100_000  # Truncate lines longer than this
MAX_BYTES_PER_FILE = 5 * 1024 * 1024  # 5 MB hard cap read per file

# Default paths to scan
DEFAULT_SCAN_PATHS = [
    Path.home() / ".hermes",
    Path.home() / ".bashrc",
    Path.home() / ".zshrc",
    Path.home() / ".profile",
]

# File extensions / names to scan
SCANNABLE_EXTENSIONS = frozenset({".env", ".json", ".yaml", ".yml", ".sh", ".bashrc", ".zshrc", ".profile"})
SKIP_NAMES = frozenset({"node_modules", ".git", "__pycache__", ".pytest_cache", ".mypy_cache"})

# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


class Finding(NamedTuple):
    """A single secret-finding result."""

    file_path: str
    line_number: int
    line_content: str  # Truncated to MAX_LINE_LENGTH
    detector_name: str
    severity: str
    secret_fingerprint: str  # SHA-256 of the detected secret value
    is_duplicate: bool = False

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "line_content": self.line_content,
            "detector_name": self.detector_name,
            "severity": self.severity,
            "secret_fingerprint": self.secret_fingerprint,
            "is_duplicate": self.is_duplicate,
        }


# ---------------------------------------------------------------------------
# Permission check
# ---------------------------------------------------------------------------


@dataclass
class PermissionIssue:
    """A file with insecure permissions that contains or may contain secrets."""

    file_path: str
    mode: int
    issue: str  # human-readable description


def check_file_permissions(path: Path) -> PermissionIssue | None:
    """Return a PermissionIssue if the file is world-readable and is a secret-containing type."""
    try:
        mode = path.stat().st_mode
    except OSError:
        return None

    is_secret_file = path.suffix in {".env", ".json"} or path.name in {".env"}

    # Check if world-readable (others can read)
    if mode & stat.S_IROTH:
        if is_secret_file:
            return PermissionIssue(
                file_path=str(path),
                mode=mode,
                issue="World-readable .env or .json file — sensitive data may be exposed to other users on the system",
            )
        # Even non-secret files that are world-readable are worth flagging if they're config files
        if path.suffix in {".yaml", ".yml", ".sh"} or path.name in {".bashrc", ".zshrc", ".profile"}:
            return PermissionIssue(
                file_path=str(path),
                mode=mode,
                issue="World-readable shell/config file — may contain credentials or sensitive settings",
            )

    # Check if group-readable and not owned by the user's primary group
    # (i.e., group-accessible to others)
    if mode & stat.S_IRGRP:
        # Only flag if the file's group is not the user's primary group, flag it
        try:
            import pwd

            st = path.stat()
            primary_gid = pwd.getpwuid(os.getuid()).pw_gid
            file_gid = st.st_gid
            if file_gid != primary_gid and is_secret_file:
                return PermissionIssue(
                    file_path=str(path),
                    mode=mode,
                    issue="Group-readable .env or .json file — sensitive data may be shared with other system groups",
                )
        except Exception:
            # If we can't determine group info, skip the group check
            pass

    return None


# ---------------------------------------------------------------------------
# Secret scanner
# ---------------------------------------------------------------------------


class ScanStats(NamedTuple):
    """Statistics from a scan run."""

    files_scanned: int
    files_with_secrets: int
    total_findings: int
    permission_issues: int
    duplicates: int


class SecretScanner:
    """Scans configured paths for plaintext secrets and security issues."""

    def __init__(
        self,
        paths: list[Path] | None = None,
        detectors: list[Detector] | None = None,
        max_bytes_per_file: int = MAX_BYTES_PER_FILE,
        max_line_length: int = MAX_LINE_LENGTH,
        entropy_threshold: float = 3.5,
    ) -> None:
        self.paths = paths or DEFAULT_SCAN_PATHS
        self.detectors = detectors or DETECTORS
        self.max_bytes_per_file = max_bytes_per_file
        self.max_line_length = max_line_length
        self.entropy_threshold = entropy_threshold
        # Track seen fingerprints to detect duplicates
        self._seen_fingerprints: dict[str, list[str]] = {}  # fingerprint -> [file_path, ...]
        self._stats = ScanStats(
            files_scanned=0,
            files_with_secrets=0,
            total_findings=0,
            permission_issues=0,
            duplicates=0,
        )

    def scan(self) -> tuple[list[Finding], list[PermissionIssue], ScanStats]:
        """Run the scan across all configured paths.

        Returns:
            A tuple of (findings, permission_issues, stats)
        """
        findings: list[Finding] = []
        permission_issues: list[PermissionIssue] = []
        self._seen_fingerprints.clear()
        self._stats = ScanStats(0, 0, 0, 0, 0)

        for base_path in self.paths:
            if not base_path.exists():
                continue
            for file_path, _file_issues, file_findings in self._scan_path(base_path):
                self._stats = self._stats._replace(files_scanned=self._stats.files_scanned + 1)

                # Check permissions first
                perm_issue = check_file_permissions(file_path)
                if perm_issue:
                    permission_issues.append(perm_issue)
                    self._stats = self._stats._replace(permission_issues=self._stats.permission_issues + 1)

                if file_findings:
                    findings.extend(file_findings)
                    self._stats = self._stats._replace(
                        files_with_secrets=self._stats.files_with_secrets + 1,
                        total_findings=self._stats.total_findings + len(file_findings),
                    )

                # Count duplicates
                for f in file_findings:
                    if f.is_duplicate:
                        self._stats = self._stats._replace(duplicates=self._stats.duplicates + 1)

        return findings, permission_issues, self._stats

    def _scan_path(self, base_path: Path) -> Iterator[tuple[Path, list[PermissionIssue], list[Finding]]]:
        """Recursively walk a path and yield scan results per file."""
        if base_path.is_file():
            yield from self._scan_file(base_path)
            return

        for item in _walk_with_skip(base_path):
            if item.is_file():
                if not self._is_scannable(item):
                    continue
                yield from self._scan_file(item)

    def _scan_file(self, path: Path) -> Iterator[tuple[Path, list[PermissionIssue], list[Finding]]]:
        """Scan a single file for secrets. Yields (path, permission_issues, findings)."""
        try:
            file_size = path.stat().st_size
        except OSError:
            return

        findings: list[Finding] = []
        line_number = 0

        def process_line(line: str) -> None:
            nonlocal line_number, findings
            line_number += 1
            # Guard against catastrophic backtracking on very long lines.
            # Skip pattern matching entirely if the line exceeds the configured
            # maximum length — we've already truncated it to what we store anyway.
            if len(line) > self.max_line_length:
                return
            for detector in self.detectors:
                match = detector.pattern.search(line)
                if not match:
                    continue

                secret_value = match.group(0)
                if detector.name == "High Entropy Secret Assignment":
                    candidate = _extract_assignment_value(secret_value)
                    lowered = candidate.lower()
                    if any(word in lowered for word in PLACEHOLDER_ALLOWLIST):
                        continue
                    if candidate and _shannon_entropy(candidate) < self.entropy_threshold:
                        continue
                fingerprint = _fingerprint(secret_value)

                # Record fingerprint for duplicate detection
                is_dup = fingerprint in self._seen_fingerprints
                if not is_dup:
                    self._seen_fingerprints[fingerprint] = []
                self._seen_fingerprints[fingerprint].append(str(path))

                findings.append(
                    Finding(
                        file_path=str(path),
                        line_number=line_number,
                        line_content=line[: self.max_line_length],
                        detector_name=detector.name,
                        severity=detector.severity,
                        secret_fingerprint=fingerprint,
                        is_duplicate=is_dup,
                    )
                )

        if file_size > self.max_bytes_per_file:
            # Stream the file
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    process_line(line.rstrip("\n"))
        else:
            # Read entire small file
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                return
            for line in content.splitlines():
                process_line(line)

        yield path, [], findings

    def _is_scannable(self, path: Path) -> bool:
        """Return True if this file should be scanned for secrets."""
        name = path.name
        if name in SKIP_NAMES:
            return False
        if path.suffix in SCANNABLE_EXTENSIONS:
            return True
        if name in {".bashrc", ".zshrc", ".profile", ".env"}:
            return True
        return False


def _walk_with_skip(root: Path) -> Iterator[Path]:
    """Walk directory tree, yielding paths while skipping node_modules, .git, etc."""
    try:
        entries = list(root.iterdir())
    except PermissionError:
        return

    for entry in entries:
        if entry.name in SKIP_NAMES:
            continue
        yield entry
        if entry.is_dir():
            yield from _walk_with_skip(entry)


def _fingerprint(secret: str) -> str:
    """Compute a SHA-256 fingerprint of a secret value for duplicate detection."""
    return hashlib.sha256(secret.encode("utf-8"), usedforsecurity=True).hexdigest()


def _extract_assignment_value(text: str) -> str:
    """Extract assigned value from key=value/key: value style strings."""
    for sep in ("=", ":"):
        if sep in text:
            return text.split(sep, 1)[1].strip().strip("'\"")
    return text.strip().strip("'\"")


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    freq: dict[str, int] = {}
    for ch in value:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(value)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------


def format_findings_cli(findings: list[Finding], permission_issues: list[PermissionIssue], stats: ScanStats) -> str:
    """Format scan results as a CLI-friendly human-readable report."""
    lines: list[str] = []

    severity_colors = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🟢",
    }

    if not findings and not permission_issues:
        lines.append("✅ No secrets or permission issues found.")
        return "\n".join(lines)

    if findings:
        lines.append(f"\n🔍 Secret Findings ({stats.total_findings} total, {stats.duplicates} duplicates):")
        for f in sorted(findings, key=lambda x: _severity_rank(x.severity)):
            icon = severity_colors.get(f.severity, "⚪")
            dup_marker = " [DUPLICATE]" if f.is_duplicate else ""
            lines.append(
                f"  {icon} [{f.severity.upper()}] {f.detector_name}{dup_marker}\n"
                f"      File: {f.file_path}:{f.line_number}\n"
                f"      Line: {f.line_content[:120]}{'...' if len(f.line_content) > 120 else ''}"
            )

    if permission_issues:
        lines.append(f"\n🔓 Permission Issues ({stats.permission_issues}):")
        for p in permission_issues:
            octal_mode = oct(p.mode)[-3:]
            lines.append(f"  ⚠️  {p.file_path}")
            lines.append(f"      Mode: {octal_mode} | Issue: {p.issue}")

    lines.append(f"\n📊 Stats: {stats.files_scanned} files scanned, {stats.files_with_secrets} with secrets")
    return "\n".join(lines)


def _severity_rank(severity: str) -> int:
    """Return a numeric rank for sorting severities (lower = more critical)."""
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return order.get(severity, 99)


def format_findings_json(findings: list[Finding], permission_issues: list[PermissionIssue], stats: ScanStats) -> str:
    """Format scan results as structured JSON for machine consumption."""
    import json

    return json.dumps(
        {
            "findings": [f.to_dict() for f in findings],
            "permission_issues": [
                {"file_path": p.file_path, "mode": oct(p.mode), "issue": p.issue}
                for p in permission_issues
            ],
            "stats": {
                "files_scanned": stats.files_scanned,
                "files_with_secrets": stats.files_with_secrets,
                "total_findings": stats.total_findings,
                "permission_issues": stats.permission_issues,
                "duplicates": stats.duplicates,
            },
        },
        indent=2,
    )
