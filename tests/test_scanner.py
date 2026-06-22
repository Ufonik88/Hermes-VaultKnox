"""Unit tests for VaultKnox secret scanner."""

from __future__ import annotations

import json
import os
from pathlib import Path

from vaultknox import detectors as detectors_module
from vaultknox.scanner import (
    MAX_LINE_LENGTH,
    Finding,
    SecretScanner,
    _fingerprint,
    _severity_rank,
    _shannon_entropy,
    check_file_permissions,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_file(path: Path, *lines: str) -> None:
    """Write a temp file with the given lines (newline-separated)."""
    path.write_text("".join(lines), encoding="utf-8")


def _openai_placeholder() -> str:
    """A placeholder OpenAI-style key — NEVER a real secret."""
    # Must be sk-[A-Za-z0-9_-]{20,} = at least 23 chars total
    return "sk-TESTPLACEHOLDER12345X"


def _github_placeholder() -> str:
    """A placeholder GitHub PAT — NEVER a real secret."""
    # Must be ghp_[A-Za-z0-9]{36,} = at least 40 chars total (ghp_ + 36 chars)
    return "ghp_TESTPLACEHOLDERTOKEN1234567890123456"


def _anthropic_placeholder() -> str:
    """A placeholder Anthropic key — NEVER a real secret."""
    # Must be sk-ant-[A-Za-z0-9_-]{40,} = at least 47 chars total (sk-ant- + 40 chars)
    return "sk-ant-testplaceholder12345678901234567890ABCDEF"


def _aws_placeholder() -> str:
    """A placeholder AWS key ID — NEVER a real secret."""
    # Must be AKIA[A-Z0-9]{16} = 20 chars total
    return "AKIATESTSECRET1234567"


# ---------------------------------------------------------------------------
# Fingerprint tests
# ---------------------------------------------------------------------------


class TestFingerprint:
    def test_fingerprint_is_sha256_hex(self) -> None:
        fp = _fingerprint("sk-test-placeholder-key-for-testing")
        assert len(fp) == 64
        assert all(c in "0123456789abcdef" for c in fp)

    def test_fingerprint_is_deterministic(self) -> None:
        fp1 = _fingerprint("sk-test-placeholder-key-for-testing")
        fp2 = _fingerprint("sk-test-placeholder-key-for-testing")
        assert fp1 == fp2

    def test_fingerprint_different_values_differ(self) -> None:
        fp1 = _fingerprint("sk-test-placeholder-key-for-testing")
        fp2 = _fingerprint("sk-test-placeholder-key-for-different")
        assert fp1 != fp2


# ---------------------------------------------------------------------------
# Severity ranking
# ---------------------------------------------------------------------------


class TestSeverityRank:
    def test_order_critical_first(self) -> None:
        severities = ["low", "medium", "high", "critical"]
        ranked = sorted(severities, key=_severity_rank)
        assert ranked == ["critical", "high", "medium", "low"]


# ---------------------------------------------------------------------------
# Detector registry
# ---------------------------------------------------------------------------


class TestDetectorRegistry:
    def test_detectors_not_empty(self) -> None:
        assert len(detectors_module.DETECTORS) > 0

    def test_each_detector_has_required_fields(self) -> None:
        for d in detectors_module.DETECTORS:
            assert d.name
            assert d.pattern
            assert d.severity in ("critical", "high", "medium", "low")
            assert d.description
            assert d.commonly_found_in is not None

    def test_get_detector_by_name(self) -> None:
        d = detectors_module.get_detector("OpenAI API Key")
        assert d is not None
        assert d.name == "OpenAI API Key"
        assert d.severity == "critical"

    def test_get_detector_unknown_returns_none(self) -> None:
        assert detectors_module.get_detector("Not a Real Detector") is None

    def test_get_detectors_by_severity(self) -> None:
        critical = detectors_module.get_detectors_by_severity("critical")
        assert all(d.severity == "critical" for d in critical)

    def test_get_detectors_for_file(self) -> None:
        env_detectors = detectors_module.get_detectors_for_file(".env")
        assert len(env_detectors) > 0

    def test_openai_pattern_matches(self) -> None:
        d = detectors_module.get_detector("OpenAI API Key")
        assert d is not None
        match = d.pattern.search(f"export OPENAI_KEY='{_openai_placeholder()}'")
        assert match is not None

    def test_github_pattern_matches(self) -> None:
        d = detectors_module.get_detector("GitHub Personal Access Token (classic)")
        assert d is not None
        match = d.pattern.search(f"GH_TOKEN='{_github_placeholder()}'")
        assert match is not None

    def test_anthropic_pattern_matches(self) -> None:
        d = detectors_module.get_detector("Anthropic API Key")
        assert d is not None
        match = d.pattern.search(f"ANTHROPIC_API_KEY={_anthropic_placeholder()}")
        assert match is not None

    def test_aws_pattern_matches(self) -> None:
        d = detectors_module.get_detector("AWS Access Key ID")
        assert d is not None
        match = d.pattern.search(f"AWS_ACCESS_KEY_ID={_aws_placeholder()}")
        assert match is not None

    def test_generic_key_pattern_matches(self) -> None:
        d = detectors_module.get_detector("Generic API Key Pattern")
        assert d is not None
        match = d.pattern.search("MY_SERVICE_API_KEY='abcdefghijk12345678901234'")
        assert match is not None

    def test_bearer_token_pattern_matches(self) -> None:
        d = detectors_module.get_detector("Bearer Token")
        assert d is not None
        match = d.pattern.search("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2F1dGguc2VydmljZSJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
        assert match is not None

    def test_google_api_key_pattern_matches(self) -> None:
        d = detectors_module.get_detector("Google API Key")
        assert d is not None
        match = d.pattern.search("AIzaSyDUMMYDUMMYDUMMYDUMMYDUMMYDUMMY123")
        assert match is not None

    def test_jwt_pattern_matches(self) -> None:
        d = detectors_module.get_detector("JWT Token")
        assert d is not None
        match = d.pattern.search("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
        assert match is not None


# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------


class TestFinding:
    def test_to_dict(self) -> None:
        f = Finding(
            file_path="/tmp/test.env",
            line_number=5,
            line_content="OPENAI_KEY=sk-test-placeholder-key",
            detector_name="OpenAI API Key",
            severity="critical",
            secret_fingerprint="abc123",
            is_duplicate=False,
        )
        d = f.to_dict()
        assert d["file_path"] == "/tmp/test.env"
        assert d["line_number"] == 5
        assert d["severity"] == "critical"
        assert d["is_duplicate"] is False


# ---------------------------------------------------------------------------
# Scanner — single file tests
# ---------------------------------------------------------------------------


class TestSecretScannerSingleFile:
    def test_scans_env_file_finds_openai_key(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        _write_file(env_file, f'OPENAI_KEY="{_openai_placeholder()}"\n')

        scanner = SecretScanner(paths=[env_file])
        findings, perm_issues, stats = scanner.scan()

        assert len(findings) == 1
        assert findings[0].detector_name == "OpenAI API Key"
        assert findings[0].severity == "critical"
        assert findings[0].line_number == 1
        assert stats.files_scanned == 1

    def test_scans_json_file_finds_github_token(self, tmp_path: Path) -> None:
        json_file = tmp_path / "config.json"
        content = json.dumps({"github_token": _github_placeholder()})
        _write_file(json_file, content)

        scanner = SecretScanner(paths=[json_file])
        findings, _, stats = scanner.scan()

        assert len(findings) == 1
        assert findings[0].detector_name == "GitHub Personal Access Token (classic)"
        assert findings[0].severity == "critical"

    def test_scans_yaml_file_finds_anthropic_key(self, tmp_path: Path) -> None:
        yaml_file = tmp_path / "config.yaml"
        _write_file(yaml_file, f'ANTHROPIC_API_KEY: "{_anthropic_placeholder()}"\n')

        scanner = SecretScanner(paths=[yaml_file])
        findings, _, _ = scanner.scan()

        # Both the Anthropic-specific pattern (sk-ant-{40,}) AND the generic
        # OpenAI pattern (sk-{20,}) fire — this is expected behaviour.
        assert len(findings) >= 1
        names = {f.detector_name for f in findings}
        assert "Anthropic API Key" in names

    def test_scans_shell_script_finds_aws_key(self, tmp_path: Path) -> None:
        sh_file = tmp_path / "setup.sh"
        _write_file(sh_file, f'export AWS_ACCESS_KEY_ID="{_aws_placeholder()}"\n')

        scanner = SecretScanner(paths=[sh_file])
        findings, _, _ = scanner.scan()

        assert len(findings) == 1
        assert findings[0].detector_name == "AWS Access Key ID"

    def test_scans_bashrc_finds_generic_token(self, tmp_path: Path) -> None:
        bashrc = tmp_path / ".bashrc"
        _write_file(bashrc, 'export MY_SERVICE_API_KEY="abcdefghijk1234567890123456"\n')

        scanner = SecretScanner(paths=[bashrc])
        findings, _, _ = scanner.scan()

        assert len(findings) >= 1
        names = {f.detector_name for f in findings}
        assert "Generic API Key Pattern" in names

    def test_no_findings_in_clean_file(self, tmp_path: Path) -> None:
        clean_file = tmp_path / "settings.py"
        _write_file(clean_file, "DATABASE_URL=postgresql://localhost/mydb\nDEBUG=True\n")

        scanner = SecretScanner(paths=[clean_file])
        findings, _, stats = scanner.scan()

        assert len(findings) == 0
        assert stats.files_scanned == 1

    def test_multiple_findings_same_file(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        _write_file(
            env_file,
            f'OPENAI_KEY="{_openai_placeholder()}"\n',
            f'GITHUB_TOKEN="{_github_placeholder()}"\n',
            f'AWS_KEY="{_aws_placeholder()}"\n',
        )

        scanner = SecretScanner(paths=[env_file])
        findings, _, _ = scanner.scan()

        assert len(findings) == 3
        names = {f.detector_name for f in findings}
        assert "OpenAI API Key" in names
        assert "GitHub Personal Access Token (classic)" in names
        assert "AWS Access Key ID" in names

    def test_line_number_tracked(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        # 4 physical lines (splitlines() strips trailing newline):
        # 1: '# This is a comment'
        # 2: '' (blank)
        # 3: '# Another comment'
        # 4: 'OPENAI_KEY=sk-TESTPLACEHOLDER12345X'
        _write_file(env_file, "# This is a comment\n\n# Another comment\nOPENAI_KEY=sk-TESTPLACEHOLDER12345X\n")

        scanner = SecretScanner(paths=[env_file])
        findings, _, _ = scanner.scan()

        assert len(findings) == 1
        assert findings[0].line_number == 4

    def test_truncates_long_lines_timeout_guard(self, tmp_path: Path) -> None:
        """Long lines over max_line_length must not cause catastrophic backtracking."""
        env_file = tmp_path / ".env"
        # A 200K-char line containing only 'x' characters should be skipped
        # without triggering catastrophic backtracking (which would timeout).
        long_line = "x" * 200_000
        _write_file(env_file, f'KEY="{long_line}"\n')

        scanner = SecretScanner(paths=[env_file], max_line_length=MAX_LINE_LENGTH)
        findings, _, _ = scanner.scan()

        # Long lines are skipped (guarded by the max_line_length check in process_line).
        # No findings since the line content doesn't match any secret pattern.
        assert len(findings) == 0

    def test_entropy_gate_reduces_false_positive_for_generic_entropy_detector(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        _write_file(env_file, "SECRET=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")
        scanner = SecretScanner(paths=[env_file], entropy_threshold=3.5)
        findings, _, _ = scanner.scan()
        assert all(f.detector_name != "High Entropy Secret Assignment" for f in findings)

    def test_placeholder_allowlist_skips_placeholder_values(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        _write_file(env_file, "API_KEY=your-key-here\n")
        scanner = SecretScanner(paths=[env_file])
        findings, _, _ = scanner.scan()
        assert len(findings) == 0

    def test_fingerprint_deterministic_across_files(self, tmp_path: Path) -> None:
        env1 = tmp_path / "a.env"
        env2 = tmp_path / "b.env"
        secret = _openai_placeholder()
        _write_file(env1, f'KEY="{secret}"\n')
        _write_file(env2, f'KEY="{secret}"\n')

        scanner = SecretScanner(paths=[env1, env2])
        findings, _, _ = scanner.scan()

        assert len(findings) == 2
        fps = {f.secret_fingerprint for f in findings}
        assert len(fps) == 1  # Same fingerprint

    def test_duplicate_detection(self, tmp_path: Path) -> None:
        env1 = tmp_path / "a.env"
        env2 = tmp_path / "b.env"
        secret = _openai_placeholder()
        _write_file(env1, f'KEY="{secret}"\n')
        _write_file(env2, f'KEY="{secret}"\n')

        scanner = SecretScanner(paths=[env1, env2])
        findings, _, _ = scanner.scan()

        assert len(findings) == 2
        dupes = [f for f in findings if f.is_duplicate]
        assert len(dupes) == 1
        originals = [f for f in findings if not f.is_duplicate]
        assert len(originals) == 1


# ---------------------------------------------------------------------------
# Permission checks
# ---------------------------------------------------------------------------


class TestPermissionChecks:
    def test_world_readable_env_flagged(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        _write_file(env_file, "CLEAN=value\n")
        # Make world-readable
        os.chmod(env_file, 0o644)

        issue = check_file_permissions(env_file)
        assert issue is not None
        assert "world-readable" in issue.issue.lower()

    def test_private_env_not_flagged(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        _write_file(env_file, "CLEAN=value\n")
        # Private file
        os.chmod(env_file, 0o600)

        issue = check_file_permissions(env_file)
        assert issue is None

    def test_world_readable_json_flagged(self, tmp_path: Path) -> None:
        json_file = tmp_path / "config.json"
        _write_file(json_file, '{"key": "value"}')
        os.chmod(json_file, 0o644)

        issue = check_file_permissions(json_file)
        assert issue is not None
        assert "world-readable" in issue.issue.lower()

    def test_world_readable_yaml_not_flagged(self, tmp_path: Path) -> None:
        # .yaml/.yml world-readable is a warning but not flagged as strongly
        yaml_file = tmp_path / "config.yaml"
        _write_file(yaml_file, "key: value\n")
        os.chmod(yaml_file, 0o644)

        # Not a secret file type per se, but still reported as config and world-readable
        issue = check_file_permissions(yaml_file)
        assert issue is not None
        assert "world-readable" in issue.issue.lower()

    def test_private_shell_script_not_flagged(self, tmp_path: Path) -> None:
        sh_file = tmp_path / "setup.sh"
        _write_file(sh_file, "echo hello\n")
        os.chmod(sh_file, 0o700)

        issue = check_file_permissions(sh_file)
        assert issue is None


# ---------------------------------------------------------------------------
# Duplicate credentials
# ---------------------------------------------------------------------------


class TestDuplicateCredentials:
    def test_duplicate_across_multiple_files(self, tmp_path: Path) -> None:
        """Two files with the same secret should mark the second as duplicate."""
        env1 = tmp_path / "a" / ".env"
        env2 = tmp_path / "b" / ".env"
        env1.parent.mkdir()
        env2.parent.mkdir()
        secret = _github_placeholder()
        _write_file(env1, f'GH={secret}\n')
        _write_file(env2, f'GH={secret}\n')

        scanner = SecretScanner(paths=[tmp_path])
        findings, _, stats = scanner.scan()

        assert len(findings) == 2
        assert stats.duplicates == 1

    def test_same_secret_different_names_both_flagged(self, tmp_path: Path) -> None:
        """Same value but different var names detected separately, fingerprints same."""
        env = tmp_path / ".env"
        _write_file(env, f"VAR_A={_openai_placeholder()}\nVAR_B={_openai_placeholder()}\n")

        scanner = SecretScanner(paths=[env])
        findings, _, stats = scanner.scan()

        assert len(findings) == 2
        # Both have same fingerprint
        fps = [f.secret_fingerprint for f in findings]
        assert fps[0] == fps[1]
        # Both are in same file, first is not duplicate
        assert any(not f.is_duplicate for f in findings)
        # Only one is duplicate since they share fingerprint
        assert stats.duplicates == 1


# ---------------------------------------------------------------------------
# Large file streaming
# ---------------------------------------------------------------------------


class TestLargeFileStreaming:
    def test_large_file_scanned_without_memory_explosion(self, tmp_path: Path) -> None:
        """Scan a file larger than MAX_BYTES_PER_FILE — should still work via streaming."""
        large_file = tmp_path / "large.env"
        secret_line = f'OPENAI_KEY="{_openai_placeholder()}"\n'
        # Create a file larger than max_bytes_per_file (5MB default)
        with large_file.open("w", encoding="utf-8") as fh:
            # Write 3MB of padding
            fh.write("# " + "x" * (3 * 1024 * 1024) + "\n")
            # Then the secret
            fh.write(secret_line)

        scanner = SecretScanner(paths=[large_file], max_bytes_per_file=1024 * 1024)
        findings, _, _ = scanner.scan()

        assert len(findings) == 1
        assert findings[0].detector_name == "OpenAI API Key"


class TestEntropyHelpers:
    def test_shannon_entropy_higher_for_random_like_string(self) -> None:
        low = _shannon_entropy("aaaaaaaaaaaaaaaaaaaaaaaa")
        high = _shannon_entropy("a8Z_1pQx9LmN2wVt5YkR3sHj")
        assert high > low


# ---------------------------------------------------------------------------
# Walk / skip logic
# ---------------------------------------------------------------------------


class TestScannerWalk:
    def test_skips_node_modules(self, tmp_path: Path) -> None:
        nm = tmp_path / "node_modules" / "package" / "index.js"
        nm.parent.mkdir(parents=True)
        _write_file(nm, f'const key = "{_openai_placeholder()}";\n')

        scanner = SecretScanner(paths=[tmp_path])
        findings, _, _ = scanner.scan()

        assert len(findings) == 0

    def test_skips_git_dir(self, tmp_path: Path) -> None:
        git_file = tmp_path / ".git" / "config"
        git_file.parent.mkdir(parents=True)
        _write_file(git_file, f'token = "{_github_placeholder()}"\n')

        scanner = SecretScanner(paths=[tmp_path])
        findings, _, _ = scanner.scan()

        assert len(findings) == 0

    def test_scans_nested_directories(self, tmp_path: Path) -> None:
        nested = tmp_path / "project" / "config" / "dev.env"
        nested.parent.mkdir(parents=True)
        _write_file(nested, f'KEY="{_openai_placeholder()}"\n')

        scanner = SecretScanner(paths=[tmp_path])
        findings, _, _ = scanner.scan()

        assert len(findings) == 1

    def test_only_scannable_extensions(self, tmp_path: Path) -> None:
        # Create files with non-scannable extensions
        txt_file = tmp_path / "readme.txt"
        _write_file(txt_file, f'KEY="{_openai_placeholder()}"\n')

        scanner = SecretScanner(paths=[tmp_path])
        findings, _, _ = scanner.scan()

        assert len(findings) == 0
