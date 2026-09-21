"""
CLI regression tests for command paths that previously crashed.

- ``hermes-vault get --mask``: passed the secret id where the password
  argument belongs to ``VaultKnox.get_masked`` and crashed with a TypeError.
- ``hermes-vault health``: referenced a non-existent
  ``CheckSeverity.CRITICAL`` member while rendering the human-readable
  report and crashed after printing the verdict line.

Uses a temporary runtime dir and placeholder data only. No real secrets.
"""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from vaultknox.cli import main

PASSWORD = "cli-test-master-pass-2026"
DEMO_KEY = "sk-demo-cli-000000000001"


def _run(runtime_dir: Path, args: list[str], input_text: str | None = None):
    runner = CliRunner()
    return runner.invoke(
        main,
        ["--runtime-dir", str(runtime_dir), *args],
        input=input_text,
    )


def _init(runtime_dir: Path) -> None:
    result = _run(runtime_dir, ["init", "--no-password-check"], f"{PASSWORD}\n{PASSWORD}\n")
    assert result.exit_code == 0, result.output


def test_get_mask_returns_masked_view(tmp_path: Path) -> None:
    """`get --mask` must prompt for the password and never print plaintext."""
    _init(tmp_path)
    result = _run(
        tmp_path,
        [
            "add",
            "--id",
            "cli_key",
            "--type",
            "api_key",
            "--label",
            "CLI test key",
            "--data",
            '{"key": "sk-demo-cli-000000000001", "service": "example.com", "scope": "read"}',
        ],
        f"{PASSWORD}\n",
    )
    assert result.exit_code == 0, result.output

    result = _run(tmp_path, ["get", "cli_key", "--mask"], f"{PASSWORD}\n")
    assert result.exit_code == 0, result.output
    assert "cli_key" in result.output
    assert DEMO_KEY not in result.output  # the raw value must never leave the vault


def test_health_command_renders_report(tmp_path: Path) -> None:
    """`health` must complete and render its report (0/1/2 exit codes only)."""
    _init(tmp_path)
    result = _run(tmp_path, ["health"])
    assert "Traceback" not in result.output
    assert "Vault Health" in result.output
    assert result.exit_code in (0, 1, 2), result.output


def test_unlock_then_list_flow(tmp_path: Path) -> None:
    """The documented two-step flow: unlock persists a session, list reads it."""
    _init(tmp_path)
    result = _run(
        tmp_path,
        [
            "add",
            "--id",
            "cli_key",
            "--type",
            "api_key",
            "--label",
            "CLI test key",
            "--data",
            '{"key": "sk-demo-cli-000000000001", "service": "example.com", "scope": "read"}',
        ],
        f"{PASSWORD}\n",
    )
    assert result.exit_code == 0, result.output

    result = _run(tmp_path, ["unlock"], f"{PASSWORD}\n")
    assert result.exit_code == 0, result.output

    result = _run(tmp_path, ["list"])
    assert result.exit_code == 0, result.output
    assert "cli_key" in result.output
