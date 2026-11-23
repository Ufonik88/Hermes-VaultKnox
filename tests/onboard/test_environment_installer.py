"""Tests for vaultknox.onboard.environment.installer — manifest→command selection.

The installer's job is choosing WHICH install command each detected ecosystem
needs; running commands safely is SandboxExecutor's job (covered by the
executor's own tests). These tests substitute a recording executor so every
branch of the selection logic is pinned without spawning real processes.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from vaultknox.onboard.analyzer.engine import AnalysisReport
from vaultknox.onboard.config import OnboardConfig
from vaultknox.onboard.environment import installer
from vaultknox.onboard.sandbox.executor import SandboxResult


class RecordingExecutor:
    """Stands in for SandboxExecutor: records calls, runs nothing."""

    def __init__(self, repo_path: Path, *args: Any, **kwargs: Any) -> None:
        self.repo_path = repo_path
        self.allowed_commands = kwargs.get("allowed_commands")
        self.default_timeout = kwargs.get("default_timeout")
        self.runs: list[dict[str, Any]] = []
        self.retries: list[dict[str, Any]] = []

    def run(self, command: str, *, timeout: int | None = None, **kwargs: Any) -> SandboxResult:
        self.runs.append({"command": command, "timeout": timeout, "kwargs": kwargs})
        return SandboxResult(success=True, stdout="", stderr="", return_code=0, command=command, duration_seconds=0.0)

    def run_with_retry(self, command: str, retries: int = 0, **kwargs: Any) -> SandboxResult:
        self.retries.append({"command": command, "retries": retries, "kwargs": kwargs})
        return SandboxResult(success=True, stdout="", stderr="", return_code=0, command=command, duration_seconds=0.0)


@pytest.fixture
def executors(monkeypatch: pytest.MonkeyPatch) -> list[RecordingExecutor]:
    """Patch installer.SandboxExecutor; yield every instance it constructed."""
    created: list[RecordingExecutor] = []

    def factory(repo_path: Path, *args: Any, **kwargs: Any) -> RecordingExecutor:
        executor = RecordingExecutor(repo_path, *args, **kwargs)
        created.append(executor)
        return executor

    monkeypatch.setattr(installer, "SandboxExecutor", factory)
    return created


def make_report(repo: Path, dependencies: dict[str, Any]) -> AnalysisReport:
    return AnalysisReport(repo_path=str(repo), repo_name=repo.name, dependencies=dependencies)


class TestInstallDispatch:
    def test_a_report_with_no_ecosystems_runs_nothing(self, tmp_path: Path, executors: list[RecordingExecutor]) -> None:
        results = installer.install_dependencies(make_report(tmp_path, {}), OnboardConfig(repo_path=tmp_path))
        assert results == []
        assert executors[0].runs == []
        assert executors[0].retries == []

    def test_the_executor_is_configured_from_onboard_config(self, tmp_path: Path, executors: list[RecordingExecutor]) -> None:
        allowed = ["pip", "npm"]
        config = OnboardConfig(repo_path=tmp_path, allowed_install_commands=allowed, max_install_timeout_seconds=42)
        installer.install_dependencies(make_report(tmp_path, {}), config)
        executor = executors[0]
        assert executor.repo_path == tmp_path
        assert executor.allowed_commands == allowed
        assert executor.default_timeout == 42

    def test_secondary_ecosystems_dispatch_to_their_fixed_commands(self, tmp_path: Path, executors: list[RecordingExecutor]) -> None:
        report = make_report(tmp_path, {"rust": {}, "go": {}, "ruby": {}, "php": {}})
        results = installer.install_dependencies(report, OnboardConfig(repo_path=tmp_path))
        expected = [
            "cargo fetch",
            "go mod download",
            "bundle install",
            "composer install",
        ]
        assert [r["command"] for r in executors[0].runs] == expected
        assert [r.command for r in results] == expected

    def test_rust_commands_carry_the_configured_timeout(self, tmp_path: Path, executors: list[RecordingExecutor]) -> None:
        config = OnboardConfig(repo_path=tmp_path, max_install_timeout_seconds=42)
        installer.install_dependencies(make_report(tmp_path, {"rust": {}}), config)
        assert executors[0].runs == [{"command": "cargo fetch", "timeout": 42, "kwargs": {}}]

    def test_mixed_node_and_python_results_keep_ecosystem_order(self, tmp_path: Path, executors: list[RecordingExecutor]) -> None:
        (tmp_path / "bun.lockb").write_bytes(b"")
        (tmp_path / "uv.lock").write_text("")
        report = make_report(tmp_path, {"nodejs": {}, "python": {}})
        results = installer.install_dependencies(report, OnboardConfig(repo_path=tmp_path))
        assert [r.command for r in results] == ["bun install", "uv sync"]
        assert [r["command"] for r in executors[0].runs] == ["bun install"]
        assert [r["command"] for r in executors[0].retries] == ["uv sync"]


class TestNodejsCommandSelection:
    def test_bun_lockb_selects_bun_install(self, tmp_path: Path, executors: list[RecordingExecutor]) -> None:
        (tmp_path / "bun.lockb").write_bytes(b"")
        report = make_report(tmp_path, {"nodejs": {}})
        installer.install_dependencies(report, OnboardConfig(repo_path=tmp_path))
        assert [r["command"] for r in executors[0].runs] == ["bun install"]

    def test_pnpm_lock_yaml_selects_pnpm_install(self, tmp_path: Path, executors: list[RecordingExecutor]) -> None:
        (tmp_path / "pnpm-lock.yaml").write_text("")
        report = make_report(tmp_path, {"nodejs": {}})
        installer.install_dependencies(report, OnboardConfig(repo_path=tmp_path))
        assert [r["command"] for r in executors[0].runs] == ["pnpm install"]

    def test_yarn_lock_selects_yarn_install(self, tmp_path: Path, executors: list[RecordingExecutor]) -> None:
        (tmp_path / "yarn.lock").write_text("")
        report = make_report(tmp_path, {"nodejs": {}})
        installer.install_dependencies(report, OnboardConfig(repo_path=tmp_path))
        assert [r["command"] for r in executors[0].runs] == ["yarn install"]

    def test_package_lock_json_selects_npm_ci(self, tmp_path: Path, executors: list[RecordingExecutor]) -> None:
        (tmp_path / "package-lock.json").write_text("{}")
        report = make_report(tmp_path, {"nodejs": {}})
        installer.install_dependencies(report, OnboardConfig(repo_path=tmp_path))
        assert [r["command"] for r in executors[0].runs] == ["npm ci"]

    def test_no_lockfile_with_versioned_package_manager_strips_the_version(self, tmp_path: Path, executors: list[RecordingExecutor]) -> None:
        report = make_report(tmp_path, {"nodejs": {"package_manager": "pnpm@9.1.0"}})
        installer.install_dependencies(report, OnboardConfig(repo_path=tmp_path))
        assert [r["command"] for r in executors[0].runs] == ["pnpm install"]

    def test_no_lockfile_defaults_to_npm_install(self, tmp_path: Path, executors: list[RecordingExecutor]) -> None:
        report = make_report(tmp_path, {"nodejs": {}})
        installer.install_dependencies(report, OnboardConfig(repo_path=tmp_path))
        assert [r["command"] for r in executors[0].runs] == ["npm install"]


class TestPythonCommandSelection:
    def test_uv_lock_selects_uv_sync_with_one_retry(self, tmp_path: Path, executors: list[RecordingExecutor]) -> None:
        (tmp_path / "uv.lock").write_text("")
        report = make_report(tmp_path, {"python": {}})
        installer.install_dependencies(report, OnboardConfig(repo_path=tmp_path))
        assert executors[0].runs == []
        assert executors[0].retries == [{"command": "uv sync", "retries": 1, "kwargs": {}}]

    def test_poetry_lock_selects_poetry_install(self, tmp_path: Path, executors: list[RecordingExecutor]) -> None:
        (tmp_path / "poetry.lock").write_text("")
        report = make_report(tmp_path, {"python": {}})
        installer.install_dependencies(report, OnboardConfig(repo_path=tmp_path))
        assert [r["command"] for r in executors[0].runs] == ["poetry install"]

    def test_pipfile_lock_selects_pipenv_install_dev(self, tmp_path: Path, executors: list[RecordingExecutor]) -> None:
        (tmp_path / "Pipfile.lock").write_text("{}")
        report = make_report(tmp_path, {"python": {}})
        installer.install_dependencies(report, OnboardConfig(repo_path=tmp_path))
        assert [r["command"] for r in executors[0].runs] == ["pipenv install --dev"]

    def test_pyproject_only_selects_pip_install_editable_dev(self, tmp_path: Path, executors: list[RecordingExecutor]) -> None:
        (tmp_path / "pyproject.toml").write_text("[project]\n")
        report = make_report(tmp_path, {"python": {}})
        installer.install_dependencies(report, OnboardConfig(repo_path=tmp_path))
        assert [r["command"] for r in executors[0].runs] == ["pip install -e .[dev]"]

    def test_requirements_txt_only_selects_pip_install_requirements(self, tmp_path: Path, executors: list[RecordingExecutor]) -> None:
        (tmp_path / "requirements.txt").write_text("click>=8.1.0\n")
        report = make_report(tmp_path, {"python": {}})
        installer.install_dependencies(report, OnboardConfig(repo_path=tmp_path))
        assert [r["command"] for r in executors[0].runs] == ["pip install -r requirements.txt"]

    def test_no_manifest_reports_failure_without_running_anything(self, tmp_path: Path, executors: list[RecordingExecutor]) -> None:
        report = make_report(tmp_path, {"python": {}})
        results = installer.install_dependencies(report, OnboardConfig(repo_path=tmp_path))
        assert executors[0].runs == []
        assert executors[0].retries == []
        assert len(results) == 1
        failure = results[0]
        assert failure.success is False
        assert failure.stderr == "No Python dep manifest found"
        assert failure.return_code == -1
        assert failure.command == "pip"
