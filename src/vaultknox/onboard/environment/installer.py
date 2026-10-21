"""Dependency installer — uses detected package manager to install dependencies."""

from __future__ import annotations

from pathlib import Path

from vaultknox.onboard.analyzer.engine import AnalysisReport
from vaultknox.onboard.config import OnboardConfig
from vaultknox.onboard.sandbox.executor import SandboxExecutor, SandboxResult


def install_dependencies(report: AnalysisReport, config: OnboardConfig) -> list[SandboxResult]:
    executor = SandboxExecutor(
        repo_path=config.repo_path,
        allowed_commands=config.allowed_install_commands,
        default_timeout=config.max_install_timeout_seconds,
    )
    results: list[SandboxResult] = []

    if report.has_nodejs:
        results.append(_install_nodejs(report, executor))
    if report.has_python:
        results.append(_install_python(report, executor))
    if report.has_rust:
        results.append(executor.run("cargo fetch", timeout=config.max_install_timeout_seconds))
    if report.has_go:
        results.append(executor.run("go mod download", timeout=config.max_install_timeout_seconds))
    if "ruby" in report.dependencies:
        results.append(executor.run("bundle install", timeout=config.max_install_timeout_seconds))
    if "php" in report.dependencies:
        results.append(executor.run("composer install", timeout=config.max_install_timeout_seconds))

    return results


def _install_nodejs(report: AnalysisReport, executor: SandboxExecutor) -> SandboxResult:
    repo_path = Path(report.repo_path)
    if (repo_path / "bun.lockb").exists():
        return executor.run("bun install")
    elif (repo_path / "pnpm-lock.yaml").exists():
        return executor.run("pnpm install")
    elif (repo_path / "yarn.lock").exists():
        return executor.run("yarn install")
    elif (repo_path / "package-lock.json").exists():
        return executor.run("npm ci")
    else:
        pkg = report.dependencies.get("nodejs", {}).get("package_manager", "npm")
        return executor.run(f"{pkg.split('@')[0] if '@' in pkg else pkg} install")


def _install_python(report: AnalysisReport, executor: SandboxExecutor) -> SandboxResult:
    repo_path = Path(report.repo_path)
    if (repo_path / "uv.lock").exists():
        return executor.run_with_retry("uv sync", retries=1)
    elif (repo_path / "poetry.lock").exists():
        return executor.run("poetry install")
    elif (repo_path / "Pipfile.lock").exists():
        return executor.run("pipenv install --dev")
    elif (repo_path / "pyproject.toml").exists():
        return executor.run("pip install -e .[dev]")
    elif (repo_path / "requirements.txt").exists():
        return executor.run("pip install -r requirements.txt")
    return SandboxResult(success=False, stdout="", stderr="No Python dep manifest found",
                         return_code=-1, command="pip", duration_seconds=0.0)
