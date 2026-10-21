"""Build checker — runs diagnostic build/compile commands."""

from __future__ import annotations

from vaultknox.onboard.analyzer.engine import AnalysisReport
from vaultknox.onboard.config import OnboardConfig
from vaultknox.onboard.sandbox.executor import SandboxExecutor, SandboxResult


def run_build_checks(report: AnalysisReport, config: OnboardConfig) -> list[SandboxResult]:
    executor = SandboxExecutor(
        repo_path=config.repo_path,
        allowed_commands=config.allowed_install_commands + [
            "python", "python3", "node", "npm", "npx", "cargo", "go", "make", "bundle", "composer",
        ],
        default_timeout=config.max_build_timeout_seconds,
    )
    results: list[SandboxResult] = []

    if report.has_nodejs:
        scripts = report.dependencies.get("nodejs", {}).get("scripts", {})
        if "build" in scripts: results.append(executor.run("npm run build"))  # noqa: E701
        elif "typecheck" in scripts: results.append(executor.run("npm run typecheck"))  # noqa: E701
        if any("TypeScript" in lang for lang in report.languages):
            results.append(executor.run("npx tsc --noEmit"))

    if report.has_python:
        results.append(executor.run("python --version", timeout=30))

    if report.has_rust:
        results.append(executor.run("cargo check", timeout=config.max_build_timeout_seconds))

    if report.has_go:
        results.append(executor.run("go vet ./...", timeout=config.max_build_timeout_seconds))

    return results
