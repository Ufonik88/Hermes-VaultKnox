"""Environment setup engine — orchestrates dep installation, build checks, and env detection."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from vaultknox.onboard.analyzer.engine import AnalysisReport
from vaultknox.onboard.config import OnboardConfig
from vaultknox.onboard.environment.build_checker import run_build_checks
from vaultknox.onboard.environment.env_detector import detect_missing_env_vars
from vaultknox.onboard.environment.installer import install_dependencies
from vaultknox.onboard.sandbox.executor import SandboxResult


@dataclass(slots=True)
class EnvReport:
    repo_path: str
    install_results: list[SandboxResult] = field(default_factory=list)
    install_success: bool = False
    build_results: list[SandboxResult] = field(default_factory=list)
    build_success: bool = False
    env_vars: dict[str, Any] = field(default_factory=dict)
    missing_env_vars: list[str] = field(default_factory=list)
    secret_vars_detected: list[str] = field(default_factory=list)
    ready: bool = False
    issues: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def all_deps_installed(self) -> bool:
        return all(r.success for r in self.install_results) if self.install_results else True


class EnvSetup:
    def __init__(self, config: OnboardConfig) -> None:
        self.config = config

    def setup(self, report: AnalysisReport) -> EnvReport:
        env_report = EnvReport(repo_path=str(self.config.repo_path))

        if self.config.install_dependencies and not self.config.dry_run:
            env_report.install_results = install_dependencies(report, self.config)
            env_report.install_success = env_report.all_deps_installed
            if not env_report.install_success:
                for r in env_report.install_results:
                    if not r.success and not r.blocked:
                        env_report.issues.append(f"Dependency installation failed: {r.stderr[:200]}")
        elif self.config.dry_run:
            env_report.issues.append("DRY RUN: Dependencies would be installed")

        if self.config.run_build_checks and not self.config.dry_run:
            env_report.build_results = run_build_checks(report, self.config)
            env_report.build_success = all(r.success for r in env_report.build_results) if env_report.build_results else True
            if not env_report.build_success:
                for r in env_report.build_results:
                    if not r.success:
                        env_report.issues.append(f"Build check failed: {r.stderr[:200]}")
        elif self.config.dry_run:
            env_report.issues.append("DRY RUN: Build checks would be run")

        if self.config.detect_env_vars:
            env_report.env_vars = detect_missing_env_vars(report)
            env_report.missing_env_vars = env_report.env_vars.get("missing_vars", [])
            env_report.secret_vars_detected = env_report.env_vars.get("secret_patterns", [])
            if env_report.missing_env_vars:
                env_report.issues.append(f"Missing environment variables: {', '.join(env_report.missing_env_vars[:5])}")
            if env_report.secret_vars_detected:
                env_report.warnings.append(f"Secrets/credentials required: {', '.join(env_report.secret_vars_detected[:5])}")

        env_report.ready = env_report.install_success and env_report.build_success and not env_report.missing_env_vars
        return env_report
