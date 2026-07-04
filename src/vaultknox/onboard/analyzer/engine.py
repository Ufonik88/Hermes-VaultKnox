"""Analyzer engine — orchestrates language, framework, dependency, and structure analysis."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from vaultknox.onboard.analyzer.dependency_parser import parse_all_dependencies
from vaultknox.onboard.analyzer.language_detector import detect_frameworks, detect_languages
from vaultknox.onboard.analyzer.structure_mapper import map_structure
from vaultknox.onboard.config import OnboardConfig


@dataclass(slots=True)
class AnalysisReport:
    """Complete repository analysis report."""

    repo_path: str
    repo_name: str
    languages: dict[str, dict] = field(default_factory=dict)
    primary_language: str = ""
    language_count: int = 0
    frameworks: dict[str, str] = field(default_factory=dict)
    dependencies: dict[str, Any] = field(default_factory=dict)
    structure: dict[str, Any] = field(default_factory=dict)
    entry_points: list[str] = field(default_factory=list)
    test_dirs: list[str] = field(default_factory=list)
    source_dirs: list[str] = field(default_factory=list)
    config_files_scanned: list[str] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def has_nodejs(self) -> bool:
        return "nodejs" in self.dependencies

    @property
    def has_python(self) -> bool:
        return "python" in self.dependencies or "python_requirements" in self.dependencies

    @property
    def has_rust(self) -> bool:
        return "rust" in self.dependencies

    @property
    def has_go(self) -> bool:
        return "go" in self.dependencies

    def to_json(self) -> str:
        from dataclasses import asdict
        return json.dumps(asdict(self), indent=2, default=str)


class RepoAnalyzer:
    """Analyzes a repository to identify languages, frameworks, dependencies, and structure."""

    def __init__(self, config: OnboardConfig) -> None:
        self.config = config
        self._report: AnalysisReport | None = None

    def analyze(self) -> AnalysisReport:
        report = AnalysisReport(
            repo_path=str(self.config.repo_path),
            repo_name=self.config.repo_name,
        )

        if self.config.scan_languages:
            report.languages = detect_languages(self.config.repo_path)
            if report.languages:
                report.primary_language = next(iter(report.languages))
                report.language_count = len(report.languages)
            else:
                report.warnings.append("No programming languages detected in repository")

        if self.config.scan_frameworks:
            report.frameworks = detect_frameworks(self.config.repo_path)

        if self.config.scan_dependencies:
            report.dependencies = parse_all_dependencies(self.config.repo_path)
            report.config_files_scanned = list(report.dependencies.keys())

        if self.config.scan_structure:
            structure = map_structure(self.config.repo_path)
            report.structure = structure
            report.entry_points = structure.get("entry_points", [])
            report.test_dirs = structure.get("test_dirs", [])
            report.source_dirs = structure.get("source_dirs", [])

        self._detect_issues(report)
        self._report = report
        if not self.config.dry_run:
            self._save_cache(report)
        return report

    def _detect_issues(self, report: AnalysisReport) -> None:
        if not report.entry_points and report.structure.get("stats", {}).get("total_files", 0) > 5:
            report.warnings.append("No clear entry points detected (main.py, index.js, etc.)")
        if not report.test_dirs:
            report.issues.append("No test directory found (tests/, test/, __tests__/)")
        if not report.config_files_scanned:
            report.issues.append("No recognized dependency manifest files found")
        doc_files = report.structure.get("doc_files", [])
        readme_found = any("readme" in f.lower() or "README" in f for f in doc_files)
        if not readme_found:
            report.issues.append("No README found")

    def get_report(self) -> AnalysisReport:
        if self._report is None:
            return self.analyze()
        return self._report

    def _save_cache(self, report: AnalysisReport) -> None:
        cache_dir = self.config.cache_dir
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_file = cache_dir / "analysis.json"
        try:
            cache_file.write_text(report.to_json(), encoding="utf-8")
        except OSError:
            pass
