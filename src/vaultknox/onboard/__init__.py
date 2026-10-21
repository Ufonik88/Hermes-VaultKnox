"""Autonomous repository onboarding for VaultKnox — analyze, document, and prepare any repo for Hermes Agent."""

from vaultknox.onboard.analyzer.engine import AnalysisReport, RepoAnalyzer
from vaultknox.onboard.config import OnboardConfig
from vaultknox.onboard.documenter.engine import DocGenerator, DocReport
from vaultknox.onboard.environment.engine import EnvReport, EnvSetup

__all__ = [
    "AnalysisReport",
    "RepoAnalyzer",
    "OnboardConfig",
    "DocGenerator",
    "DocReport",
    "EnvReport",
    "EnvSetup",
]
