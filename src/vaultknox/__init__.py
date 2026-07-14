from vaultknox.agent_guide import TRIGGERS, check_triggers, get_system_prompt_snippet
from vaultknox.autonomous_secrets import AutonomousSecretsError, AutonomousSecretsStore
from vaultknox.exceptions import VaultError
from vaultknox.health import VaultHealthChecker
from vaultknox.hermes_tool import vault_tool
from vaultknox.hooks import handle
from vaultknox.onboard.analyzer.engine import AnalysisReport, RepoAnalyzer
from vaultknox.onboard.config import OnboardConfig
from vaultknox.onboard.documenter.engine import DocGenerator, DocReport
from vaultknox.onboard.environment.engine import EnvReport, EnvSetup
from vaultknox.rotation import rotate_master_key
from vaultknox.scanner import SecretScanner
from vaultknox.vault import VaultKnox
from vaultknox.verifier import CredentialVerifier

__version__ = "0.7.3"

__all__ = [
    "VaultKnox",
    "VaultError",
    "vault_tool",
    "AutonomousSecretsStore",
    "AutonomousSecretsError",
    "rotate_master_key",
    "SecretScanner",
    "CredentialVerifier",
    "VaultHealthChecker",
    "TRIGGERS",
    "check_triggers",
    "get_system_prompt_snippet",
    "handle",
    "__version__",
    "AnalysisReport",
    "RepoAnalyzer",
    "OnboardConfig",
    "DocGenerator",
    "DocReport",
    "EnvReport",
    "EnvSetup",
]
