from vaultknox.agent_guide import TRIGGERS, check_triggers, get_system_prompt_snippet
from vaultknox.autonomous_secrets import AutonomousSecretsError, AutonomousSecretsStore
from vaultknox.health import VaultHealthChecker
from vaultknox.hermes_tool import vault_tool
from vaultknox.hooks import handle
from vaultknox.rotation import rotate_master_key
from vaultknox.scanner import SecretScanner
from vaultknox.vault import VaultError, VaultKnox
from vaultknox.verifier import CredentialVerifier

__version__ = "0.6.1"

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
]