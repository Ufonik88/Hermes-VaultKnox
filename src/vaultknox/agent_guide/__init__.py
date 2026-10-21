"""VaultKnox Agent Autonomy Package.

Lightweight guidance for AI agents so they automatically know how to use
VaultKnox without the user having to prompt it.

Public-safe — no encryption internals, no file paths, no master password mechanics.
"""

from vaultknox.agent_guide.prompts import get_system_prompt_snippet
from vaultknox.agent_guide.triggers import TRIGGERS, check_triggers

__all__ = [
    "TRIGGERS",
    "check_triggers",
    "get_system_prompt_snippet",
]
