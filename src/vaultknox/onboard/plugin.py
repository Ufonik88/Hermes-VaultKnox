"""VaultKnox Onboard — Hermes gateway plugin for autonomous repository onboarding.

Registers a ``pre_llm_call`` hook that injects VaultKnox Onboard capability
guidance so the agent knows the ``hermes-vault onboard`` pipeline exists.

Note
----
Earlier versions also attempted a ``pre_gateway_dispatch`` hook returning
``{"action": "onboard_repo"}``. The Hermes gateway consumes only ``rewrite``
results from that hook, so the action was silently dropped and the hook was
removed (dead code). Onboarding detection is delivered through the injected
prompt guidance instead.
"""

from __future__ import annotations

from typing import Any

_SNIPPET_MARKER = "### Repository Onboarding"

_SNIPPET = (
    "### Repository Onboarding\n\n"
    "Use `hermes-vault onboard analyze <repo>` to detect languages, frameworks, and dependencies.\n"
    "Use `hermes-vault onboard document <repo>` to generate AGENTS.md, README.md, SETUP.md.\n"
    "Use `hermes-vault onboard setup <repo>` to install deps and verify the build.\n"
    "Use `hermes-vault onboard full <repo>` for the complete pipeline."
)


def on_pre_llm_call(
    session_id: str = "",
    user_message: str = "",
    conversation_history: Any = None,
    **kwargs: Any,
) -> dict[str, Any] | None:
    """Inject VaultKnox Onboard capability guidance (once per conversation).

    Hermes consumes ``{"context": <str>}`` from pre_llm_call results.
    """
    if conversation_history:
        for msg in conversation_history:
            content = msg.get("content", "") if isinstance(msg, dict) else getattr(msg, "content", "")
            if isinstance(content, str) and _SNIPPET_MARKER in content:
                return None
    return {"context": _SNIPPET}


def register(ctx: Any) -> None:
    """Register plugin hooks with Hermes."""
    ctx.register_hook("pre_llm_call", on_pre_llm_call)
