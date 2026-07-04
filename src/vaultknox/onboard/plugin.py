"""VaultKnox Onboard — Hermes gateway plugin for autonomous repository onboarding.

This plugin registers hooks that let Hermes detect onboarding requests
and help agents autonomously analyze, document, and set up repositories.
"""

from __future__ import annotations

from typing import Any


def on_pre_gateway_dispatch(**kwargs: Any) -> dict[str, Any] | None:
    """Detect onboarding requests in incoming user messages."""
    text = kwargs.get("user_message") or kwargs.get("content") or kwargs.get("message") or ""
    if not isinstance(text, str):
        return None

    triggers = [
        "onboard", "analyze this repo", "analyze the repo",
        "setup this project", "prepare this codebase",
        "document this repo", "generate agents.md",
        "what does this repo do", "scan this project",
    ]

    if any(t in text.lower() for t in triggers):
        import re
        path_match = re.search(r'(?:/\S+|~/S+|https?://\S+\.git)', text)
        repo_path = path_match.group(0) if path_match else kwargs.get("workspace")
        if repo_path:
            return {"action": "onboard_repo", "repo_path": str(repo_path)}
    return None


def on_pre_llm_call(**kwargs: Any) -> dict[str, Any] | None:
    """Inject VaultKnox Onboard capability guidance into agent context."""
    snippet = (
        "### Repository Onboarding\n\n"
        "Use `hermes-vault onboard analyze <repo>` to detect languages, frameworks, and dependencies.\n"
        "Use `hermes-vault onboard document <repo>` to generate AGENTS.md, README.md, SETUP.md.\n"
        "Use `hermes-vault onboard setup <repo>` to install deps and verify the build.\n"
        "Use `hermes-vault onboard full <repo>` for the complete pipeline."
    )
    history = kwargs.get("conversation_history") or []
    for msg in history:
        content = msg.get("content", "") if isinstance(msg, dict) else getattr(msg, "content", "")
        if snippet in content:
            return None
    system_msg = kwargs.get("system_message") or ""
    if snippet in system_msg:
        return None
    return {"context": snippet}


def register(ctx: Any) -> None:
    """Register plugin hooks with Hermes."""
    for hook_name, callback in [
        ("pre_gateway_dispatch", on_pre_gateway_dispatch),
        ("pre_llm_call", on_pre_llm_call),
    ]:
        if hasattr(ctx, "register_hook"):
            ctx.register_hook(hook_name, callback)
        elif hasattr(ctx, "on"):
            ctx.on(hook_name, callback)
