"""Trigger detection for VaultKnox agent autonomy.

Detects when an agent is in a situation where VaultKnox should be used.
Simple keyword + context heuristics — fast, deterministic, auditable.
"""

from __future__ import annotations

TRIGGERS: list[dict] = [
    {
        "id": "user_pastes_secret",
        "description": "User message contains what looks like an API key, token, or password",
        "action": (
            "Warn user not to paste secrets. "
            "Suggest vault-add-key CLI or 'store in vault' workflow."
        ),
        "priority": "critical",
        "keywords": [
            "sk-", "ghp_", "gho_", "ghs_", "ghu_", "ghr_",
            "sk-ant-", "AKIA", "xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-",
            "npm_", "SG.", "sk_live_", "pk_live_",
            "-----BEGIN", "PRIVATE KEY-----",
        ],
    },
    {
        "id": "user_asks_store_key",
        "description": "User explicitly asks to store a credential, API key, or password",
        "action": (
            "Guide user to vault-add-key CLI or offer to store via vault tool. "
            "Never accept the secret value in chat."
        ),
        "priority": "high",
        "keywords": [
            "store my key", "store api key", "store password",
            "save my key", "save api key", "save password",
            "add key to vault", "put key in vault", "vault add",
            "encrypt my key", "secure my key",
        ],
    },
    {
        "id": "agent_needs_api_key",
        "description": "Agent is about to make an API call but no key is in environment",
        "action": (
            "Check vault for key via get_masked. "
            "If not found, ask user to add it — do not ask for the raw secret in chat."
        ),
        "priority": "high",
        "keywords": [
            "api key missing", "no api key", "need api key",
            "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GITHUB_TOKEN",
        ],
    },
    {
        "id": "script_needs_secret",
        "description": "Agent is writing a script that needs credentials",
        "action": (
            "Inject vault-loading pattern (AutonomousSecretsStore or env var). "
            "Never hardcode secrets in generated scripts."
        ),
        "priority": "medium",
        "keywords": [
            "write a script", "generate script", "create script",
            "cron job", "scheduled task", "automation script",
        ],
    },
    {
        "id": "cron_job_needs_auth",
        "description": "Agent is setting up an automated job that needs API authentication",
        "action": (
            "Use AutonomousSecretsStore (key-file-backed, no password needed). "
            "Guide user to store the secret first if not already present."
        ),
        "priority": "medium",
        "keywords": [
            "cron job", "scheduled job", "recurring task",
            "automated api call", "unattended script",
        ],
    },
]


def check_triggers(context: dict) -> list[dict]:
    """Return matched triggers based on simple keyword/context heuristics.

    Args:
        context: A dict with at least a ``text`` key (the message/content to scan).
            Optional keys:
            - ``intent``: str describing what the agent is doing (e.g. "writing_script")
            - ``env_vars``: dict of current environment variables
            - ``has_vault_key``: bool — whether the requested key exists in vault

    Returns:
        A list of trigger dicts that matched, sorted by priority
        (critical first, then high, medium, low).
    """
    text: str = (context.get("text") or "").lower()
    intent: str = (context.get("intent") or "").lower()
    env_vars: dict = context.get("env_vars") or {}
    matched: list[dict] = []

    for trigger in TRIGGERS:
        trigger_id = trigger["id"]
        keywords = [kw.lower() for kw in trigger.get("keywords", [])]

        # Keyword match in text
        text_match = any(kw in text for kw in keywords)

        # Intent match
        intent_match = any(kw in intent for kw in keywords)

        # Environment check for agent_needs_api_key
        env_match = False
        if trigger_id == "agent_needs_api_key":
            env_match = any(
                var.endswith(("_KEY", "_TOKEN", "_SECRET"))
                and not value
                for var, value in env_vars.items()
            )

        # Script check for script_needs_secret
        script_match = False
        if trigger_id == "script_needs_secret":
            script_match = (
                "script" in intent
                or "code" in intent
                or "write" in intent
            ) and any(
                kw in text
                for kw in ("api", "key", "token", "secret", "password", "auth")
            )

        # Cron check for cron_job_needs_auth
        cron_match = False
        if trigger_id == "cron_job_needs_auth":
            cron_match = (
                "cron" in intent
                or "schedule" in intent
                or any(kw in text for kw in ("cron", "schedule", "recurring", "automated"))
            ) and any(
                kw in text
                for kw in ("api", "key", "token", "secret", "auth")
            )

        if text_match or intent_match or env_match or script_match or cron_match:
            matched.append(trigger)

    # Sort by priority
    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    matched.sort(key=lambda t: priority_order.get(t["priority"], 99))
    return matched
