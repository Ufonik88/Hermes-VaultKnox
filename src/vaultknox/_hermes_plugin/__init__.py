"""VaultKnox — secret-guard plugin for Hermes Agent.

A self-contained Hermes plugin that protects chat surfaces from secret
leaks. It registers three hooks and one (conditionally available) tool:

``pre_gateway_dispatch``
    Scans INBOUND user messages for API keys, tokens, and passwords using
    the bundled VaultKnox detector registry and rewrites the message with
    a security notice + redacted content BEFORE it reaches session
    storage, the agent, or any persistence layer.

``pre_llm_call``
    Injects safe secret-handling rules into the per-turn context so the
    agent never asks a user to paste a secret in chat (the most common
    real-world leak path).

``transform_llm_output``
    Scans OUTBOUND assistant responses with the same 28-pattern VALUE
    detector registry used inbound and redacts any API key, token, or
    password found there (so a secret echoed by the model never reaches
    the user), then rewrites phrases that ask the user to share a secret
    with safe CLI guidance before delivery.

``vaultknox`` (tool, when the vaultknox package is importable)
    Read-only-first vault operations: masked references, one-time tokens,
    and secret scanning. Write actions require ``allow_write``.

Design notes
------------
- Stdlib-only at import time so the admission capability probe (a bare
  subprocess) and any Hermes install can load it; the optional ``vaultknox``
  package is imported lazily inside the tool handler only.
- ``detectors.py`` is vendored byte-for-byte from ``vaultknox.detectors``
  and the hook copy (outbound patterns, rewrite text, system prompt
  snippet) is kept byte-equal to the package's ``vaultknox.hooks.secret_guard``
  and ``vaultknox.agent_guide.prompts`` counterparts — both enforced by
  ``tests/test_hermes_plugin_sync.py``.
- Hook contracts match Hermes >=0.19: ``pre_gateway_dispatch`` receives
  ``event=`` and returns ``{"action": "rewrite", "text": ...}``;
  ``pre_llm_call`` returns ``{"context": ...}``; ``transform_llm_output``
  returns a replacement string.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from typing import Any

from .detectors import DETECTORS

logger = logging.getLogger(__name__)

_REDACT_REPLACEMENT = "[REDACTED-SENSITIVE-VALUE]"

# First line of the injected snippet; used to detect that the snippet is
# already present in the conversation (pre_llm_call dedupe).
_SNIPPET_MARKER = "## VaultKnox — Secret Management"

_WARNING_PREFIX = (
    "⚠️ **Security Notice:** Your message contained what looks like an API key, "
    "token, or password. It has been redacted before storage. Please rotate that "
    "key immediately and store the new one securely:\n"
    "  hermes-vault add --id <id> --type api_key --label \"<description>\" "
    "--data '{\"value\":\"<key>\"}'\n\n"
    "Your original message (without the secret) has been processed below:\n"
)

# ---------------------------------------------------------------------------
# Outbound detection patterns — phrases that indicate the assistant is asking
# the user to share a secret in chat. Kept byte-equal to
# vaultknox.hooks.secret_guard.OUTBOUND_PATTERNS by the sync test.
# ---------------------------------------------------------------------------

OUTBOUND_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"drop\s+(your|the|it)\s+(api\s+)?key", re.IGNORECASE),
    re.compile(r"paste\s+(your|the|it)\s+(api\s+)?key", re.IGNORECASE),
    re.compile(r"send\s+me\s+(your|the|it)\s+(api\s+)?key", re.IGNORECASE),
    re.compile(r"provide\s+your\s+(api\s+)?key", re.IGNORECASE),
    re.compile(r"share\s+your\s+(secret|key|token|password)", re.IGNORECASE),
    re.compile(r"give\s+me\s+your\s+(api\s+)?key", re.IGNORECASE),
    re.compile(r"enter\s+your\s+(password|secret|token)", re.IGNORECASE),
    re.compile(r"throw\s+(it|the\s+key|your\s+key)\s+(here|over)", re.IGNORECASE),
    re.compile(r"drop\s+it\s+here", re.IGNORECASE),
    re.compile(r"paste\s+it\s+here", re.IGNORECASE),
    re.compile(r"send\s+it\s+(over|here)", re.IGNORECASE),
    re.compile(r"your\s+(api\s+)?key\s+(here|in\s+chat|in\s+the\s+chat)", re.IGNORECASE),
]

# Kept byte-equal to vaultknox.hooks.secret_guard.OUTBOUND_REWRITE.
OUTBOUND_REWRITE = (
    "⚠️ **Security Notice:** I should not ask you to share secrets in chat. "
    "To securely store your API key, use:\n"
    "```\n"
    "hermes-vault add --id <id> --type api_key --label \"<description>\" "
    "--data '{\"value\":\"<key>\"}'\n"
    "```"
)

# ---------------------------------------------------------------------------
# Rules injected via pre_llm_call. Kept byte-equal to
# vaultknox.agent_guide.prompts.get_system_prompt_snippet().
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT_SNIPPET = """
## VaultKnox — Secret Management

When interacting with users about credentials or API keys:

1. **NEVER ask a user to paste a secret in chat.** If a user pastes what looks like an API key, token, or password, immediately warn them and redact it.

2. **To store a secret safely**, guide the user to:
   ```bash
   hermes-vault add --id <id> --type api_key --label "<description>" --data '{"value":"<the-secret>"}'
   ```
   This bypasses chat entirely and encrypts the secret immediately.

3. **To retrieve a secret** for an API call, use the VaultKnox tool:
   ```python
   vaultknox(action="get_masked", secret_id="<id>", purpose="<why>")
   ```
   This returns metadata + a one-time token. The actual secret is never exposed to the agent's context window.

4. **For automated scripts and cron jobs**, use the Autonomous Secrets Store:
   ```python
   from vaultknox import AutonomousSecretsStore
   store = AutonomousSecretsStore()
   api_key = store.get("MY_API_KEY")
   ```
   This requires no password and is designed for unattended automation.

5. **If you detect a secret in chat**, immediately:
   - Warn the user
   - Do not echo the secret back
   - Suggest rotation if it was a real key
   - Offer to help store it safely via `hermes-vault add`
""".strip()


def _fingerprint(value: str) -> str:
    """Unsalted SHA-256 fingerprint of a matched value — safe to log, never the raw secret.

    Unsalted on purpose: it only has to prove "this exact value appeared", so
    it must be reproducible. It does NOT hide a low-entropy match (a password
    pattern is dictionary-recoverable from the digest), so treat it as an
    identifier, not as anonymisation.
    """
    return hashlib.sha256(value.encode("utf-8"), usedforsecurity=True).hexdigest()


def _merge_spans(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Merge overlapping/nested spans so multi-detector matches redact cleanly."""
    if not spans:
        return []
    ordered = sorted(spans, key=lambda s: s[0])
    merged = [ordered[0]]
    for start, end in ordered[1:]:
        if start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def _scan_and_redact(text: str) -> tuple[str, list[dict[str, Any]]]:
    """Scan text for secrets; return (redacted_text, findings).

    Findings carry detector name, severity, span, and an unsalted SHA-256
    fingerprint — never the raw matched value. The unsalted digest identifies
    a value that already appeared; it does not hide a guessable one.
    """
    findings: list[dict[str, Any]] = []
    for detector in DETECTORS:
        for match in detector.pattern.finditer(text):
            findings.append({
                "detector": detector.name,
                "severity": detector.severity,
                "fingerprint": _fingerprint(match.group(0)),
                "span": match.span(),
            })

    if not findings:
        return text, []

    spans = _merge_spans([f["span"] for f in findings])
    redacted = text
    for start, end in reversed(spans):
        redacted = redacted[:start] + _REDACT_REPLACEMENT + redacted[end:]
    return redacted, findings


def _scan_outbound(text: str) -> list[re.Match[str]]:
    """Scan assistant response text for phrases that ask users for secrets."""
    if not text or not isinstance(text, str):
        return []
    matches: list[re.Match[str]] = []
    for pattern in OUTBOUND_PATTERNS:
        matches.extend(pattern.finditer(text))
    return matches


def _rewrite_outbound(text: str, matches: list[re.Match[str]]) -> str:
    """Replace outbound secret-requesting phrases with safe guidance."""
    if not matches:
        return text
    spans = _merge_spans([(m.start(), m.end()) for m in matches])
    result = text
    for start, end in reversed(spans):
        result = result[:start] + OUTBOUND_REWRITE + result[end:]
    return result


# ---------------------------------------------------------------------------
# Hook: pre_gateway_dispatch — redact inbound secrets before persistence
# ---------------------------------------------------------------------------

def on_pre_gateway_dispatch(event: Any = None, gateway: Any = None, session_store: Any = None, **kwargs: Any) -> dict[str, Any] | None:
    """Scan the inbound MessageEvent; rewrite the text when secrets are found.

    Hermes fires this hook as ``invoke_hook("pre_gateway_dispatch", event=…,
    gateway=…, session_store=…)`` before auth/session/agent/persistence.
    """
    text = getattr(event, "text", None)
    if not isinstance(text, str) or not text:
        return None

    redacted, findings = _scan_and_redact(text)
    if not findings:
        return None

    logger.info(
        "VaultKnox secret-guard: redacted %d secret(s) from inbound message (%s)",
        len(findings),
        ", ".join(sorted({str(f["detector"]) for f in findings})),
    )
    return {"action": "rewrite", "text": _WARNING_PREFIX + redacted}


# ---------------------------------------------------------------------------
# Hook: pre_llm_call — inject safe secret-handling rules into turn context
# ---------------------------------------------------------------------------

def _history_contains_snippet(conversation_history: Any) -> bool:
    if not conversation_history:
        return False
    for msg in conversation_history:
        try:
            content = msg.get("content", "") if isinstance(msg, dict) else getattr(msg, "content", "")
        except Exception:
            continue
        if isinstance(content, str) and _SNIPPET_MARKER in content:
            return True
        if isinstance(content, list):
            for part in content:
                part_text = part.get("text") if isinstance(part, dict) else None
                if isinstance(part_text, str) and _SNIPPET_MARKER in part_text:
                    return True
    return False


def on_pre_llm_call(session_id: str = "", user_message: str = "", conversation_history: Any = None, **kwargs: Any) -> dict[str, Any] | None:
    """Inject VaultKnox secret-handling rules, once per conversation.

    Hermes consumes ``{"context": <str>}`` and injects it into the user
    message for the turn; anything else is ignored.
    """
    if _history_contains_snippet(conversation_history):
        return None
    return {"context": _SYSTEM_PROMPT_SNIPPET}


# ---------------------------------------------------------------------------
# Hook: transform_llm_output — rewrite secret-requesting responses outbound
# ---------------------------------------------------------------------------

def on_transform_llm_output(response_text: str = "", **kwargs: Any) -> str | None:
    """Redact secret values from, and rewrite secret requests in, assistant replies.

    Two passes, in this order:

    1. **Value redaction** — the 28-pattern detector registry (the same one
       used on inbound messages) runs over the outgoing text, so an API key,
       token, or password the model echoed back is replaced with
       ``[REDACTED-SENSITIVE-VALUE]`` before the user sees it.
    2. **Solicitation rewrite** — phrases that ask the user to share a secret
       are replaced with safe CLI guidance. Matches are computed on the
       *redacted* text so every span index stays valid.

    Hermes fires ``transform_llm_output`` after the tool loop; the first
    hook returning a non-empty string replaces the response. Returns
    ``None`` when nothing matched, leaving the response untouched.
    """
    if not isinstance(response_text, str) or not response_text:
        return None

    redacted, findings = _scan_and_redact(response_text)
    if findings:
        logger.info(
            "VaultKnox secret-guard: outbound — redacted %d secret value(s) (%s)",
            len(findings),
            ", ".join(sorted({str(f["detector"]) for f in findings})),
        )

    matches = _scan_outbound(redacted)
    if not matches:
        if not findings:
            return None
        return redacted

    logger.info(
        "VaultKnox secret-guard: outbound — rewrote %d secret-requesting phrase(s)",
        len(matches),
    )
    return _rewrite_outbound(redacted, matches)


# ---------------------------------------------------------------------------
# Tool: vaultknox — vault operations when the vaultknox package is installed
# ---------------------------------------------------------------------------

_VAULTKNOX_TOOL_SCHEMA = {
    "name": "vaultknox",
    "description": (
        "Encrypted secrets vault operations (VaultKnox). Read actions return masked "
        "references or issue short-lived single-use tokens without exposing plaintext "
        "to the model, with one deliberate exception: consume_token exchanges a "
        "one-time token for the plaintext value and only runs when the operator's "
        "vault policy grants raw secret access. Write actions require allow_write=true. "
        "The vault must be unlocked by the operator; the session key is used automatically."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": [
                    "status", "list", "get_masked", "get_token", "consume_token",
                    "scan_text", "lock", "add", "update", "delete", "inject_env", "revoke_token",
                ],
                "description": (
                    "Vault action. Read: status, list, get_masked, get_token, consume_token, "
                    "scan_text. Write (require allow_write): add, update, delete, inject_env, revoke_token."
                ),
            },
            "secret_id": {"type": "string", "description": "Secret identifier, e.g. OPENAI_API_KEY."},
            "secret_type": {"type": "string", "description": "Secret type, e.g. api_key, token, password, note."},
            "label": {"type": "string", "description": "Human-readable label for add/update."},
            "payload": {"type": "object", "description": "Secret payload for add/update, e.g. {\"value\": \"...\"}."},
            "purpose": {"type": "string", "description": "Why the secret is requested (audit trail)."},
            "token": {"type": "string", "description": "One-time token for consume_token / revoke_token."},
            "text": {"type": "string", "description": "Text to scan for secrets (scan_text action)."},
            "env_var": {"type": "string", "description": "Environment variable name for inject_env."},
            "token_ttl_seconds": {"type": "integer", "description": "Requested token lifetime (TTL is clamped by policy)."},
            "agent_id": {"type": "string", "description": "Agent identity for policy checks."},
            "runtime_dir": {"type": "string", "description": "Vault runtime directory override."},
            "allow_write": {"type": "boolean", "description": "Explicitly allow write actions (default false)."},
        },
        "required": ["action"],
    },
}


def _check_vaultknox_available() -> bool:
    """check_fn: expose the tool only when the vaultknox package is importable."""
    try:
        from importlib.util import find_spec

        return find_spec("vaultknox") is not None
    except Exception:
        return False


def _handle_vaultknox(args: dict[str, Any], **kwargs: Any) -> str:
    """Tool handler: dispatch to vaultknox.hermes_tool.vault_tool, lazily imported."""
    args = args if isinstance(args, dict) else {}
    action = str(args.get("action") or "").strip()
    try:
        from vaultknox.hermes_tool import vault_tool
    except ImportError:
        return json.dumps({
            "error": "vaultknox_not_installed",
            "message": (
                "The vaultknox package is not installed in this Hermes environment. "
                "Install it from https://github.com/Ufonik88/Hermes-VaultKnox to use "
                "vault operations."
            ),
        })
    try:
        result = vault_tool(action=action, **{k: v for k, v in args.items() if k != "action"})
    except Exception as exc:  # surface vault errors as tool output, never crash the loop
        return json.dumps({"error": type(exc).__name__, "message": str(exc)})
    return json.dumps(result, indent=2, default=str)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def register(ctx: Any) -> None:
    """Register the secret-guard hooks and the vaultknox tool."""
    ctx.register_hook("pre_gateway_dispatch", on_pre_gateway_dispatch)
    ctx.register_hook("pre_llm_call", on_pre_llm_call)
    ctx.register_hook("transform_llm_output", on_transform_llm_output)
    ctx.register_tool(
        name="vaultknox",
        toolset="vaultknox",
        schema=_VAULTKNOX_TOOL_SCHEMA,
        handler=_handle_vaultknox,
        check_fn=_check_vaultknox_available,
        description="Encrypted secrets vault operations (VaultKnox)",
        emoji="🔐",
    )
    logger.info(
        "VaultKnox plugin registered (hooks: pre_gateway_dispatch, pre_llm_call, "
        "transform_llm_output; tool: vaultknox)"
    )
