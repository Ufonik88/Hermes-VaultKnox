"""Secret-Guard hook — redact sensitive values from chat before storage.

Imports the existing VaultKnox detector registry so patterns stay in
one place.  All errors are caught by HookRegistry.emit().

Supports three event types:

``message:received``
    Context key: ``content`` — the full message text.
    Used by the gateway core emitter when available (v0.4.1+).

``agent:start``
    Context key: ``message`` — the message text (may be truncated to
    500 chars by the emitter).  Defense-in-depth for CLI / non-gateway
    paths where ``message:received`` may not fire.

Outbound scanning (v0.4.2)
    ``scan_outbound(text)`` scans AI responses for phrases that ask
    users to paste secrets in chat.  ``rewrite_outbound(text, matches)``
    replaces those phrases with safe guidance.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from vaultknox.detectors import DETECTORS

_REDACT_REPLACEMENT = "[REDACTED-SENSITIVE-VALUE]"

# ---------------------------------------------------------------------------
# Outbound detection patterns — phrases that indicate the AI is asking
# the user to share a secret in chat.
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

OUTBOUND_REWRITE = (
    "⚠️ **Security Notice:** I should not ask you to share secrets in chat. "
    "To securely store your API key, use:\n"
    "```\n"
    "vault-add-key <id> \"<description>\" <key>\n"
    "```"
)


def scan_outbound(text: str) -> list[re.Match[str]]:
    """Scan AI response text for phrases that ask users for secrets.

    Returns a list of regex match objects for any detected patterns.
    """
    if not text or not isinstance(text, str):
        return []
    matches: list[re.Match[str]] = []
    for pattern in OUTBOUND_PATTERNS:
        for m in pattern.finditer(text):
            matches.append(m)
    return matches


def rewrite_outbound(text: str, matches: list[re.Match[str]]) -> str:
    """Replace outbound secret-requesting phrases with safe guidance.

    Merges overlapping spans to avoid duplicate replacement notices.
    """
    if not matches:
        return text

    # Collect all spans, merge overlaps
    spans = sorted([(m.start(), m.end()) for m in matches], key=lambda s: s[0])
    merged = [spans[0]]
    for start, end in spans[1:]:
        if start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))

    # Replace in reverse order so indices stay valid
    result = text
    for start, end in reversed(merged):
        result = result[:start] + OUTBOUND_REWRITE + result[end:]

    return result


# ---------------------------------------------------------------------------
# Inbound hook handler
# ---------------------------------------------------------------------------


def handle(event_type: str, context: dict[str, Any]) -> None:
    """Scan incoming message content for secrets and redact them in-place."""
    # Resolve the text to scan based on event type
    text = _resolve_content(event_type, context)
    if not text or not isinstance(text, str):
        return

    findings: list[dict[str, Any]] = []

    for detector in DETECTORS:
        for match in detector.pattern.finditer(text):
            secret_value = match.group(0)
            findings.append(
                {
                    "detector": detector.name,
                    "severity": detector.severity,
                    "fingerprint": hashlib.sha256(secret_value.encode("utf-8"), usedforsecurity=True).hexdigest(),
                    "span": match.span(),
                }
            )

    if not findings:
        return

    # Merge overlapping/nested spans to avoid corruption during redaction
    spans = sorted([f["span"] for f in findings], key=lambda s: s[0])
    merged = []
    for start, end in spans:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))

    # Redact in-place, sorting reverse-order so span replacements don't
    # shift the indices of earlier matches.
    redacted = text
    for start, end in reversed(merged):
        redacted = redacted[:start] + _REDACT_REPLACEMENT + redacted[end:]

    # Write back to the correct context key
    _write_content(context, event_type, redacted)
    context["_secret_guard_findings"] = findings
    context["_secret_guard_redacted"] = True


def _resolve_content(event_type: str, context: dict[str, Any]) -> str:
    """Extract message text from context for the given event type."""
    if event_type == "message:received":
        return context.get("content", "")
    elif event_type == "agent:start":
        return context.get("message", "")
    return ""


def _write_content(context: dict[str, Any], event_type: str, redacted: str) -> None:
    """Write redacted text back to the correct context key."""
    if event_type == "message:received":
        context["content"] = redacted
    elif event_type == "agent:start":
        context["message"] = redacted
