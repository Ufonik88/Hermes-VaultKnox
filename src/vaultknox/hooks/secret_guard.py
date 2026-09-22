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

Outbound scanning (v0.4.2, extended in v0.8.1)
    ``scan_and_redact(text)`` runs the full 28-pattern detector registry
    over arbitrary text and returns ``(redacted_text, findings)``.
    ``scan_outbound(text)`` scans AI responses for phrases that ask users
    to paste secrets in chat, and ``rewrite_outbound(text, matches)``
    replaces those phrases with safe guidance.  ``transform_outbound(text)``
    is the complete outbound pass: redact secret VALUES first, then rewrite
    solicitation phrases on the redacted text.
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
    "hermes-vault add --id <id> --type api_key --label \"<description>\" "
    "--data '{\"value\":\"<key>\"}'\n"
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


def scan_and_redact(text: str) -> tuple[str, list[dict[str, Any]]]:
    """Scan text with the full detector registry; return (redacted, findings).

    Findings carry the detector name, severity, span, and a SHA-256
    fingerprint of the match — never the raw matched value.  Mirrors
    ``_scan_and_redact`` in the packaged Hermes plugin.
    """
    if not text or not isinstance(text, str):
        return text if isinstance(text, str) else "", []

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
        return text, []

    # Redact in-place, sorting reverse-order so span replacements don't
    # shift the indices of earlier matches.
    redacted = text
    for start, end in reversed(_merge_spans([f["span"] for f in findings])):
        redacted = redacted[:start] + _REDACT_REPLACEMENT + redacted[end:]

    return redacted, findings


def transform_outbound(text: str) -> str | None:
    """Redact secret values from, and rewrite secret requests in, agent output.

    Pass 1 replaces any API key, token, or password found by the detector
    registry; pass 2 rewrites phrases that ask the user to share a secret.
    Matches for pass 2 are computed on the *redacted* text so span indices
    stay valid.  Returns ``None`` when neither pass changed anything.
    """
    if not text or not isinstance(text, str):
        return None

    redacted, findings = scan_and_redact(text)

    matches = scan_outbound(redacted)
    if not matches:
        return redacted if findings else None

    return rewrite_outbound(redacted, matches)


# ---------------------------------------------------------------------------
# Inbound hook handler
# ---------------------------------------------------------------------------


def handle(event_type: str, context: dict[str, Any]) -> None:
    """Scan incoming message content for secrets and redact them in-place."""
    # Resolve the text to scan based on event type
    text = _resolve_content(event_type, context)
    if not text or not isinstance(text, str):
        return

    redacted, findings = scan_and_redact(text)
    if not findings:
        return

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
