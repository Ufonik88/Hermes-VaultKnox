"""Secret-Guard hook — redact sensitive values from chat before storage.

Imports the existing VaultKnox detector registry so patterns stay in
one place.  All errors are caught by HookRegistry.emit().

Supports two event types:

``message:received``
    Context key: ``content`` — the full message text.
    Used by the gateway core emitter when available (v0.4.1+).

``agent:start``
    Context key: ``message`` — the message text (may be truncated to
    500 chars by the emitter).  Defense-in-depth for CLI / non-gateway
    paths where ``message:received`` may not fire.
"""

from __future__ import annotations

from typing import Any

from vaultknox.detectors import DETECTORS

_REDACT_REPLACEMENT = "[REDACTED-SENSITIVE-VALUE]"


def handle(event_type: str, context: dict[str, Any]) -> None:
    """Scan incoming message content for secrets and redact them in-place."""
    # Resolve the text to scan based on event type
    text = _resolve_content(event_type, context)
    if not text or not isinstance(text, str):
        return

    findings: list[dict[str, Any]] = []

    for detector in DETECTORS:
        for match in detector.pattern.finditer(text):
            findings.append(
                {
                    "detector": detector.name,
                    "severity": detector.severity,
                    "matched_text": match.group(0),
                    "span": match.span(),
                }
            )

    if not findings:
        return

    # Redact in-place, sorting reverse-order so span replacements don't
    # shift the indices of earlier matches.
    redacted = text
    for finding in sorted(findings, key=lambda f: f["span"][0], reverse=True):
        start, end = finding["span"]
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
