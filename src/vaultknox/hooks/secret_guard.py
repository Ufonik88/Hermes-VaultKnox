"""Secret-Guard hook — redact sensitive values from chat before storage.

Imports the existing VaultKnox detector registry so patterns stay in
one place.  All errors are caught by HookRegistry.emit().
"""

from __future__ import annotations

from typing import Any

from vaultknox.detectors import DETECTORS

_REDACT_REPLACEMENT = "[REDACTED-SENSITIVE-VALUE]"


def handle(event_type: str, context: dict[str, Any]) -> None:
    """Scan incoming message content for secrets and redact them in-place.

    Args:
        event_type: The hook event type (only ``message:received`` is handled).
        context: Event context dictionary; ``content`` key holds the message text.
    """
    if event_type != "message:received":
        return

    content = context.get("content", "")
    if not content or not isinstance(content, str):
        return

    findings: list[dict[str, Any]] = []

    for detector in DETECTORS:
        for match in detector.pattern.finditer(content):
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
    redacted = content
    for finding in sorted(findings, key=lambda f: f["span"][0], reverse=True):
        start, end = finding["span"]
        redacted = redacted[:start] + _REDACT_REPLACEMENT + redacted[end:]

    context["content"] = redacted
    context["_secret_guard_findings"] = findings
    context["_secret_guard_redacted"] = True
