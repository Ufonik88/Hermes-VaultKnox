"""Tests for chat secret detection and redaction (v0.4.0)."""


from vaultknox.agent_guide import TRIGGERS, check_triggers, get_system_prompt_snippet
from vaultknox.detectors import DETECTORS
from vaultknox.hermes_tool import vault_tool
from vaultknox.hooks.secret_guard import _REDACT_REPLACEMENT, handle


class TestScanTextTool:
    """Test the vaultknox(action='scan_text') tool action."""

    def test_scan_text_empty(self):
        result = vault_tool(action="scan_text", text="")
        assert result["count"] == 0
        assert result["findings"] == []

    def test_scan_text_no_secrets(self):
        result = vault_tool(action="scan_text", text="Hello, this is a normal message with no secrets.")
        assert result["count"] == 0

    def test_scan_text_finds_openai_key(self):
        text = "My OpenAI key is sk-xyz789def456ghi012jkl0"
        result = vault_tool(action="scan_text", text=text)
        assert result["count"] >= 1
        assert any(f["detector"] == "OpenAI API Key" for f in result["findings"])

    def test_scan_text_finds_github_token(self):
        text = "ghp_123456789012345678901234567890123456"
        result = vault_tool(action="scan_text", text=text)
        assert result["count"] >= 1
        assert any(f["detector"] == "GitHub Personal Access Token (classic)" for f in result["findings"])

    def test_scan_text_returns_spans(self):
        text = "sk-test12345678901234567890"
        result = vault_tool(action="scan_text", text=text)
        assert result["count"] >= 1
        finding = result["findings"][0]
        assert "span" in finding
        assert isinstance(finding["span"], tuple)
        assert finding["severity"] in ("critical", "high", "medium", "low")

    def test_scan_text_multiple_detectors(self):
        text = (
            "OpenAI: sk-xyz789def456ghi012jkl0 "
            "GitHub: ghp_123456789012345678901234567890123456"
        )
        result = vault_tool(action="scan_text", text=text)
        assert result["count"] >= 2
        detectors = {f["detector"] for f in result["findings"]}
        assert "OpenAI API Key" in detectors
        assert "GitHub Personal Access Token (classic)" in detectors


class TestSecretGuardHook:
    """Test the secret-guard hook redaction logic."""

    def test_hook_redacts_openai_key(self):
        content = "Here is my key: sk-xyz789def456ghi012jkl0 thanks"
        ctx = {"content": content}
        handle("message:received", ctx)

        assert ctx["_secret_guard_redacted"] is True
        assert _REDACT_REPLACEMENT in ctx["content"]
        assert "sk-xyz789" not in ctx["content"]

    def test_hook_no_match_leaves_content_unchanged(self):
        content = "Just a normal message with no secrets at all"
        ctx = {"content": content}
        handle("message:received", ctx)

        assert "_secret_guard_redacted" not in ctx
        assert ctx["content"] == content

    def test_hook_ignores_wrong_event(self):
        ctx = {"content": "sk-xyz789def456ghi012jkl0"}
        handle("agent:start", ctx)

        assert "_secret_guard_redacted" not in ctx

    def test_hook_empty_content(self):
        ctx = {"content": ""}
        handle("message:received", ctx)
        assert "_secret_guard_redacted" not in ctx

    def test_hook_non_string_content(self):
        ctx = {"content": 12345}
        handle("message:received", ctx)
        assert "_secret_guard_redacted" not in ctx

    def test_hook_multiple_secrets(self):
        content = (
            "OpenAI: sk-xyz789def456ghi012jkl0 "
            "GitHub: ghp_123456789012345678901234567890123456"
        )
        ctx = {"content": content}
        handle("message:received", ctx)

        assert ctx["_secret_guard_redacted"] is True
        occurrences = ctx["content"].count(_REDACT_REPLACEMENT)
        assert occurrences >= 2

    def test_hook_findings_structure(self):
        content = "ghp_123456789012345678901234567890123456"
        ctx = {"content": content}
        handle("message:received", ctx)

        findings = ctx.get("_secret_guard_findings", [])
        assert len(findings) >= 1
        assert all("detector" in f for f in findings)
        assert all("severity" in f for f in findings)
        assert all("fingerprint" in f for f in findings)
        assert all("matched_text" not in f for f in findings)
        assert all("span" in f for f in findings)


class TestAgentGuideTriggers:
    """Test the agent autonomy trigger detection."""

    def test_triggers_list_not_empty(self):
        assert len(TRIGGERS) > 0

    def test_check_triggers_api_key_paste(self):
        text = "I just pasted my sk-abc123 API key here, can you help?"
        matched = check_triggers({"text": text})
        assert len(matched) > 0
        assert any(m["id"] == "user_pastes_secret" for m in matched)

    def test_check_triggers_missing_key(self):
        text = "I need api key for this service but it's not available"
        matched = check_triggers({"text": text})
        assert any(m["id"] == "agent_needs_api_key" for m in matched)

    def test_check_triggers_no_match(self):
        text = "What's the weather like today?"
        matched = check_triggers({"text": text})
        assert matched == []

    def test_system_prompt_snippet_is_string(self):
        snippet = get_system_prompt_snippet()
        assert isinstance(snippet, str)
        assert "NEVER" in snippet
        assert "vault-add-key" in snippet

    def test_system_prompt_snippet_length(self):
        snippet = get_system_prompt_snippet()
        assert len(snippet) > 500  # Should be substantial


class TestDetectorRegistry:
    """Sanity checks on the detector registry."""

    def test_detectors_not_empty(self):
        assert len(DETECTORS) >= 21

    def test_all_detectors_have_pattern(self):
        for d in DETECTORS:
            assert hasattr(d, "pattern")
            assert hasattr(d, "name")
            assert hasattr(d, "severity")

    def test_all_severities_valid(self):
        valid = {"critical", "high", "medium", "low"}
        for d in DETECTORS:
            assert d.severity in valid
