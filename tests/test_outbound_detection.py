"""Tests for outbound secret-request detection (v0.4.2).

Covers:
- Outbound pattern detection (all 12 patterns)
- Response rewriting
- System prompt injection
- ``agent_requests_secret`` trigger matching
- Integration: full flow where AI asks for key → gets rewritten
"""

from __future__ import annotations

import pytest

from vaultknox.agent_guide import TRIGGERS, check_triggers
from vaultknox.agent_guide.prompts import get_system_prompt_snippet
from vaultknox.hooks.secret_guard import OUTBOUND_PATTERNS, rewrite_outbound, scan_outbound

# ---------------------------------------------------------------------------
# Outbound pattern detection
# ---------------------------------------------------------------------------

class TestOutboundPatternDetection:
    """Test that each outbound regex pattern matches its intended phrase."""

    @pytest.mark.parametrize(
        ("phrase", "pattern_idx"),
        [
            # Pattern 0: "drop (your|the|it) (api )?key"
            ("drop your key", 0),
            ("drop the key", 0),
            ("drop it key", 0),
            ("drop your api key", 0),
            ("Drop Your API Key", 0),
            # Pattern 1: "paste (your|the|it) (api )?key"
            ("paste your key", 1),
            ("paste the key", 1),
            ("paste your api key", 1),
            # Pattern 2: "send me (your|the|it) (api )?key"
            ("send me your key", 2),
            ("send me the key", 2),
            ("send me your api key", 2),
            # Pattern 3: "provide your (api )?key"
            ("provide your key", 3),
            ("provide your api key", 3),
            # Pattern 4: "share your (secret|key|token|password)"
            ("share your secret", 4),
            ("share your key", 4),
            ("share your token", 4),
            ("share your password", 4),
            # Pattern 5: "give me your (api )?key"
            ("give me your key", 5),
            ("give me your api key", 5),
            # Pattern 6: "enter your (password|secret|token)"
            ("enter your password", 6),
            ("enter your secret", 6),
            ("enter your token", 6),
            # Pattern 7: "throw (it|the key|your key) (here|over)"
            ("throw it here", 7),
            ("throw the key here", 7),
            ("throw your key over", 7),
            # Pattern 8: "drop it here"
            ("drop it here", 8),
            # Pattern 9: "paste it here"
            ("paste it here", 9),
            # Pattern 10: "send it (over|here)"
            ("send it over", 10),
            ("send it here", 10),
            # Pattern 11: "your (api )?key (here|in chat|in the chat)"
            ("your key here", 11),
            ("your api key here", 11),
            ("your key in chat", 11),
            ("your api key in the chat", 11),
        ],
    )
    def test_pattern_matches_phrase(self, phrase: str, pattern_idx: int) -> None:
        pattern = OUTBOUND_PATTERNS[pattern_idx]
        assert pattern.search(phrase), (
            f"Pattern {pattern_idx} ({pattern.pattern}) should match '{phrase}'"
        )

    def test_scan_outbound_returns_matches(self) -> None:
        text = "Please drop your api key here so I can use it."
        matches = scan_outbound(text)
        assert len(matches) >= 1

    def test_scan_outbound_no_match(self) -> None:
        text = "To add your API key, run: vault-add-key openai_key \"OpenAI API Key\" sk-xxx"
        matches = scan_outbound(text)
        assert matches == []

    def test_scan_outbound_empty_string(self) -> None:
        assert scan_outbound("") == []

    def test_scan_outbound_non_string(self) -> None:
        assert scan_outbound(42) == []  # type: ignore[arg-type]

    def test_case_insensitive_matching(self) -> None:
        text = "DROP YOUR API KEY HERE"
        matches = scan_outbound(text)
        assert len(matches) >= 1

    def test_multiple_patterns_match(self) -> None:
        text = "Please drop your key here, or paste your api key in chat."
        matches = scan_outbound(text)
        # At least 2 distinct pattern matches
        assert len(matches) >= 2


# ---------------------------------------------------------------------------
# Response rewriting
# ---------------------------------------------------------------------------

class TestOutboundRewriting:
    """Test that rewrite_outbound replaces secret-requesting phrases."""

    def test_simple_replacement(self) -> None:
        text = "Please drop your key and I'll store it."
        matches = scan_outbound(text)
        rewritten = rewrite_outbound(text, matches)
        assert "drop your key" not in rewritten
        assert "⚠️ **Security Notice:**" in rewritten
        assert "vault-add-key" in rewritten

    def test_preserves_surrounding_text(self) -> None:
        text = "Sure! Drop your api key here and I'll set it up for you."
        matches = scan_outbound(text)
        rewritten = rewrite_outbound(text, matches)
        assert "Sure!" in rewritten
        assert "set it up for you" in rewritten
        assert "drop your api key here" not in rewritten

    def test_no_match_returns_original(self) -> None:
        text = "Use vault-add-key to store your secret safely."
        matches = scan_outbound(text)
        rewritten = rewrite_outbound(text, matches)
        assert rewritten == text

    def test_overlapping_spans_merged(self) -> None:
        # "drop your key here" matches both pattern 0 and pattern 11
        text = "Just drop your key here"
        matches = scan_outbound(text)
        rewritten = rewrite_outbound(text, matches)
        # Should only contain one security notice, not two
        assert rewritten.count("⚠️ **Security Notice:**") == 1

    def test_rewrite_at_start_of_text(self) -> None:
        text = "Drop your key here, thanks!"
        matches = scan_outbound(text)
        rewritten = rewrite_outbound(text, matches)
        assert rewritten.startswith("⚠️ **Security Notice:**")

    def test_rewrite_at_end_of_text(self) -> None:
        text = "Let's get started—just drop your key"
        matches = scan_outbound(text)
        rewritten = rewrite_outbound(text, matches)
        assert rewritten.endswith("vault-add-key <id> \"<description>\" <key>\n```")

    def test_multiple_distinct_phrases(self) -> None:
        text = "First, paste your key. Then, share your password."
        matches = scan_outbound(text)
        rewritten = rewrite_outbound(text, matches)
        # Both phrases should be replaced
        assert "paste your key" not in rewritten
        assert "share your password" not in rewritten
        # Should have two security notices (non-overlapping)
        assert rewritten.count("⚠️ **Security Notice:**") == 2


# ---------------------------------------------------------------------------
# System prompt injection
# ---------------------------------------------------------------------------

class TestSystemPromptInjection:
    """Test the system prompt snippet used by pre_llm_call."""

    def test_snippet_contains_key_rules(self) -> None:
        snippet = get_system_prompt_snippet()
        assert "NEVER" in snippet
        assert "vault-add-key" in snippet
        assert "get_masked" in snippet or "get_masked" in snippet.lower()
        assert "AutonomousSecretsStore" in snippet
        assert "paste" in snippet.lower() or "secret" in snippet.lower()

    def test_snippet_is_substantial(self) -> None:
        snippet = get_system_prompt_snippet()
        assert len(snippet) > 500

    def test_snippet_no_internals(self) -> None:
        """System prompt must not leak vault internals."""
        snippet = get_system_prompt_snippet()
        assert "master.key" not in snippet
        assert "master_password" not in snippet
        assert "secrets.enc" not in snippet

    def test_prepend_to_system_message(self) -> None:
        """Simulate what the plugin's _on_pre_llm_call does."""
        snippet = get_system_prompt_snippet()
        original_system = "You are a helpful assistant."
        modified = snippet + "\n\n" + original_system
        assert modified.startswith("## VaultKnox")
        assert "You are a helpful assistant." in modified

    def test_no_double_injection(self) -> None:
        """If snippet is already present, should not duplicate."""
        snippet = get_system_prompt_snippet()
        system_msg = snippet + "\n\nSome other content"
        if snippet in system_msg:
            # Should skip injection
            result = system_msg
        else:
            result = snippet + "\n\n" + system_msg
        assert result.count("## VaultKnox") == 1


# ---------------------------------------------------------------------------
# agent_requests_secret trigger
# ---------------------------------------------------------------------------

class TestAgentRequestsSecretTrigger:
    """Test the new critical-priority trigger."""

    def test_trigger_exists(self) -> None:
        ids = [t["id"] for t in TRIGGERS]
        assert "agent_requests_secret" in ids

    def test_trigger_is_critical(self) -> None:
        trigger = next(t for t in TRIGGERS if t["id"] == "agent_requests_secret")
        assert trigger["priority"] == "critical"

    def test_trigger_matches_api_key_keyword(self) -> None:
        matched = check_triggers({"text": "I need your api key to proceed"})
        assert any(t["id"] == "agent_requests_secret" for t in matched)

    def test_trigger_matches_paste_keyword(self) -> None:
        matched = check_triggers({"text": "Just paste it in chat"})
        assert any(t["id"] == "agent_requests_secret" for t in matched)

    def test_trigger_matches_drop_your_keyword(self) -> None:
        matched = check_triggers({"text": "Drop your credentials here"})
        assert any(t["id"] == "agent_requests_secret" for t in matched)

    def test_trigger_does_not_match_safe_text(self) -> None:
        # "api key" is a keyword so this might match — let's use clearly safe text
        matched_safe = check_triggers({"text": "What's the weather like today?"})
        assert not any(t["id"] == "agent_requests_secret" for t in matched_safe)

    def test_trigger_action_guides_to_vault(self) -> None:
        trigger = next(t for t in TRIGGERS if t["id"] == "agent_requests_secret")
        assert "vault-add-key" in trigger["action"] or "vault tool" in trigger["action"]
        assert "NEVER" in trigger["action"].upper() or "Stop" in trigger["action"].upper() or "never" in trigger["action"].lower()

    def test_trigger_sorted_before_high(self) -> None:
        """Critical triggers should sort before high-priority ones."""
        matched = check_triggers({
            "text": "I need your api key and I want to store my key too"
        })
        if len(matched) >= 2:
            priorities = [t["priority"] for t in matched]
            crit_idx = priorities.index("critical") if "critical" in priorities else 999
            high_idx = priorities.index("high") if "high" in priorities else 999
            assert crit_idx < high_idx


# ---------------------------------------------------------------------------
# Integration: full flow
# ---------------------------------------------------------------------------

class TestFullOutboundFlow:
    """Integration test: AI asks for key → scanner detects → response rewritten."""

    def test_ai_asks_for_key_gets_rewritten(self) -> None:
        """Simulate the complete post_llm_call flow."""
        ai_response = "Sure! Just drop your api key here and I'll configure it for you."
        matches = scan_outbound(ai_response)
        assert len(matches) >= 1, "Scanner should detect the secret-requesting phrase"
        rewritten = rewrite_outbound(ai_response, matches)
        assert "drop your api key here" not in rewritten
        assert "⚠️ **Security Notice:**" in rewritten
        assert "vault-add-key" in rewritten

    def test_ai_says_paste_it_here(self) -> None:
        ai_response = "No problem, paste it here and I'll take care of it."
        matches = scan_outbound(ai_response)
        assert len(matches) >= 1
        rewritten = rewrite_outbound(ai_response, matches)
        assert "paste it here" not in rewritten
        assert "Security Notice" in rewritten

    def test_safe_response_unchanged(self) -> None:
        ai_response = (
            "To store your OpenAI key safely, run:\n"
            "  vault-add-key openai_key \"OpenAI API Key\" <your-key>\n"
            "Then I can retrieve it via get_masked when needed."
        )
        matches = scan_outbound(ai_response)
        rewritten = rewrite_outbound(ai_response, matches)
        assert rewritten == ai_response

    def test_trigger_and_scanner_agree_on_dangerous_response(self) -> None:
        """Both the trigger system and scanner should flag the same dangerous response."""
        dangerous = "Give me your api key and I'll store it."
        # Trigger check
        triggers = check_triggers({"text": dangerous})
        assert any(t["id"] == "agent_requests_secret" for t in triggers)
        # Scanner check
        matches = scan_outbound(dangerous)
        assert len(matches) >= 1

    def test_pre_llm_call_injection_plus_post_llm_rewrite(self) -> None:
        """Full defense-in-depth: system prompt injected, then response rewritten if needed."""
        # Step 1: Inject system prompt
        original_system = "You are a helpful coding assistant."
        snippet = get_system_prompt_snippet()
        modified_system = snippet + "\n\n" + original_system
        assert "NEVER" in modified_system

        # Step 2: Despite injection, if AI still produces dangerous response
        ai_response = "Just share your token here and I'll use it."
        matches = scan_outbound(ai_response)
        rewritten = rewrite_outbound(ai_response, matches)
        assert "share your token here" not in rewritten
        assert "Security Notice" in rewritten
