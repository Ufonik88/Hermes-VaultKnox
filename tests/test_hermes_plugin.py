"""Contract tests for the packaged Hermes plugin (src/vaultknox/_hermes_plugin).

Pins the plugin to the CURRENT Hermes hook contracts (verified against
hermes-agent v0.21.x). A contract mismatch silently disables protection, so
each registered hook is exercised with the exact payload shape the runtime
sends:

- ``pre_gateway_dispatch`` fires as ``invoke_hook("pre_gateway_dispatch",
  event=…, gateway=…, session_store=…)`` before persistence; the gateway
  consumes ``{"action": "rewrite", "text": …}`` (gateway/run_inbound.py).
- ``pre_llm_call`` results are consumed only as ``{"context": <str>}`` or a
  bare string, injected into the user message for the turn
  (agent/turn_context.py).
- ``transform_llm_output`` replaces the response with the first non-empty
  string returned; ``post_llm_call`` results are DISCARDED by the runtime
  (agent/turn_finalizer.py).
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest
import yaml

PLUGIN_DIR = Path(__file__).resolve().parent.parent / "src" / "vaultknox" / "_hermes_plugin"

# Fake, format-valid OpenAI-style key (low entropy; not a real credential).
FAKE_KEY = "sk-xyz789def456ghi012jkl0"


class FakeEvent:
    """Minimal stand-in for Hermes' MessageEvent (only ``.text`` is read)."""

    def __init__(self, text, **extra):
        self.text = text
        for key, value in extra.items():
            setattr(self, key, value)


class RecordingContext:
    """Replica of the Hermes admission probe's recording context."""

    plugin_config: dict = {}
    profile_name = "default"
    plugin_id = "test_plugin"

    def __init__(self):
        self.tools: list[str] = []
        self.hooks: dict = {}

    def register_tool(self, name, *args, **kwargs):
        self.tools.append(str(name))

    def register_hook(self, hook_name, callback):
        self.hooks[str(hook_name)] = callback


@pytest.fixture(scope="module")
def plugin():
    spec = importlib.util.spec_from_file_location(
        "vaultknox_hermes_plugin_contract_test",
        str(PLUGIN_DIR / "__init__.py"),
        submodule_search_locations=[str(PLUGIN_DIR)],
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    module.__path__ = [str(PLUGIN_DIR)]
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def registered(plugin):
    ctx = RecordingContext()
    plugin.register(ctx)
    return ctx


# ---------------------------------------------------------------------------
# Registration surface
# ---------------------------------------------------------------------------

class TestRegistration:
    def test_registers_expected_hooks(self, registered):
        assert set(registered.hooks) == {
            "pre_gateway_dispatch",
            "pre_llm_call",
            "transform_llm_output",
        }

    def test_registers_vaultknox_tool(self, registered):
        assert registered.tools == ["vaultknox"]

    def test_manifest_declarations_match_registrations(self, registered):
        manifest = yaml.safe_load((PLUGIN_DIR / "plugin.yaml").read_text())
        assert set(manifest.get("provides_hooks") or []) == set(registered.hooks)
        assert set(manifest.get("provides_tools") or []) == set(registered.tools)
        assert not (manifest.get("provides_middleware") or [])


# ---------------------------------------------------------------------------
# pre_gateway_dispatch — inbound redaction
# ---------------------------------------------------------------------------

class TestInboundRedaction:
    def test_rewrites_message_containing_secret(self, registered):
        event = FakeEvent(text=f"here is my key {FAKE_KEY} keep it safe")
        result = registered.hooks["pre_gateway_dispatch"](
            event=event, gateway=None, session_store=None
        )
        assert isinstance(result, dict)
        assert result.get("action") == "rewrite"
        assert FAKE_KEY not in result["text"]
        assert "[REDACTED-SENSITIVE-VALUE]" in result["text"]
        assert result["text"].startswith("⚠️ **Security Notice:**")

    def test_clean_message_is_untouched(self, registered):
        event = FakeEvent(text="hello, what is the weather today?")
        result = registered.hooks["pre_gateway_dispatch"](
            event=event, gateway=None, session_store=None
        )
        assert result is None

    def test_missing_event_is_safe(self, registered):
        hook = registered.hooks["pre_gateway_dispatch"]
        assert hook(gateway=None, session_store=None) is None
        assert hook(event=object()) is None
        assert hook(event=FakeEvent(text="")) is None

    def test_warning_does_not_echo_secret(self, registered):
        event = FakeEvent(text=f"token: {FAKE_KEY}")
        result = registered.hooks["pre_gateway_dispatch"](event=event)
        assert FAKE_KEY not in json.dumps(result)


# ---------------------------------------------------------------------------
# pre_llm_call — prompt-rule injection
# ---------------------------------------------------------------------------

class TestPromptInjection:
    def test_returns_context_key(self, registered):
        result = registered.hooks["pre_llm_call"](
            session_id="s1", user_message="hi", conversation_history=[]
        )
        assert isinstance(result, dict)
        assert "context" in result
        assert "system_message" not in result  # old (dead) contract removed
        assert result["context"].startswith("## VaultKnox")

    def test_dedupes_when_already_in_history(self, plugin, registered):
        history = [{"role": "user", "content": f"prefix {plugin._SNIPPET_MARKER} suffix"}]
        result = registered.hooks["pre_llm_call"](
            session_id="s1", user_message="hi", conversation_history=history
        )
        assert result is None

    def test_injects_when_history_clean(self, registered):
        history = [{"role": "user", "content": "hello"}]
        result = registered.hooks["pre_llm_call"](
            session_id="s1", user_message="hi", conversation_history=history
        )
        assert isinstance(result, dict) and "context" in result

    def test_handles_multimodal_history(self, plugin, registered):
        history = [
            {"role": "user", "content": [{"type": "text", "text": plugin._SNIPPET_MARKER}]}
        ]
        result = registered.hooks["pre_llm_call"](conversation_history=history)
        assert result is None


# ---------------------------------------------------------------------------
# transform_llm_output — outbound rewrite
# ---------------------------------------------------------------------------

class TestOutboundRewrite:
    def test_rewrites_secret_request(self, registered):
        result = registered.hooks["transform_llm_output"](
            response_text="Just paste your api key here and I'll store it."
        )
        assert isinstance(result, str)
        assert "paste your api key" not in result
        assert "hermes-vault add" in result

    def test_clean_response_returns_none(self, registered):
        assert registered.hooks["transform_llm_output"](
            response_text="All good, nothing to see here."
        ) is None

    def test_non_string_safe(self, registered):
        hook = registered.hooks["transform_llm_output"]
        assert hook(response_text=None) is None
        assert hook() is None


# ---------------------------------------------------------------------------
# vaultknox tool
# ---------------------------------------------------------------------------

class TestVaultknoxTool:
    def test_check_fn_true_in_this_env(self, plugin):
        assert plugin._check_vaultknox_available() is True

    def test_handler_scan_text_roundtrip(self, plugin):
        payload = json.loads(
            plugin._handle_vaultknox({"action": "scan_text", "text": f"key {FAKE_KEY}"})
        )
        assert payload["count"] >= 1

    def test_handler_degrades_when_package_missing(self, plugin, monkeypatch):
        import builtins

        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "vaultknox.hermes_tool":
                raise ImportError("blocked for test")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        payload = json.loads(plugin._handle_vaultknox({"action": "status"}))
        assert payload.get("error") == "vaultknox_not_installed"

    def test_handler_always_returns_valid_json(self, plugin):
        result = plugin._handle_vaultknox({"action": "status"})
        assert isinstance(result, str)
        json.loads(result)
