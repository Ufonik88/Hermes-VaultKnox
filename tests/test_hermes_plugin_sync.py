"""Sync guards for the packaged Hermes plugin.

The plugin directory (``src/vaultknox/_hermes_plugin/``) is self-contained:
it must load with NO vaultknox package available (that is how the Hermes
plugin admission probe runs it). To achieve that it carries its own copy of:

- ``detectors.py`` — vendored byte-for-byte from ``vaultknox.detectors``
- outbound patterns, rewrite text, system prompt snippet — kept byte-equal
  to ``vaultknox.hooks.secret_guard`` / ``vaultknox.agent_guide.prompts``

These tests fail loudly if the copies drift, and prove standalone loading in
a subprocess with vaultknox imports blocked.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src" / "vaultknox"
PLUGIN_DIR = SRC / "_hermes_plugin"


def _load_plugin():
    spec = importlib.util.spec_from_file_location(
        "vaultknox_hermes_plugin_sync_test",
        str(PLUGIN_DIR / "__init__.py"),
        submodule_search_locations=[str(PLUGIN_DIR)],
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_vendored_detectors_are_byte_identical():
    assert (PLUGIN_DIR / "detectors.py").read_bytes() == (SRC / "detectors.py").read_bytes()


def test_outbound_patterns_match_package():
    from vaultknox.hooks import secret_guard

    plugin = _load_plugin()
    assert [p.pattern for p in plugin.OUTBOUND_PATTERNS] == [
        p.pattern for p in secret_guard.OUTBOUND_PATTERNS
    ]


def test_copy_strings_match_package():
    from vaultknox.agent_guide.prompts import get_system_prompt_snippet
    from vaultknox.hooks import secret_guard

    plugin = _load_plugin()
    assert plugin.OUTBOUND_REWRITE == secret_guard.OUTBOUND_REWRITE
    assert plugin._SYSTEM_PROMPT_SNIPPET == get_system_prompt_snippet()
    assert plugin._SNIPPET_MARKER in plugin._SYSTEM_PROMPT_SNIPPET


def test_inbound_redaction_parity_with_package_hook():
    """Same input must produce the same redacted output in plugin and package."""
    from vaultknox.hooks import secret_guard

    plugin = _load_plugin()
    samples = [
        "my key is sk-xyz789def456ghi012jkl0 ok",
        "token ghp_abcdefghijklmnopqrstuvwxyz0123456789 end",
        "nothing to see here",
    ]
    for sample in samples:
        ctx = {"content": sample}
        secret_guard.handle("message:received", ctx)
        plugin_redacted, _ = plugin._scan_and_redact(sample)
        assert ctx["content"] == plugin_redacted, f"diverged on: {sample!r}"


def test_plugin_is_self_contained_without_vaultknox():
    """Load + register + redact in a subprocess with vaultknox imports blocked."""
    code = textwrap.dedent(
        f'''
        import importlib.util, json, sys
        sys.modules["vaultknox"] = None
        sys.modules["vaultknox.hermes_tool"] = None

        pdir = {str(PLUGIN_DIR)!r}
        spec = importlib.util.spec_from_file_location(
            "vaultknox_plugin_standalone",
            pdir + "/__init__.py",
            submodule_search_locations=[pdir],
        )
        mod = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = mod
        spec.loader.exec_module(mod)

        class Ctx:
            plugin_config = {{}}
            plugin_id = "t"
            def __init__(self):
                self.tools, self.hooks = [], []
            def register_tool(self, name, *a, **k):
                self.tools.append(str(name))
            def register_hook(self, name, cb):
                self.hooks.append(str(name))

        ctx = Ctx()
        mod.register(ctx)
        assert sorted(ctx.hooks) == [
            "pre_gateway_dispatch", "pre_llm_call", "transform_llm_output"
        ], ctx.hooks
        assert ctx.tools == ["vaultknox"], ctx.tools

        class E:
            text = "key sk-xyz789def456ghi012jkl0 here"

        res = mod.on_pre_gateway_dispatch(event=E())
        assert isinstance(res, dict) and res.get("action") == "rewrite", res
        assert "sk-xyz789def456ghi012jkl0" not in res["text"], res

        out = json.loads(mod._handle_vaultknox({{"action": "status"}}))
        assert out.get("error") == "vaultknox_not_installed", out
        print("STANDALONE-OK")
        '''
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        encoding="utf-8",
        timeout=60,
        cwd=str(REPO_ROOT),
    )
    assert result.returncode == 0, f"stdout={result.stdout}\nstderr={result.stderr}"
    assert "STANDALONE-OK" in result.stdout
