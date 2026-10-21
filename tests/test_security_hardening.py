from __future__ import annotations

import json
import os

from vaultknox.autonomous_secrets import AutonomousSecretsStore
from vaultknox.dashboard import _DASHBOARD_HTML
from vaultknox.hermes_tool import vault_tool
from vaultknox.hooks.secret_guard import handle
from vaultknox.scanner import SecretScanner, _redact_spans, format_findings_json


def test_autonomous_store_initializes_sets_and_gets_without_shadowing_secrets_module(tmp_path):
    store = AutonomousSecretsStore(tmp_path / "store")

    store.initialize()
    store.set("TEST_API_KEY", "sk-" + "A" * 32)

    assert store.get("TEST_API_KEY") == "sk-" + "A" * 32
    assert sorted(store.list_keys()) == ["TEST_API_KEY"]
    assert oct(os.stat(store.key_path).st_mode & 0o777) == "0o600"
    assert oct(os.stat(store.secrets_path).st_mode & 0o777) == "0o600"


def test_autonomous_store_compact_v2_large_payload_roundtrip(tmp_path):
    store_path = tmp_path / "store"
    store = AutonomousSecretsStore(store_path)

    store.initialize()
    payload = {f"KEY_{index:03d}": "v" * 10 for index in range(50)}
    for key, value in payload.items():
        store.set(key, value)

    assert os.stat(store.secrets_path).st_size > 100

    reloaded = AutonomousSecretsStore(store_path)
    assert sorted(reloaded.list_keys()) == sorted(payload)
    for key, value in payload.items():
        assert reloaded.get(key) == value


def test_scan_text_reports_fingerprint_not_raw_secret():
    raw_secret = "sk-" + "B" * 32
    result = vault_tool("scan_text", text=f"OPENAI_API_KEY={raw_secret}")

    serialized = json.dumps(result)
    assert raw_secret not in serialized
    assert "matched_text" not in serialized
    assert result["findings"][0]["fingerprint"]


def test_secret_guard_findings_do_not_retain_raw_secret():
    raw_secret = "sk-" + "C" * 32
    context = {"content": f"leaked {raw_secret}"}

    handle("message:received", context)

    assert raw_secret not in context["content"]
    serialized = json.dumps(context["_secret_guard_findings"])
    assert raw_secret not in serialized
    assert "matched_text" not in serialized
    assert context["_secret_guard_findings"][0]["fingerprint"]


def test_file_scanner_redacts_line_content_in_json_output(tmp_path):
    raw_secret = "sk-" + "D" * 32
    env_file = tmp_path / ".env"
    env_file.write_text(f"OPENAI_API_KEY={raw_secret}\n", encoding="utf-8")

    findings, perm_issues, stats = SecretScanner(paths=[tmp_path]).scan()

    assert findings
    assert raw_secret not in findings[0].line_content
    assert raw_secret not in format_findings_json(findings, perm_issues, stats)


def test_file_scanner_redacts_multiple_secrets_per_line_in_json_output(tmp_path):
    raw_secret_1 = "sk-" + "F" * 32
    raw_secret_2 = "ghp_" + "G" * 36
    env_file = tmp_path / ".env"
    env_file.write_text(f"OPENAI_API_KEY={raw_secret_1} GITHUB_TOKEN={raw_secret_2}\n", encoding="utf-8")

    findings, perm_issues, stats = SecretScanner(paths=[tmp_path]).scan()
    serialized = format_findings_json(findings, perm_issues, stats)

    assert findings
    for finding in findings:
        assert raw_secret_1 not in finding.line_content
        assert raw_secret_2 not in finding.line_content
    assert raw_secret_1 not in serialized
    assert raw_secret_2 not in serialized
    assert any(finding.line_content.count("[REDACTED-SENSITIVE-VALUE]") >= 2 for finding in findings)


def test_redact_spans_merges_adjacent_matches_without_gaps():
    text = "prefix sk-" + "A" * 32 + "ghp_" + "B" * 36 + " suffix"
    first_start = text.index("sk-")
    first_end = first_start + 35
    second_end = first_end + 40

    redacted = _redact_spans(text, [(first_start, first_end), (first_end, second_end)])

    assert "sk-" not in redacted
    assert "ghp_" not in redacted
    assert redacted.count("[REDACTED-SENSITIVE-VALUE]") == 1
    assert redacted == "prefix [REDACTED-SENSITIVE-VALUE] suffix"


def test_dashboard_html_escapes_api_values_and_does_not_keep_bootstrap_token_in_js():
    assert "function esc(value)" in _DASHBOARD_HTML
    assert "function cssClass(value)" in _DASHBOARD_HTML
    assert "bootstrapToken" not in _DASHBOARD_HTML
    assert "Authorization'] = 'Bearer '" not in _DASHBOARD_HTML
    assert "esc(s.label)" in _DASHBOARD_HTML
    assert "badge-' + cssClass(s.type)" in _DASHBOARD_HTML
    assert "esc(f.file)" in _DASHBOARD_HTML


def test_oauth_rejects_non_https_token_urls_before_network_call():
    from vaultknox.oauth import OAuthTokenError, exchange_code, refresh_access_token

    try:
        exchange_code(
            code="code",
            client_id="client",
            client_secret="secret",
            redirect_uri="http://127.0.0.1/callback",
            code_verifier="verifier",
            token_url="file:///tmp/token",
        )
    except OAuthTokenError as exc:
        assert "HTTPS" in str(exc)
    else:
        raise AssertionError("exchange_code accepted non-HTTPS token URL")

    try:
        refresh_access_token(
            refresh_token="refresh",
            client_id="client",
            client_secret="secret",
            token_url="http://example.invalid/token",
        )
    except OAuthTokenError as exc:
        assert "HTTPS" in str(exc)
    else:
        raise AssertionError("refresh_access_token accepted non-HTTPS token URL")


def test_oauth_accepts_https_token_url_and_reaches_urlopen(monkeypatch):
    from vaultknox import oauth

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return json.dumps({"access_token": "access", "token_type": "Bearer", "expires_in": 3600}).encode()

    calls = []

    def fake_urlopen(request, timeout):
        calls.append((request.full_url, timeout))
        return FakeResponse()

    monkeypatch.setattr(oauth, "urlopen", fake_urlopen)
    result = oauth.exchange_code(
        code="code",
        client_id="client",
        client_secret="secret",
        redirect_uri="http://127.0.0.1/callback",
        code_verifier="verifier",
        token_url="https://example.test/token",
    )

    assert result.access_token == "access"
    assert calls == [("https://example.test/token", 30)]


def test_sanitize_history_redacts_messages_table_and_ignores_unrelated_tables(tmp_path):
    import sqlite3

    from click.testing import CliRunner

    from vaultknox.cli import main

    raw_secret = "sk-" + "E" * 32
    ignored_secret = "sk-" + "H" * 32
    db_path = tmp_path / "state.db"
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, content TEXT, tool_calls TEXT, reasoning TEXT)")
    conn.execute("INSERT INTO messages (content, tool_calls, reasoning) VALUES (?, ?, ?)", (f"token={raw_secret}", None, None))
    conn.execute('CREATE TABLE "odd table" ("odd col" TEXT)')
    conn.execute('INSERT INTO "odd table" ("odd col") VALUES (?)', (f"token={ignored_secret}",))
    conn.commit()
    conn.close()

    result = CliRunner().invoke(main, ["sanitize-history", "--apply", "--paths", str(db_path)])

    assert result.exit_code == 0, result.output
    conn = sqlite3.connect(db_path)
    value = conn.execute("SELECT content FROM messages").fetchone()[0]
    ignored_value = conn.execute('SELECT "odd col" FROM "odd table"').fetchone()[0]
    conn.close()
    assert raw_secret not in value
    assert "[REDACTED-SENSITIVE-VALUE]" in value
    assert ignored_value == f"token={ignored_secret}"
