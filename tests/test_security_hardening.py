from __future__ import annotations

import json
import os

from vaultknox.autonomous_secrets import AutonomousSecretsStore
from vaultknox.dashboard import _DASHBOARD_HTML
from vaultknox.hermes_tool import vault_tool
from vaultknox.hooks.secret_guard import handle
from vaultknox.scanner import SecretScanner, format_findings_json


def test_autonomous_store_initializes_sets_and_gets_without_shadowing_secrets_module(tmp_path):
    store = AutonomousSecretsStore(tmp_path / "store")

    store.initialize()
    store.set("TEST_API_KEY", "sk-" + "A" * 32)

    assert store.get("TEST_API_KEY") == "sk-" + "A" * 32
    assert sorted(store.list_keys()) == ["TEST_API_KEY"]
    assert oct(os.stat(store.key_path).st_mode & 0o777) == "0o600"
    assert oct(os.stat(store.secrets_path).st_mode & 0o777) == "0o600"


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


def test_dashboard_html_escapes_api_values_and_does_not_keep_bootstrap_token_in_js():
    assert "function esc(value)" in _DASHBOARD_HTML
    assert "bootstrapToken" not in _DASHBOARD_HTML
    assert "Authorization'] = 'Bearer '" not in _DASHBOARD_HTML
    assert "esc(s.label)" in _DASHBOARD_HTML
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


def test_sanitize_history_quotes_hostile_sqlite_identifiers(tmp_path):
    import sqlite3

    from click.testing import CliRunner

    from vaultknox.cli import main

    raw_secret = "sk-" + "E" * 32
    db_path = tmp_path / "state.db"
    conn = sqlite3.connect(db_path)
    conn.execute('CREATE TABLE "odd table" ("odd col" TEXT)')
    conn.execute('INSERT INTO "odd table" ("odd col") VALUES (?)', (f"token={raw_secret}",))
    conn.commit()
    conn.close()

    result = CliRunner().invoke(main, ["sanitize-history", "--apply", "--paths", str(db_path)])

    assert result.exit_code == 0, result.output
    conn = sqlite3.connect(db_path)
    value = conn.execute('SELECT "odd col" FROM "odd table"').fetchone()[0]
    conn.close()
    assert raw_secret not in value
    assert "[REDACTED-SENSITIVE-VALUE]" in value
