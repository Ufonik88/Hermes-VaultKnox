from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from vaultknox.config import expand_runtime_path
from vaultknox.vault import VaultKnox

STRONG_PASSWORD = "CorrectHorse123!"


def test_oauth_near_expiry_triggers_refresh_and_persists(monkeypatch, tmp_path: Path) -> None:
    runtime_dir = tmp_path / ".runtime"
    vault = VaultKnox(expand_runtime_path(runtime_dir))
    vault.initialize(STRONG_PASSWORD)
    vault.unlock(STRONG_PASSWORD)

    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=30)).isoformat()
    payload = {
        "provider_id": "github",
        "access_token": "old_access",
        "refresh_token": "old_refresh",
        "client_id": "cid",
        "client_secret": "csecret",
        "token_type": "Bearer",
        "expires_at": expires_at,
        "scope": "repo",
    }
    vault.add_secret(STRONG_PASSWORD, "oauth_1", "oauth", "GitHub OAuth", payload)

    class DummyResp:
        access_token = "new_access"
        token_type = "Bearer"
        expires_in = 3600
        refresh_token = "new_refresh"
        scope = "repo"
        issued_at = datetime.now(timezone.utc)

    monkeypatch.setattr("vaultknox.vault.refresh_access_token", lambda **kwargs: DummyResp())

    result = vault.get_secret(None, "oauth_1")
    assert result["payload"]["access_token"] == "new_access"
    assert result["payload"]["refresh_token"] == "new_refresh"

    # Ensure persisted by reading again
    persisted = vault.get_secret(None, "oauth_1")
    assert persisted["payload"]["access_token"] == "new_access"


def test_oauth_refresh_failure_flags_result_without_throw(monkeypatch, tmp_path: Path) -> None:
    runtime_dir = tmp_path / ".runtime"
    vault = VaultKnox(expand_runtime_path(runtime_dir))
    vault.initialize(STRONG_PASSWORD)
    vault.unlock(STRONG_PASSWORD)

    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=30)).isoformat()
    payload = {
        "provider_id": "github",
        "access_token": "old_access",
        "refresh_token": "old_refresh",
        "client_id": "cid",
        "client_secret": "csecret",
        "token_type": "Bearer",
        "expires_at": expires_at,
        "scope": "repo",
    }
    vault.add_secret(STRONG_PASSWORD, "oauth_2", "oauth", "GitHub OAuth", payload)

    from vaultknox.oauth import OAuthTokenError

    def _raise(**kwargs):
        raise OAuthTokenError("refresh failed")

    monkeypatch.setattr("vaultknox.vault.refresh_access_token", _raise)

    result = vault.get_secret(None, "oauth_2")
    assert result["payload"]["access_token"] == "old_access"
    assert result["payload"].get("refresh_failed") is True
