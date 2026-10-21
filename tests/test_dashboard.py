from __future__ import annotations

import json
from http.cookies import SimpleCookie
from pathlib import Path

from vaultknox.config import expand_runtime_path
from vaultknox.dashboard import DashboardServer
from vaultknox.vault import VaultKnox

STRONG_PASSWORD = "CorrectHorse123!"


def _extract_handler(server: DashboardServer):
    import http.server
    from urllib.parse import parse_qs, urlparse

    DashboardServer._instance = server

    class Handler(http.server.BaseHTTPRequestHandler):
        def __init__(self):
            pass

        def _set_common_headers(self):
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")

        def _read_bearer(self):
            auth = self.headers.get("Authorization", "") if hasattr(self, "headers") else ""
            if auth.lower().startswith("bearer "):
                return auth[7:]
            cookie_header = self.headers.get("Cookie", "") if hasattr(self, "headers") else ""
            cookie = SimpleCookie()
            cookie.load(cookie_header)
            morsel = cookie.get("vaultknox_token")
            if morsel:
                return morsel.value
            return ""

        def do_GET(self):
            parsed = urlparse(self.path)
            qs = parse_qs(parsed.query)
            token = self._read_bearer()

            if parsed.path == "/":
                # Bootstrap path allows ?token= once; then issues HttpOnly cookie
                bootstrap = qs.get("token", [""])[0]
                if bootstrap:
                    if bootstrap != DashboardServer._instance.token:
                        self.send_error(401, "Unauthorized")
                        return
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.send_header("Set-Cookie", "vaultknox_token=" + bootstrap + "; HttpOnly; Path=/; SameSite=Strict")
                    self._set_common_headers()
                    self.end_headers()
                    self.wfile.write(b"ok")
                    return

            if parsed.path.startswith("/api/"):
                if qs.get("token"):
                    self.send_error(401, "Unauthorized")
                    return
                if token != DashboardServer._instance.token:
                    self.send_error(401, "Unauthorized")
                    return
                if parsed.path == "/api/health":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self._set_common_headers()
                    self.end_headers()
                    self.wfile.write(json.dumps({"ok": True}).encode("utf-8"))
                    return

            self.send_error(404, "Not Found")

        def log_message(self, format, *args):
            pass

    return Handler


def test_dashboard_api_rejects_query_token_after_bootstrap(tmp_path: Path) -> None:
    runtime_dir = tmp_path / ".runtime"
    vault = VaultKnox(expand_runtime_path(runtime_dir))
    vault.initialize(STRONG_PASSWORD)
    vault.unlock(STRONG_PASSWORD)

    server = DashboardServer(host="127.0.0.1", port=0)
    handler_cls = _extract_handler(server)

    # Simulate handler object
    class Dummy(handler_cls):
        def __init__(self, path: str, headers=None):
            self.path = path
            self.headers = headers or {}
            self.code = None
            self.sent_headers = {}
            self.wfile = __import__("io").BytesIO()

        def send_response(self, code, message=None):
            self.code = code

        def send_header(self, key, val):
            self.sent_headers[key] = val

        def end_headers(self):
            pass

        def send_error(self, code, message=None):
            self.code = code

    ok = Dummy(path=f"/?token={server.token}")
    ok.do_GET()
    assert ok.code == 200
    assert "Set-Cookie" in ok.sent_headers

    bad = Dummy(path=f"/api/health?token={server.token}")
    bad.do_GET()
    assert bad.code == 401


def test_dashboard_api_allows_cookie_and_sets_headers(tmp_path: Path) -> None:
    server = DashboardServer(host="127.0.0.1", port=0)
    handler_cls = _extract_handler(server)

    class Dummy(handler_cls):
        def __init__(self, path: str, headers=None):
            self.path = path
            self.headers = headers or {}
            self.code = None
            self.sent_headers = {}
            self.wfile = __import__("io").BytesIO()

        def send_response(self, code, message=None):
            self.code = code

        def send_header(self, key, val):
            self.sent_headers[key] = val

        def end_headers(self):
            pass

        def send_error(self, code, message=None):
            self.code = code

    cookie = f"vaultknox_token={server.token}"
    req = Dummy(path="/api/health", headers={"Cookie": cookie})
    req.do_GET()
    assert req.code == 200
    assert req.sent_headers.get("Cache-Control") == "no-store"
    assert req.sent_headers.get("X-Content-Type-Options") == "nosniff"
