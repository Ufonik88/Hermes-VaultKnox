"""VaultKnox Dashboard - Local web console for credential management.

A token-guarded local dashboard for operators to view vault health,
credential metadata, audit activity, and perform safe operations without
exposing raw secrets.
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
import webbrowser
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import click
from vaultknox import __version__
from vaultknox.config import expand_runtime_path
from vaultknox.health import VaultHealthChecker
from vaultknox.scanner import SecretScanner
from vaultknox.verifier import CredentialVerifier
from vaultknox.vault import VaultKnox

logger = logging.getLogger("vaultknox.dashboard")

# Simple in-memory HTML templates - no external dependencies
_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VaultKnox Dashboard</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #e6edf3; min-height: 100vh; }
        .header { background: #161b22; border-bottom: 1px solid #30363d; padding: 1rem 2rem; display: flex; justify-content: space-between; align-items: center; }
        .header h1 { font-size: 1.25rem; color: #58a6ff; }
        .status-badge { padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 500; }
        .status-healthy { background: #1a4d2e; color: #3fb950; }
        .status-degraded { background: #4d3a00; color: #d29922; }
        .status-critical { background: #4d1a1a; color: #f85149; }
        .container { max-width: 1400px; margin: 0 auto; padding: 2rem; }
        .tabs { display: flex; gap: 0.5rem; margin-bottom: 1.5rem; border-bottom: 1px solid #30363d; }
        .tab { padding: 0.75rem 1.25rem; background: transparent; border: none; color: #8b949e; cursor: pointer; font-size: 0.875rem; transition: all 0.2s; }
        .tab:hover { color: #e6edf3; }
        .tab.active { color: #58a6ff; border-bottom: 2px solid #58a6ff; margin-bottom: -1px; }
        .card { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 1.25rem; margin-bottom: 1rem; }
        .card h2 { font-size: 1rem; color: #8b949e; margin-bottom: 0.75rem; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1rem; }
        .stat { text-align: center; padding: 1rem; }
        .stat-value { font-size: 2rem; font-weight: 600; color: #58a6ff; }
        .stat-label { font-size: 0.75rem; color: #8b949e; margin-top: 0.25rem; }
        table { width: 100%; border-collapse: collapse; }
        th, td { text-align: left; padding: 0.75rem; border-bottom: 1px solid #30363d; }
        th { color: #8b949e; font-weight: 500; font-size: 0.75rem; text-transform: uppercase; }
        td { font-size: 0.875rem; }
        .badge { display: inline-block; padding: 0.125rem 0.5rem; border-radius: 9999px; font-size: 0.75rem; background: #21262d; }
        .badge-api_key { color: #a371f7; }
        .badge-credential { color: #58a6ff; }
        .badge-oauth { color: #3fb950; }
        .badge-note { color: #8b949e; }
        .btn { padding: 0.5rem 1rem; background: #238636; color: white; border: none; border-radius: 6px; cursor: pointer; font-size: 0.875rem; }
        .btn:hover { background: #2ea043; }
        .btn-secondary { background: #21262d; }
        .btn-secondary:hover { background: #30363d; }
        .error { color: #f85149; padding: 1rem; background: #1a1414; border-radius: 6px; margin-bottom: 1rem; }
        .footer { text-align: center; padding: 2rem; color: #8b949e; font-size: 0.75rem; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔐 VaultKnox Dashboard</h1>
        <span class="status-badge" id="overallStatus">Loading...</span>
    </div>
    <div class="container">
        <div class="tabs">
            <button class="tab active" onclick="showTab('health')">Health</button>
            <button class="tab" onclick="showTab('credentials')">Credentials</button>
            <button class="tab" onclick="showTab('audit')">Audit</button>
            <button class="tab" onclick="showTab('scan')">Scanner</button>
        </div>
        
        <div id="healthTab">
            <div class="grid" id="healthStats">
                <div class="card stat"><div class="stat-value" id="secretCount">-</div><div class="stat-label">Secrets</div></div>
                <div class="card stat"><div class="stat-value" id="checkCount">-</div><div class="stat-label">Checks</div></div>
                <div class="card stat"><div class="stat-value" id="initStatus">-</div><div class="stat-label">Initialized</div></div>
                <div class="card stat"><div class="stat-value" id="unlockStatus">-</div><div class="stat-label">Unlocked</div></div>
            </div>
            <div class="card">
                <h2>Health Check Results</h2>
                <table id="healthTable">
                    <thead><tr><th>Check</th><th>Status</th><th>Message</th></tr></thead>
                    <tbody></tbody>
                </table>
            </div>
        </div>
        
        <div id="credentialsTab" style="display:none">
            <div class="card">
                <h2>Stored Credentials</h2>
                <table id="credentialsTable">
                    <thead><tr><th>ID</th><th>Type</th><th>Label</th><th>Created</th><th>Expires</th></tr></thead>
                    <tbody></tbody>
                </table>
            </div>
        </div>
        
        <div id="auditTab" style="display:none">
            <div class="card">
                <h2>Recent Audit Activity</h2>
                <table id="auditTable">
                    <thead><tr><th>Time</th><th>Action</th><th>Status</th><th>Secret ID</th></tr></thead>
                    <tbody></tbody>
                </table>
            </div>
        </div>
        
        <div id="scanTab" style="display:none">
            <div class="card">
                <h2>Scan for Plaintext Secrets</h2>
                <p style="color:#8b949e;margin-bottom:1rem">Scan Hermes directories for leaked secrets</p>
                <button class="btn" onclick="runScan()">Run Scan</button>
                <div id="scanResults" style="margin-top:1rem"></div>
            </div>
        </div>
    </div>
    <div class="footer">
        VaultKnox Dashboard v{{version}} • Token expires in 1 hour
    </div>
    <script>
        const token = new URLSearchParams(window.location.search).get('token');
        
        async function api(endpoint) {
            const resp = await fetch('/api/' + endpoint + '?token=' + token);
            return resp.json();
        }
        
        async function loadHealth() {
            const data = await api('health');
            document.getElementById('overallStatus').textContent = data.overall_status || 'unknown';
            document.getElementById('overallStatus').className = 'status-badge status-' + (data.overall_status || 'critical');
            
            document.getElementById('secretCount').textContent = data.secret_count || 0;
            document.getElementById('checkCount').textContent = (data.findings || []).length;
            
            const checks = data.findings || [];
            let passCount = 0, failCount = 0;
            checks.forEach(c => {
                if (c.status === 'pass') passCount++;
                if (c.status === 'fail') failCount++;
            });
            document.getElementById('initStatus').textContent = 'yes';
            document.getElementById('unlockStatus').textContent = data.unlocked ? 'yes' : 'no';
            
            const tbody = document.querySelector('#healthTable tbody');
            tbody.innerHTML = checks.map(c => '<tr><td>' + c.name + '</td><td><span class="badge">' + c.status + '</span></td><td>' + (c.message || '') + '</td></tr>').join('');
        }
        
        async function loadCredentials() {
            const data = await api('credentials');
            const secrets = data.secrets || [];
            document.getElementById('secretCount').textContent = secrets.length;
            
            const tbody = document.querySelector('#credentialsTable tbody');
            tbody.innerHTML = secrets.map(s => '<tr><td>' + s.id + '</td><td><span class="badge badge-' + s.type + '">' + s.type + '</span></td><td>' + s.label + '</td><td>' + (s.created_at || '') + '</td><td>' + (s.expires_at || '-') + '</td></tr>').join('') || '<tr><td colspan="5" style="text-align:center;color:#8b949e">No secrets stored</td></tr>';
        }
        
        async function loadAudit() {
            const data = await api('audit');
            const entries = data.entries || [];
            const tbody = document.querySelector('#auditTable tbody');
            tbody.innerHTML = entries.slice(0, 20).map(e => '<tr><td>' + e.time + '</td><td>' + e.action + '</td><td><span class="badge">' + e.status + '</span></td><td>' + (e.secret_id || '-') + '</td></tr>').join('') || '<tr><td colspan="4" style="text-align:center;color:#8b949e">No audit entries</td></tr>';
        }
        
        async function runScan() {
            const btn = event.target;
            btn.disabled = true;
            btn.textContent = 'Scanning...';
            
            const data = await api('scan');
            const findings = data.findings || [];
            
            document.getElementById('scanResults').innerHTML = '<p>Found ' + findings.length + ' issues</p>' + 
                findings.map(f => '<div class="card" style="margin:0.5rem 0"><strong>' + f.detector + '</strong> in ' + f.file + ' (line ' + f.line + ')</div>').join('');
            
            btn.disabled = false;
            btn.textContent = 'Run Scan';
        }
        
        function showTab(tab) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            event.target.classList.add('active');
            
            document.getElementById('healthTab').style.display = tab === 'health' ? 'block' : 'none';
            document.getElementById('credentialsTab').style.display = tab === 'credentials' ? 'block' : 'none';
            document.getElementById('auditTab').style.display = tab === 'audit' ? 'block' : 'none';
            document.getElementById('scanTab').style.display = tab === 'scan' ? 'block' : 'none';
        }
        
        // Load initial data
        loadHealth();
    </script>
</body>
</html>""".replace("{{version}}", __version__)


def _generate_token() -> str:
    """Generate an ephemeralBearer token for dashboard access."""
    return secrets.token_urlsafe(32)


def _verify_token(token: str, expected: str) -> bool:
    """Constant-time token verification."""
    return secrets.compare_digest(token, expected)


class DashboardServer:
    """Simple HTTP server for VaultKnox dashboard."""
    
    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.host = host
        self.port = port
        self.token = _generate_token()
        self.vault = VaultKnox(expand_runtime_path())
        
    def _get_status(self) -> dict[str, Any]:
        """Get vault status."""
        state = self.vault.status()
        return {
            "initialized": state.initialized,
            "unlocked": state.unlocked,
            "secret_count": state.secret_count,
            "auto_lock_minutes": state.auto_lock_minutes,
        }
    
    def _get_health(self) -> dict[str, Any]:
        """Get vault health."""
        # Always accessible - doesn't require unlock
        import os
        from vaultknox.config import expand_runtime_path
        
        paths = expand_runtime_path()
        checker = VaultHealthChecker(paths)
        report = checker.run_all_checks()
        
        status = self._get_status()
        
        return {
            "overall_status": report.overall_status,
            "unlocked": status["unlocked"],
            "secret_count": status["secret_count"],
            "findings": [{"name": c.name, "status": c.status.value, "message": c.message or ""} for c in report.checks],
        }
    
    def _get_credentials(self) -> dict[str, Any]:
        """Get credential metadata (requires unlock)."""
        status = self._get_status()
        if not status["unlocked"]:
            return {"error": "vault_locked", "secrets": []}
        
        secrets = self.vault.list_secrets()
        # Always mask - never expose raw secrets
        masked = []
        for s in secrets:
            masked.append({
                "id": s.get("id"),
                "type": s.get("type"),
                "label": s.get("label"),
                "created_at": s.get("created_at"),
                "updated_at": s.get("updated_at"),
                "expires_at": s.get("expires_at"),
            })
        
        return {"secrets": masked}
    
    def _get_audit(self) -> dict[str, Any]:
        """Get audit entries."""
        from vaultknox.audit import query_audit_log
        from vaultknox.config import expand_runtime_path
        
        paths = expand_runtime_path()
        try:
            entries = query_audit_log(paths.audit_log_path, limit=50)
        except Exception:
            entries = []
        
        return {"entries": entries}
    
    def _get_scan(self) -> dict[str, Any]:
        """Scan for plaintext secrets."""
        from vaultknox.config import expand_runtime_path
        
        paths = expand_runtime_path()
        home = paths.base_dir.parent
        
        scanner = SecretScanner(paths=[home])
        findings, perm_issues, stats = scanner.scan()
        
        return {
            "findings": [
                {"file": f.file_path, "line": f.line_number, "detector": f.detector_name, "severity": f.severity}
                for f in findings
            ],
            "permission_issues": [{"file": p.file_path, "issue": p.issue} for p in perm_issues],
            "stats": {
                "files_scanned": stats.files_scanned,
                "files_with_secrets": stats.files_with_secrets,
                "permission_issues": stats.permission_issues,
            }
        }
    
    def serve(self) -> None:
        """Start the HTTP server."""
        import http.server
        import socketserver
        from urllib.parse import urlparse, parse_qs
        
        # Store self for handler access
        DashboardServer._instance = self
        
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                parsed = urlparse(self.path)
                qs = parse_qs(parsed.query)

                # Check token - reject if missing OR invalid
                token = qs.get("token", [""])[0]
                if not token or not _verify_token(token, DashboardServer._instance.token):
                    self.send_error(401, "Unauthorized")
                    return

                if parsed.path == "/api/health":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(DashboardServer._instance._get_health()).encode())
                    return
                
                if parsed.path == "/api/credentials":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(DashboardServer._instance._get_credentials()).encode())
                    return
                
                if parsed.path == "/api/audit":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(DashboardServer._instance._get_audit()).encode())
                    return
                
                if parsed.path == "/api/scan":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(DashboardServer._instance._get_scan()).encode())
                    return
                
                # Serve dashboard HTML
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(_DASHBOARD_HTML.encode())
            
            def log_message(self, format, *args):
                # Suppress access logs
                pass
        
        with socketserver.TCPServer((self.host, self.port), Handler) as httpd:
            self.port = httpd.server_address[1]
            url = f"http://{self.host}:{self.port}/?token={self.token}"
            
            click.echo(f"VaultKnox Dashboard running at:")
            click.echo(url)
            click.echo("")
            click.echo("Press Ctrl+C to stop")
            
            # Optionally open browser
            # webbrowser.open(url)
            
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                click.echo("\nShutting down...")


@click.command()
@click.option("--host", default="127.0.0.1", help="Host to bind to")
@click.option("--port", default=0, type=int, help="Port (0 = auto)")
@click.option("--no-open", is_flag=True, help="Don't open browser automatically")
def dashboard(host: str, port: int, no_open: bool) -> None:
    """Start the VaultKnox Dashboard."""
    server = DashboardServer(host=host, port=port)
    server.serve()


def serve_dashboard(host: str = "127.0.0.1", port: int = 0, open_browser: bool = False) -> None:
    """Programmatic entry point for dashboard server.
    
    Args:
        host: Host to bind to
        port: Port (0 = auto-assign)
        open_browser: Whether to open browser automatically
    """
    server = DashboardServer(host=host, port=port)
    if open_browser:
        import webbrowser
        url = f"http://{server.host}:{server.port}/?token={server.token}"
        webbrowser.open(url)
    server.serve()


if __name__ == "__main__":
    dashboard()