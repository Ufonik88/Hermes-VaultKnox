"""MCP server transport for VaultKnox.

Exposes VaultKnox capabilities as MCP tools over stdio.
Tool calls are brokered through VaultKnox for policy enforcement.
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from vaultknox import __version__
from vaultknox.config import VaultPaths, expand_runtime_path

logger = logging.getLogger("vaultknox.mcp")

# Tool schemas matching VaultKnox capabilities
_TOOL_SCHEMAS = {
    "vaultknox_status": {
        "type": "object",
        "properties": {},
    },
    "vaultknox_list": {
        "type": "object",
        "properties": {
            "filter": {"type": "string", "description": "Optional substring filter"},
        },
    },
    "vaultknox_get_metadata": {
        "type": "object",
        "properties": {
            "secret_id": {"type": "string", "description": "Secret ID or label"},
        },
        "required": ["secret_id"],
    },
    "vaultknox_scan": {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Path to scan (default: ~/.hermes)"},
        },
    },
    "vaultknox_verify": {
        "type": "object",
        "properties": {
            "secret_id": {"type": "string", "description": "Secret ID or service name"},
        },
        "required": ["secret_id"],
    },
    "vaultknox_health": {
        "type": "object",
        "properties": {},
    },
}


def _create_server() -> Server:
    """Create and configure the MCP server."""
    server = Server("vaultknox", __version__)

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        """List available VaultKnox MCP tools."""
        return [
            Tool(
                name="vaultknox_status",
                description="Get VaultKnox status (initialized, unlocked, secret count)",
                inputSchema=_TOOL_SCHEMAS["vaultknox_status"],
            ),
            Tool(
                name="vaultknox_list",
                description="List all secrets in the vault (masked)",
                inputSchema=_TOOL_SCHEMAS["vaultknox_list"],
            ),
            Tool(
                name="vaultknox_get_metadata",
                description="Get secret metadata by ID (without exposing raw secrets)",
                inputSchema=_TOOL_SCHEMAS["vaultknox_get_metadata"],
            ),
            Tool(
                name="vaultknox_scan",
                description="Scan files for plaintext secrets",
                inputSchema=_TOOL_SCHEMAS["vaultknox_scan"],
            ),
            Tool(
                name="vaultknox_verify",
                description="Verify a credential against its provider endpoint",
                inputSchema=_TOOL_SCHEMAS["vaultknox_verify"],
            ),
            Tool(
                name="vaultknox_health",
                description="Get vault health status (stale, expiring, expired secrets)",
                inputSchema=_TOOL_SCHEMAS["vaultknox_health"],
            ),
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any] | None) -> list[TextContent]:
        """Handle tool calls."""
        from vaultknox.scanner import SecretScanner
        from vaultknox.health import VaultHealthChecker

        # Import here to avoid circular imports
        from vaultknox.vault import VaultKnox
        from vaultknox.config import get_default_paths
        from vaultknox.health import run_health_checks

        try:
            paths = get_default_paths()
            vault = VaultKnox(paths)

            if name == "vaultknox_status":
                status = vault.status()
                return [TextContent(type="text", text=json.dumps({
                    "initialized": status.initialized,
                    "unlocked": status.unlocked,
                    "secret_count": status.secret_count,
                    "auto_lock_minutes": status.auto_lock_minutes,
                }))]

            if name == "vaultknox_list":
                # Require unlocked session
                if not vault.status().unlocked:
                    return [TextContent(type="text", text=json.dumps({
                        "error": "vault_locked",
                        "message": "Vault is locked. Unlock via CLI first."
                    }))]

                filter_str = arguments.get("filter", "") if arguments else ""
                secrets = vault.list_secrets()

                if filter_str:
                    secrets = [s for s in secrets 
                             if filter_str.lower() in s.get("label", "").lower() 
                             or filter_str.lower() in s.get("id", "").lower()]

                # Return masked metadata only
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

                return [TextContent(type="text", text=json.dumps({"secrets": masked}))]

            if name == "vaultknox_get_metadata":
                if not vault.status().unlocked:
                    return [TextContent(type="text", text=json.dumps({
                        "error": "vault_locked",
                        "message": "Vault is locked."
                    }))]

                secret_id = (arguments.get("secret_id") if arguments else None)
                if not secret_id:
                    return [TextContent(type="text", text=json.dumps({
                        "error": "missing_secret_id"
                    }))]

                # Get masked view - doesn't expose raw secret
                try:
                    result = vault.get_masked(secret_id)
                    return [TextContent(type="text", text=json.dumps(result))]
                except KeyError:
                    return [TextContent(type="text", text=json.dumps({
                        "error": "not_found",
                        "secret_id": secret_id
                    }))]

            if name == "vaultknox_scan":
                scan_path_arg = (arguments.get("path") if arguments else None) or "~/.hermes"
                scan_path = Path(scan_path_arg.replace("~", str(paths.home)))

                # SecretScanner takes paths at init time and scan() takes no args
                scanner = SecretScanner(paths=[scan_path])
                findings, perm_issues, stats = scanner.scan()

                # Format findings for MCP response
                formatted = []
                for f in findings:
                    formatted.append({
                        "file": f.file_path,
                        "line": f.line_number,
                        "detector": f.detector_name,
                        "severity": f.severity,
                    })

                return [TextContent(type="text", text=json.dumps({
                    "findings": formatted,
                    "scan_path": str(scan_path),
                    "total": len(formatted),
                    "stats": {
                        "files_scanned": stats.files_scanned,
                        "files_with_secrets": stats.files_with_secrets,
                        "permission_issues": stats.permission_issues,
                    }
                }))]

            if name == "vaultknox_verify":
                if not vault.status().unlocked:
                    return [TextContent(type="text", text=json.dumps({
                        "error": "vault_locked"
                    }))]

                secret_id = (arguments.get("secret_id") if arguments else None)
                if not secret_id:
                    return [TextContent(type="text", text=json.dumps({
                        "error": "missing_secret_id"
                    }))]

                try:
                    # Need password for get_secret
                    # MCP doesn't have master password - return error
                    return [TextContent(type="text", text=json.dumps({
                        "error": "requires_master_password",
                        "message": "Verify requires vault unlock with master password via CLI"
                    }))]
                except Exception as e:
                    return [TextContent(type="text", text=json.dumps({
                        "error": "verification_failed",
                        "message": str(e)
                    }))]

            if name == "vaultknox_health":
                # Run health checks using VaultHealthChecker
                checker = VaultHealthChecker(paths)
                report = checker.run_all_checks()

                # Format for MCP response
                findings = []
                for c in report.checks:
                    findings.append({
                        "name": c.name,
                        "status": c.status.value,
                        "message": c.message or "",
                    })

                return [TextContent(type="text", text=json.dumps({
                    "overall_status": report.overall_status,
                    "findings": findings,
                }))]

            return [TextContent(type="text", text=json.dumps({"error": "unknown_tool"}))]

        except Exception as e:
            logger.exception("MCP tool call failed")
            return [TextContent(type="text", text=json.dumps({
                "error": "internal_error",
                "message": str(e)
            }))]

    return server


def run_mcp_server() -> None:
    """Entry point for MCP stdio server."""
    server = _create_server()
    stdio_server.run_server(server)


if __name__ == "__main__":
    run_mcp_server()