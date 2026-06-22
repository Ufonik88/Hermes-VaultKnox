"""Policy engine for VaultKnox.

Per-agent, per-service action policies to control credential access.
v2 format with action allowlists and capability grants.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# Policy actions
ACTIONS = frozenset([
    "get_credential",  # Get raw credential (if allowed)
    "get_env",       # Get environment variable
    "get_metadata",  # Get metadata only (tokenized)
    "verify",       # Verify credential
    "rotate",       # Rotate credential
    "delete",       # Delete credential
    "add",         # Add new credential
])

# Agent capabilities
CAPABILITIES = frozenset([
    "list_credentials",
    "scan_secrets",
    "export_backup",
    "import_credentials",
])


@dataclass
class ServicePolicy:
    """Per-service policy configuration."""
    actions: list[str] = field(default_factory=list)
    max_ttl_seconds: int | None = None
    require_verification: bool = False


@dataclass
class AgentPolicy:
    """Per-agent policy configuration."""
    services: dict[str, ServicePolicy] = field(default_factory=dict)
    raw_secret_access: bool = False
    ephemeral_env_only: bool = True
    require_verification_before_reauth: bool = True
    max_ttl_seconds: int = 900
    capabilities: list[str] = field(default_factory=list)


class PolicyEngine:
    """Policy engine with v2 support."""
    
    def __init__(self, policy_path: Path | None = None):
        self.policy_path = policy_path
        self._agents: dict[str, AgentPolicy] = {}
        if policy_path and policy_path.exists():
            self._load()
    
    def _load(self) -> None:
        """Load policy from YAML."""
        if not self.policy_path or not self.policy_path.exists():
            return
        
        data = yaml.safe_load(self.policy_path.read_text()) or {}
        
        # Parse v2 format
        for agent_id, agent_data in data.get("agents", {}).items():
            services = {}
            for svc_id, svc_data in agent_data.get("services", {}).items():
                services[svc_id] = ServicePolicy(
                    actions=svc_data.get("actions", []),
                    max_ttl_seconds=svc_data.get("max_ttl_seconds"),
                    require_verification=svc_data.get("require_verification", False),
                )
            
            self._agents[agent_id] = AgentPolicy(
                services=services,
                raw_secret_access=agent_data.get("raw_secret_access", False),
                ephemeral_env_only=agent_data.get("ephemeral_env_only", True),
                require_verification_before_reauth=agent_data.get("require_verification_before_reauth", True),
                max_ttl_seconds=agent_data.get("max_ttl_seconds", 900),
                capabilities=agent_data.get("capabilities", []),
            )
    
    def save(self) -> None:
        """Save policy to YAML."""
        data = {"agents": {}, "version": "2"}
        
        for agent_id, agent_policy in self._agents.items():
            svc_dict = {}
            for svc_id, svc_policy in agent_policy.services.items():
                svc_dict[svc_id] = {
                    "actions": svc_policy.actions,
                }
                if svc_policy.max_ttl_seconds:
                    svc_dict[svc_id]["max_ttl_seconds"] = svc_policy.max_ttl_seconds
                if svc_policy.require_verification:
                    svc_dict[svc_id]["require_verification"] = True
            
            data["agents"][agent_id] = {
                "services": svc_dict,
                "raw_secret_access": agent_policy.raw_secret_access,
                "ephemeral_env_only": agent_policy.ephemeral_env_only,
                "require_verification_before_reauth": agent_policy.require_verification_before_reauth,
                "max_ttl_seconds": agent_policy.max_ttl_seconds,
                "capabilities": agent_policy.capabilities,
            }
        
        self.policy_path.parent.mkdir(parents=True, exist_ok=True)
        self.policy_path.write_text(yaml.dump(data, default_flow_style=False))
    
    def check_access(self, agent_id: str, service: str, action: str) -> bool:
        """Check if agent can perform action on service."""
        # Default: no access
        if agent_id not in self._agents:
            return False
        
        agent = self._agents[agent_id]
        
        # Check service-specific action
        if service in agent.services:
            return action in agent.services[service].actions
        
        # Deny by default
        return False
    
    def check_capability(self, agent_id: str, capability: str) -> bool:
        """Check if agent has a capability."""
        if agent_id not in self._agents:
            return False
        return capability in self._agents[agent_id].capabilities
    
    def can_get_raw_secret(self, agent_id: str, service: str) -> bool:
        """Check if agent can get raw secret (not just token)."""
        if agent_id not in self._agents:
            return False
        agent = self._agents[agent_id]
        
        if not agent.raw_secret_access:
            return False
        
        if service in agent.services:
            return "get_credential" in agent.services[service].actions
        return False
    
    def get_allowed_services(self, agent_id: str) -> list[str]:
        """Get list of services agent can access."""
        if agent_id not in self._agents:
            return []
        return list(self._agents[agent_id].services.keys())
    
    def set_policy(self, agent_id: str, policy: AgentPolicy) -> None:
        """Set agent policy."""
        self._agents[agent_id] = policy
    
    def add_service_access(self, agent_id: str, service: str, actions: list[str]) -> None:
        """Add service access for agent."""
        if agent_id not in self._agents:
            self._agents[agent_id] = AgentPolicy()
        
        self._agents[agent_id].services[service] = ServicePolicy(actions=actions)


# ── Policy Doctor ───────────────────────────────────────────────────────────────


class PolicyDoctor:
    """Diagnose policy issues."""
    
    def __init__(self, policy_path: Path):
        self.policy_path = Path(policy_path)
        self.engine = PolicyEngine(self.policy_path) if policy_path.exists() else PolicyEngine()
    
    def diagnose(self) -> list[dict[str, Any]]:
        """Run diagnostics."""
        issues = []
        
        if not self.policy_path.exists():
            issues.append({
                "severity": "warning",
                "code": "no_policy",
                "message": "No policy.yaml found - using deny-by-default",
            })
            return issues
        
        # Check for stale services (in policy but not in vault)
        from vaultknox.config import expand_runtime_path
        from vaultknox.vault import VaultKnox
        
        vault = VaultKnox(expand_runtime_path())
        vault_secrets = vault.list_secrets() if vault.status().unlocked else []
        vault_services = {s.get("id", "").split("-")[0] for s in vault_secrets}
        
        for agent_id, agent in self.engine._agents.items():
            for svc_id in agent.services:
                if svc_id not in vault_services and svc_id not in ("*", "all"):
                    issues.append({
                        "severity": "warning",
                        "code": "unknown_service",
                        "agent": agent_id,
                        "service": svc_id,
                        "message": "Service '" + svc_id + "' in policy but not in vault",
                    })
        
        return issues
    
    def generate_patch(self) -> str:
        """Generate YAML patch suggestion."""
        from vaultknox.config import expand_runtime_path
        from vaultknox.vault import VaultKnox
        
        vault = VaultKnox(expand_runtime_path())
        
        if not vault.status().unlocked:
            return "# Unlock vault to generate policy patch"
        
        secrets = vault.list_secrets()
        services = {}
        
        for s in secrets:
            metadata = s.get("metadata") or {}
            svc_id = metadata.get("service") if isinstance(metadata, dict) else None
            if not isinstance(svc_id, str) or not svc_id:
                sid = str(s.get("id", ""))
                if "-" in sid:
                    svc_id = sid.split("-")[0]
                elif "_" in sid:
                    svc_id = sid.split("_")[0]
                else:
                    svc_id = sid
            if svc_id not in services:
                services[svc_id] = ["get_metadata", "get_env", "verify"]
        
        patch = {"version": "2", "agents": {"operator": {"services": services}}}
        return yaml.dump(patch, default_flow_style=False)
