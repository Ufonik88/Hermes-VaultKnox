"""Registry of secret detector patterns for VaultKnox scanner.

Each detector defines a regex pattern to match a specific type of secret,
along with metadata about severity, description, and where it's commonly found.

Adding a new detector is as simple as adding a new entry to DETECTORS — no
scanner logic changes required.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Pattern


@dataclass(slots=True)
class Detector:
    """A secret detection pattern with associated metadata."""

    name: str
    pattern: Pattern[str]
    severity: str  # "critical" | "high" | "medium" | "low"
    description: str
    commonly_found_in: list[str] = field(default_factory=list)
    # Optional: for secrets that have a specific prefix we can validate
    # e.g., AWS keys start with AKIA, which is verifiable
    secret_prefix: str | None = None


# ---------------------------------------------------------------------------
# Built-in detector registry
# ---------------------------------------------------------------------------

DETECTORS: list[Detector] = []

PLACEHOLDER_ALLOWLIST = {
    "example",
    "placeholder",
    "changeme",
    "dummy",
    "test",
    "your-key-here",
}


def _register(
    name: str,
    pattern: str,
    severity: str,
    description: str,
    commonly_found_in: list[str] | None = None,
    secret_prefix: str | None = None,
) -> None:
    """Register a detector pattern with the global registry."""
    DETECTORS.append(
        Detector(
            name=name,
            pattern=re.compile(pattern),
            severity=severity,
            description=description,
            commonly_found_in=commonly_found_in or [],
            secret_prefix=secret_prefix,
        )
    )


# OpenAI
_register(
    name="OpenAI API Key",
    pattern=r"sk-[A-Za-z0-9_-]{20,}",
    severity="critical",
    description="OpenAI API key — grants access to OpenAI services",
    commonly_found_in=[".env", ".bashrc", ".zshrc", ".profile", "config.py"],
    secret_prefix="sk-",
)

# GitHub tokens (classic)
_register(
    name="GitHub Personal Access Token (classic)",
    pattern=r"ghp_[A-Za-z0-9]{36,}",
    severity="critical",
    description="GitHub personal access token (classic) — grants repository and GitHub API access",
    commonly_found_in=[".env", ".bashrc", ".zshrc", ".profile", ".github/workflows"],
    secret_prefix="ghp_",
)

# GitHub OAuth tokens
_register(
    name="GitHub OAuth Access Token",
    pattern=r"gho_[A-Za-z0-9]{36,}",
    severity="critical",
    description="GitHub OAuth access token",
    commonly_found_in=[".env", ".bashrc", ".zshrc", ".profile"],
    secret_prefix="gho_",
)

# GitHub fine-grained PAT
_register(
    name="GitHub Fine-Grained PAT",
    pattern=r"ghs_[A-Za-z0-9]{36,}",
    severity="critical",
    description="GitHub fine-grained personal access token",
    commonly_found_in=[".env", ".bashrc", ".zshrc", ".profile"],
    secret_prefix="ghs_",
)

# GitHub impersonation token
_register(
    name="GitHub Impersonation Token",
    pattern=r"ghu_[A-Za-z0-9]{36,}",
    severity="critical",
    description="GitHub impersonation token",
    commonly_found_in=[".env", ".bashrc", ".zshrc", ".profile"],
    secret_prefix="ghu_",
)

# GitHub refresh token
_register(
    name="GitHub Refresh Token",
    pattern=r"ghr_[A-Za-z0-9]{36,}",
    severity="critical",
    description="GitHub refresh token",
    commonly_found_in=[".env", ".bashrc", ".zshrc", ".profile"],
    secret_prefix="ghr_",
)

# Anthropic
_register(
    name="Anthropic API Key",
    pattern=r"sk-ant-[A-Za-z0-9_-]{40,}",
    severity="critical",
    description="Anthropic API key — grants access to Claude models",
    commonly_found_in=[".env", ".bashrc", ".zshrc", ".profile", "config.py"],
    secret_prefix="sk-ant-",
)

# AWS Access Key ID
_register(
    name="AWS Access Key ID",
    pattern=r"AKIA[A-Z0-9]{16}",
    severity="critical",
    description="AWS access key ID — pair with secret to access AWS services",
    commonly_found_in=[".env", ".aws/credentials", ".bashrc", ".zshrc", ".profile", "config.yaml", "config.yml"],
    secret_prefix="AKIA",
)

# AWS Secret Access Key (heuristic — no strict format, but often appears as part of key=value)
_register(
    name="AWS Secret Access Key (heuristic)",
    pattern=r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40,}['\"]?",
    severity="critical",
    description="AWS secret access key — high-value target for cloud attacks",
    commonly_found_in=[".env", ".aws/credentials", ".bashrc", ".zshrc", ".profile"],
)

# Generic patterns — *_KEY
_register(
    name="Generic API Key Pattern",
    pattern=r"(?i)(?:api[_-]?key|apikey)\s*[=:]\s*['\"]?[A-Za-z0-9_-]{20,}['\"]?",
    severity="high",
    description="Generic API key — likely a service API key",
    commonly_found_in=[".env", ".json", ".yaml", ".yml", "config.py", "settings.py"],
)

_register(
    name="Generic Secret Key Pattern",
    pattern=r"(?i)(?:secret[_-]?key|secretkey)\s*[=:]\s*['\"]?[A-Za-z0-9_-]{20,}['\"]?",
    severity="high",
    description="Generic secret key — may grant access to various services",
    commonly_found_in=[".env", ".json", ".yaml", ".yml", "config.py", "settings.py"],
)

# Generic TOKEN patterns
_register(
    name="Generic Access Token Pattern",
    pattern=r"(?i)access[_-]?token\s*[=:]\s*['\"]?[A-Za-z0-9_-]{20,}['\"]?",
    severity="high",
    description="Generic access token — may grant authorized access",
    commonly_found_in=[".env", ".json", ".yaml", ".yml", ".sh"],
)

_register(
    name="Generic Auth Token Pattern",
    pattern=r"(?i)auth[_-]?token\s*[=:]\s*['\"]?[A-Za-z0-9_-]{20,}['\"]?",
    severity="high",
    description="Generic auth token — used for authentication",
    commonly_found_in=[".env", ".json", ".yaml", ".yml", ".sh"],
)

# Generic PASSWORD patterns (usually less critical but still sensitive)
_register(
    name="Generic Password Pattern in Config",
    pattern=r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
    severity="medium",
    description="Hardcoded password in configuration file",
    commonly_found_in=[".env", ".json", ".yaml", ".yml", ".sh", "config.py", "settings.py"],
)

# Bearer token
_register(
    name="Bearer Token",
    pattern=r"(?i)bearer\s+(?:token\s*[=:]\s*)?['\"]?[A-Za-z0-9_-]{20,}['\"]?",
    severity="high",
    description="Bearer token — used in HTTP Authorization header",
    commonly_found_in=[".env", ".json", ".yaml", ".yml", ".sh"],
)

# Slack token
_register(
    name="Slack Token",
    pattern=r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,}",
    severity="critical",
    description="Slack token — grants access to Slack workspace",
    commonly_found_in=[".env", ".bashrc", ".zshrc", ".profile"],
    secret_prefix="xoxb-",
)

# Stripe
_register(
    name="Stripe Secret Key",
    pattern=r"sk_live_[A-Za-z0-9]{24,}",
    severity="critical",
    description="Stripe secret key — live mode, enables payment operations",
    commonly_found_in=[".env", ".bashrc", ".zshrc", ".profile"],
    secret_prefix="sk_live_",
)

_register(
    name="Stripe Publishable Key",
    pattern=r"pk_live_[A-Za-z0-9]{24,}",
    severity="medium",
    description="Stripe publishable key — safe to expose in client-side code",
    commonly_found_in=[".env", ".json", "config.py"],
    secret_prefix="pk_live_",
)

# Twilio
_register(
    name="Twilio API Key",
    pattern=r"SK[0-9a-fA-F]{32}",
    severity="critical",
    description="Twilio API key",
    commonly_found_in=[".env", ".bashrc", ".zshrc", ".profile"],
    secret_prefix="SK",
)

# SendGrid
_register(
    name="SendGrid API Key",
    pattern=r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
    severity="critical",
    description="SendGrid API key",
    commonly_found_in=[".env", ".bashrc", ".zshrc", ".profile"],
    secret_prefix="SG.",
)

# NPM token
_register(
    name="NPM Access Token",
    pattern=r"npm_[A-Za-z0-9]{36}",
    severity="critical",
    description="NPM access token — grants publish access to npm packages",
    commonly_found_in=[".npmrc", ".env"],
    secret_prefix="npm_",
)

# Private key (RSA/DSA/EC)
_register(
    name="RSA Private Key",
    pattern=r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
    severity="critical",
    description="Private key — grants cryptographic identity",
    commonly_found_in=[".ssh", "*.pem", "*.key", ".bashrc", ".zshrc", ".profile"],
)

# Generic *_SECRET pattern
_register(
    name="Generic Secret Pattern",
    pattern=r"(?i)[A-Za-z_][A-Za-z0-9_]*(?:secret)\s*[=:]\s*['\"]?[A-Za-z0-9_-]{16,}['\"]?",
    severity="high",
    description="Generic secret variable — value appears to be a secret",
    commonly_found_in=[".env", ".json", ".yaml", ".yml", ".sh"],
)

# Google API Key
_register(
    name="Google API Key",
    pattern=r"AIza[0-9A-Za-z\-_]{35}",
    severity="critical",
    description="Google API key",
    commonly_found_in=[".env", ".json", ".yaml", ".yml"],
    secret_prefix="AIza",
)

# GCP service account JSON private key marker
_register(
    name="GCP Service Account Private Key",
    pattern=r"-----BEGIN PRIVATE KEY-----",
    severity="critical",
    description="GCP service account private key material",
    commonly_found_in=[".json"],
)

# Azure connection string
_register(
    name="Azure Storage Connection String",
    pattern=r"DefaultEndpointsProtocol=https;AccountName=[^;\s]+;AccountKey=[^;\s]+;EndpointSuffix=[^;\s]+",
    severity="critical",
    description="Azure Storage connection string",
    commonly_found_in=[".env", ".json", ".yaml", ".yml"],
)

# JWT token
_register(
    name="JWT Token",
    pattern=r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    severity="high",
    description="JSON Web Token",
    commonly_found_in=[".env", ".json", ".yaml", ".yml", ".sh"],
)

# Generic high-entropy assignment (b64-ish token)
_register(
    name="High Entropy Secret Assignment",
    pattern=r"(?i)(?:token|secret|key|password)\s*[=:]\s*['\"]?[A-Za-z0-9+/=_-]{24,}['\"]?",
    severity="high",
    description="Potential high-entropy secret assignment",
    commonly_found_in=[".env", ".json", ".yaml", ".yml", ".sh", "config.py"],
)


def get_detector(name: str) -> Detector | None:
    """Retrieve a detector by name."""
    for d in DETECTORS:
        if d.name == name:
            return d
    return None


def get_detectors_by_severity(severity: str) -> list[Detector]:
    """Return all detectors matching the given severity level."""
    return [d for d in DETECTORS if d.severity == severity]


def get_detectors_for_file(filename: str) -> list[Detector]:
    """Return detectors commonly found in files matching the given filename pattern."""
    matching = []
    for d in DETECTORS:
        if any(filename.endswith(ext) or filename == ext for ext in d.commonly_found_in):
            matching.append(d)
    return matching
