"""Configuration and path resolution for VaultKnox onboarding."""

from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class OnboardConfig:
    """Configuration for a repository onboarding session."""

    repo_path: Path
    """Absolute path to the repository."""

    scan_languages: bool = True
    scan_frameworks: bool = True
    scan_dependencies: bool = True
    scan_structure: bool = True
    scan_configs: bool = True

    generate_agents_md: bool = True
    generate_readme_md: bool = True
    generate_setup_md: bool = True
    generate_api_docs: bool = True
    generate_architecture: bool = True

    install_dependencies: bool = True
    run_build_checks: bool = True
    detect_env_vars: bool = True
    detect_secrets: bool = True

    dry_run: bool = False
    """If True, analyze and report but make no changes."""

    max_install_timeout_seconds: int = 600
    max_build_timeout_seconds: int = 300

    allowed_install_commands: list[str] = field(default_factory=lambda: [
        "pip", "npm", "yarn", "pnpm", "bun", "cargo", "go",
        "gem", "bundle", "composer", "mvn", "gradle", "poetry", "uv", "conda",
    ])

    blocked_directories: list[str] = field(default_factory=lambda: [
        "/etc", "/usr", "/bin", "/sbin", "/var", "/tmp",
        "/System", "/Library", "~/.ssh", "~/.gnupg",
    ])

    @property
    def repo_name(self) -> str:
        return self.repo_path.name

    @property
    def output_dir(self) -> Path:
        return self.repo_path

    @property
    def cache_dir(self) -> Path:
        return self.repo_path / ".vaultknox-onboard-cache"


def resolve_repo_path(path: str | Path) -> Path:
    """Resolve and validate a repository path.

    Handles local paths, git remote URLs, and tilde expansion.
    """
    path_str = str(path)

    if path_str.startswith(("git@", "https://", "http://")) and ".git" in path_str.split("/")[-1]:
        clone_dir = Path(tempfile.mkdtemp(prefix="vaultknox-onboard-"))
        result = subprocess.run(
            ["git", "clone", "--depth", "1", path_str, str(clone_dir)],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            clone_dir.rmdir()
            raise ValueError(f"Failed to clone repository: {result.stderr.strip()}")
        return clone_dir.resolve()

    resolved = Path(path_str).expanduser().resolve()
    if not resolved.exists():
        raise ValueError(f"Repository path does not exist: {resolved}")
    if not resolved.is_dir():
        raise ValueError(f"Repository path is not a directory: {resolved}")
    return resolved
