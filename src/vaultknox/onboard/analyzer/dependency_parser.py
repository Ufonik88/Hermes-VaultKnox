"""Dependency parser — extracts dependencies from package manifests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def parse_package_json(repo_path: Path) -> dict[str, Any]:
    pkg_path = repo_path / "package.json"
    if not pkg_path.is_file():
        return {"found": False}
    try:
        data = json.loads(pkg_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"found": False, "error": "Failed to parse package.json"}
    deps: dict[str, dict[str, str]] = {}
    for section in ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]:
        section_data = data.get(section, {})
        if section_data:
            deps[section] = section_data
    return {
        "found": True, "name": data.get("name", ""), "version": data.get("version", ""),
        "dependencies": deps, "scripts": data.get("scripts", {}),
        "engines": data.get("engines", {}), "package_manager": data.get("packageManager", ""),
        "type": data.get("type", "commonjs"),
    }


def parse_pyproject_toml(repo_path: Path) -> dict[str, Any]:
    config_path = repo_path / "pyproject.toml"
    if not config_path.is_file():
        return {"found": False}
    try:
        import tomllib
    except ImportError:
        return {"found": False, "error": "tomllib not available"}
    try:
        data = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"found": False, "error": f"Failed to parse pyproject.toml: {exc}"}
    project = data.get("project", {})
    build_system = data.get("build-system", {})
    return {
        "found": True, "name": project.get("name", ""), "version": project.get("version", ""),
        "requires_python": project.get("requires-python", ""),
        "dependencies": project.get("dependencies", []),
        "optional_dependencies": project.get("optional-dependencies", {}),
        "build_system": build_system.get("build-backend", ""),
    }


def parse_requirements_txt(repo_path: Path) -> dict[str, Any]:
    req_path = repo_path / "requirements.txt"
    if not req_path.is_file():
        return {"found": False}
    lines: list[str] = []
    try:
        for raw_line in req_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if line and not line.startswith("#") and not line.startswith("-"):
                lines.append(line)
    except OSError:
        return {"found": False, "error": "Failed to read requirements.txt"}
    return {"found": True, "dependencies": lines, "count": len(lines)}


def parse_cargo_toml(repo_path: Path) -> dict[str, Any]:
    config_path = repo_path / "Cargo.toml"
    if not config_path.is_file():
        return {"found": False}
    try:
        import tomllib
    except ImportError:
        return {"found": False, "error": "tomllib not available"}
    try:
        data = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"found": False, "error": f"Failed to parse Cargo.toml: {exc}"}
    package = data.get("package", {})
    return {
        "found": True, "name": package.get("name", ""), "version": package.get("version", ""),
        "edition": package.get("edition", ""),
        "dependencies": data.get("dependencies", {}),
        "dev_dependencies": data.get("dev-dependencies", {}),
    }


def parse_go_mod(repo_path: Path) -> dict[str, Any]:
    mod_path = repo_path / "go.mod"
    if not mod_path.is_file():
        return {"found": False}
    try:
        content = mod_path.read_text(encoding="utf-8")
    except OSError:
        return {"found": False, "error": "Failed to read go.mod"}
    lines = content.splitlines()
    module = ""
    go_version = ""
    requires: list[str] = []
    in_require = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("module "):
            module = stripped.split("module ", 1)[1].strip()
        elif stripped.startswith("go "):
            go_version = stripped.split("go ", 1)[1].strip()
        elif stripped.startswith("require ("):
            in_require = True
        elif in_require:
            if stripped == ")":
                in_require = False
            elif stripped and not stripped.startswith("//"):
                requires.append(stripped)
    return {"found": True, "module": module, "go_version": go_version, "dependencies": requires, "count": len(requires)}


def parse_gemfile(repo_path: Path) -> dict[str, Any]:
    gem_path = repo_path / "Gemfile"
    if not gem_path.is_file():
        return {"found": False}
    try:
        content = gem_path.read_text(encoding="utf-8")
    except OSError:
        return {"found": False, "error": "Failed to read Gemfile"}
    gems = [line.strip() for line in content.splitlines() if line.strip().lower().startswith("gem ")]
    return {"found": True, "dependencies": gems, "count": len(gems)}


def parse_composer_json(repo_path: Path) -> dict[str, Any]:
    comp_path = repo_path / "composer.json"
    if not comp_path.is_file():
        return {"found": False}
    try:
        data = json.loads(comp_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"found": False, "error": "Failed to parse composer.json"}
    return {
        "found": True, "name": data.get("name", ""), "description": data.get("description", ""),
        "require": data.get("require", {}), "require_dev": data.get("require-dev", {}),
    }


PARSER_REGISTRY: list[tuple[str, callable]] = [
    ("package.json", parse_package_json),
    ("pyproject.toml", parse_pyproject_toml),
    ("requirements.txt", parse_requirements_txt),
    ("Cargo.toml", parse_cargo_toml),
    ("go.mod", parse_go_mod),
    ("Gemfile", parse_gemfile),
    ("composer.json", parse_composer_json),
]


def parse_all_dependencies(repo_path: Path) -> dict[str, Any]:
    results: dict[str, Any] = {}
    name_map = {
        "package.json": "nodejs", "pyproject.toml": "python",
        "requirements.txt": "python_requirements", "Cargo.toml": "rust",
        "go.mod": "go", "Gemfile": "ruby", "composer.json": "php",
    }
    for filename, parser in PARSER_REGISTRY:
        if (repo_path / filename).is_file():
            key = name_map.get(filename, filename)
            results[key] = parser(repo_path)
    return results
