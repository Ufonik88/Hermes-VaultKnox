"""Structure mapper — maps repository layout and identifies key files."""

from __future__ import annotations

from pathlib import Path

_SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "target", "build", "dist", ".next", ".nuxt", ".output",
    ".cache", "coverage", ".pytest_cache", ".mypy_cache",
    ".ruff_cache", ".hypothesis", "bower_components",
    ".terraform", ".serverless", "vendor", ".turbo",
    ".parcel-cache", ".svelte-kit",
}

_KEY_FILE_PATTERNS: dict[str, list[str]] = {
    "entry_points": [
        "main.py", "app.py", "server.py", "index.py",
        "main.js", "index.js", "app.js", "server.js",
        "main.ts", "index.ts", "app.ts", "server.ts",
        "main.go", "main.rs", "src/main.rs",
        "Program.cs", "Main.java",
    ],
    "config_files": [
        ".env", ".env.example", ".env.local", ".env.development",
        "config.py", "config.js", "config.ts",
        "settings.py", "settings.js",
        "application.yml", "application.yaml",
        "app.config.js", "app.config.ts",
    ],
    "test_directories": ["tests", "test", "__tests__", "spec", "specs"],
    "documentation": [
        "README.md", "readme.md", "CONTRIBUTING.md",
        "CHANGELOG.md", "LICENSE", "LICENSE.md",
        "CODE_OF_CONDUCT.md", "SECURITY.md",
        "docs", "documentation",
    ],
    "source_directories": ["src", "lib", "app", "source", "pkg", "cmd", "internal", "packages", "modules"],
}


def map_structure(repo_path: Path, max_depth: int = 4) -> dict:
    result = {
        "entry_points": [], "config_files": [], "test_dirs": [],
        "doc_files": [], "source_dirs": [], "top_level_files": [],
        "stats": {"total_files": 0, "total_dirs": 0, "by_extension": {}},
    }

    for entry in sorted(repo_path.iterdir()):
        if entry.is_file() and not entry.name.startswith("."):
            result["top_level_files"].append(entry.name)

    for entry in sorted(repo_path.rglob("*")):
        parts = entry.relative_to(repo_path).parts
        if any(part in _SKIP_DIRS for part in parts):
            continue
        if any(part.startswith(".") and part != "." for part in parts if part):
            if entry.is_dir():
                continue
        if len(parts) > max_depth:
            continue

        if entry.is_file():
            result["stats"]["total_files"] += 1
            ext = entry.suffix.lower()
            result["stats"]["by_extension"][ext] = result["stats"]["by_extension"].get(ext, 0) + 1
            filename = entry.name
            rel_path = str(entry.relative_to(repo_path))
            if filename in _KEY_FILE_PATTERNS["entry_points"]:
                result["entry_points"].append(rel_path)
            if filename in _KEY_FILE_PATTERNS["config_files"]:
                result["config_files"].append(rel_path)
            if filename in _KEY_FILE_PATTERNS["documentation"]:
                result["doc_files"].append(rel_path)
        elif entry.is_dir():
            result["stats"]["total_dirs"] += 1
            dirname = entry.name
            rel_path = str(entry.relative_to(repo_path))
            if dirname in _KEY_FILE_PATTERNS["test_directories"]:
                result["test_dirs"].append(rel_path)
            if dirname in _KEY_FILE_PATTERNS["source_directories"]:
                result["source_dirs"].append(rel_path)
            if dirname in _KEY_FILE_PATTERNS["documentation"]:
                result["doc_files"].append(rel_path)

    return result
