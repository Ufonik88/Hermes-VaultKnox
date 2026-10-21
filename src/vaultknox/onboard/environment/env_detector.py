"""Environment variable and secrets detector — scans codebase for required env vars and flags missing ones."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from vaultknox.onboard.analyzer.engine import AnalysisReport

_ENV_VAR_REGEXES: list[str] = [
    r"""os\.environ\[["']([A-Z][A-Z0-9_]{2,})["']\b""",
    r"""os\.environ\.get\(["']([A-Z][A-Z0-9_]{2,})["']""",
    r"""os\.getenv\(["']([A-Z][A-Z0-9_]{2,})["']""",
    r"""process\.env\.([A-Z][A-Z0-9_]{2,})\b""",
    r"""process\.env\[["']([A-Z][A-Z0-9_]{2,})["']\]""",
    r"""os\.Getenv\(["']([A-Z][A-Z0-9_]{2,})["']""",
    r"""env!\(["']([A-Z][A-Z0-9_]{2,})["']""",
    r"""std::env::var\(["']([A-Z][A-Z0-9_]{2,})["']""",
    r"""System\.getenv\(["']([A-Z][A-Z0-9_]{2,})["']""",
]

_FALSE_POSITIVES = {
    "PYTHONPATH", "PATH", "HOME", "USER", "SHELL", "LANG",
    "TERM", "PWD", "OLDPWD", "HOSTNAME", "DISPLAY", "EDITOR",
}

_COMMON_CODE_WORDS = {
    "TRUE", "FALSE", "NONE", "NULL", "UNDEFINED",
    "ASYNC", "AWAIT", "YIELD", "CLASS", "DEF",
    "IMPORT", "EXPORT", "RETURN", "RAISE", "THROW",
    "CONST", "LET", "VAR", "STATIC", "PUBLIC", "PRIVATE",
    "SOURCE", "TARGET", "BUILD", "DEBUG", "RELEASE",
}


def detect_missing_env_vars(report: AnalysisReport) -> dict[str, Any]:
    repo_path = Path(report.repo_path)
    result: dict[str, Any] = {
        "required_vars": [],
        "missing_vars": [],
        "secret_patterns": [],
        "has_env_example": False,
        "has_env_file": False,
    }

    env_example = repo_path / ".env.example"
    env_file = repo_path / ".env"

    if env_example.is_file():
        result["has_env_example"] = True
        result["required_vars"] = _parse_env_file(env_example)

    code_vars = _scan_code_for_env_vars(report)
    all_vars = set(result["required_vars"] + code_vars)
    result["required_vars"] = sorted(all_vars)

    result["secret_patterns"] = [
        v for v in result["required_vars"] if _is_secret_var(v)
    ]

    if env_file.is_file():
        present = set(_parse_env_file(env_file))
        result["missing_vars"] = sorted(set(result["required_vars"]) - present)
    else:
        result["missing_vars"] = sorted(result["required_vars"])

    return result


def _parse_env_file(env_path: Path) -> list[str]:
    vars_found: list[str] = []
    try:
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                name = line.split("=", 1)[0].strip()
                if name:
                    vars_found.append(name)
    except OSError:
        pass
    return vars_found


def _scan_code_for_env_vars(report: AnalysisReport) -> list[str]:
    repo_path = Path(report.repo_path)
    vars_found: list[str] = []
    compiled = [re.compile(p) for p in _ENV_VAR_REGEXES]

    scan_dirs = [repo_path / d for d in report.source_dirs] if report.source_dirs else [repo_path]
    extensions = {".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java", ".rb"}

    for scan_dir in scan_dirs:
        if not scan_dir.is_dir():
            continue
        for entry in scan_dir.rglob("*"):
            if entry.suffix.lower() in extensions and entry.is_file():
                try:
                    content = entry.read_text(encoding="utf-8")
                    for cre in compiled:
                        for m in cre.finditer(content):
                            name = m.group(1)
                            if name not in _FALSE_POSITIVES and _is_valid_env_var(name):
                                vars_found.append(name)
                except OSError:
                    continue
            if len(vars_found) > 50:
                break
        if len(vars_found) > 50:
            break
    return list(set(vars_found))


def _is_valid_env_var(name: str) -> bool:
    if not name:
        return False
    if not all(c.isupper() or c == "_" or c.isdigit() for c in name):
        return False
    if "_" not in name and len(name) > 6:
        return False
    return name not in _COMMON_CODE_WORDS


def _is_secret_var(name: str) -> bool:
    indicators = [
        "_KEY", "_TOKEN", "_SECRET", "_PASSWORD", "_CREDENTIALS",
        "_API_KEY", "_ACCESS_KEY", "PRIVATE_KEY", "AUTH_TOKEN",
        "DATABASE_URL", "DB_URL", "CONNECTION_STRING",
    ]
    return any(i in name.upper() for i in indicators)
