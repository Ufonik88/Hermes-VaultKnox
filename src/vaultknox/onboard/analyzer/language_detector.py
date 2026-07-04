"""Language detection for repository analysis."""

from __future__ import annotations

from pathlib import Path

EXTENSION_LANGUAGE_MAP: dict[str, str] = {
    ".py": "Python", ".pyi": "Python", ".pyx": "Python",
    ".js": "JavaScript", ".jsx": "JavaScript (React)",
    ".ts": "TypeScript", ".tsx": "TypeScript (React)",
    ".mjs": "JavaScript (ESM)", ".cjs": "JavaScript (CJS)",
    ".mts": "TypeScript (ESM)", ".cts": "TypeScript (CJS)",
    ".html": "HTML", ".htm": "HTML",
    ".css": "CSS", ".scss": "SCSS", ".sass": "Sass", ".less": "Less",
    ".vue": "Vue", ".svelte": "Svelte",
    ".sh": "Shell", ".bash": "Bash", ".zsh": "Zsh", ".fish": "Fish",
    ".go": "Go",
    ".rs": "Rust",
    ".c": "C", ".h": "C (Header)",
    ".cpp": "C++", ".cc": "C++", ".cxx": "C++",
    ".hpp": "C++ (Header)", ".hh": "C++ (Header)",
    ".java": "Java", ".kt": "Kotlin", ".kts": "Kotlin (Script)",
    ".scala": "Scala", ".groovy": "Groovy",
    ".rb": "Ruby", ".erb": "Ruby (ERB)",
    ".php": "PHP",
    ".swift": "Swift",
    ".cs": "C#", ".fs": "F#", ".vb": "Visual Basic",
    ".dart": "Dart",
    ".lua": "Lua",
    ".r": "R", ".R": "R", ".rmd": "R Markdown",
    ".pl": "Perl", ".pm": "Perl (Module)",
    ".hs": "Haskell",
    ".ex": "Elixir", ".exs": "Elixir (Script)",
    ".zig": "Zig",
    ".jl": "Julia",
    ".json": "JSON", ".yaml": "YAML", ".yml": "YAML",
    ".toml": "TOML", ".ini": "INI", ".cfg": "Config",
    ".xml": "XML", ".csv": "CSV",
    ".md": "Markdown", ".mdx": "MDX",
    ".dockerfile": "Dockerfile",
    ".mk": "Makefile",
    ".sql": "SQL",
    ".proto": "Protocol Buffers",
    ".graphql": "GraphQL", ".gql": "GraphQL",
    ".tf": "Terraform", ".tfvars": "Terraform (Variables)",
    ".nix": "Nix",
    ".elm": "Elm",
    ".clj": "Clojure", ".cljs": "ClojureScript",
    ".erl": "Erlang",
    ".ml": "OCaml", ".mli": "OCaml (Interface)",
    ".re": "Reason",
    ".sol": "Solidity",
    ".move": "Move",
    ".cairo": "Cairo",
}

FRAMEWORK_INDICATORS: dict[str, str] = {
    "package.json": "Node.js",
    "package-lock.json": "npm",
    "yarn.lock": "Yarn",
    "pnpm-lock.yaml": "pnpm",
    "bun.lockb": "Bun",
    "tsconfig.json": "TypeScript",
    "next.config.js": "Next.js",
    "next.config.ts": "Next.js",
    "next.config.mjs": "Next.js",
    "nuxt.config.js": "Nuxt.js",
    "nuxt.config.ts": "Nuxt.js",
    "svelte.config.js": "SvelteKit",
    "vite.config.js": "Vite",
    "vite.config.ts": "Vite",
    "webpack.config.js": "Webpack",
    "rollup.config.js": "Rollup",
    "eslint.config.js": "ESLint",
    "eslint.config.mjs": "ESLint",
    ".eslintrc.js": "ESLint",
    ".eslintrc.json": "ESLint",
    "prettier.config.js": "Prettier",
    ".prettierrc": "Prettier",
    "tailwind.config.js": "Tailwind CSS",
    "tailwind.config.ts": "Tailwind CSS",
    "postcss.config.js": "PostCSS",
    "jest.config.js": "Jest",
    "jest.config.ts": "Jest",
    "vitest.config.ts": "Vitest",
    "playwright.config.ts": "Playwright",
    "requirements.txt": "pip",
    "requirements-dev.txt": "pip (dev)",
    "setup.py": "setuptools",
    "setup.cfg": "setuptools",
    "pyproject.toml": "Python (modern)",
    "Pipfile": "Pipenv",
    "Pipfile.lock": "Pipenv",
    "poetry.lock": "Poetry",
    "uv.lock": "uv",
    "tox.ini": "Tox",
    ".flake8": "Flake8",
    ".isort.cfg": "isort",
    "mypy.ini": "mypy",
    "go.mod": "Go Modules",
    "go.sum": "Go Modules",
    "Cargo.toml": "Cargo",
    "Cargo.lock": "Cargo",
    "Gemfile": "Bundler",
    "Gemfile.lock": "Bundler",
    "Rakefile": "Rake",
    "composer.json": "Composer",
    "composer.lock": "Composer",
    "pom.xml": "Maven",
    "build.gradle": "Gradle",
    "build.gradle.kts": "Gradle (Kotlin DSL)",
    "settings.gradle": "Gradle",
    "settings.gradle.kts": "Gradle (Kotlin DSL)",
    ".csproj": ".NET",
    ".sln": "Visual Studio Solution",
    "Dockerfile": "Docker",
    "docker-compose.yml": "Docker Compose",
    "docker-compose.yaml": "Docker Compose",
    ".github/workflows/": "GitHub Actions",
    ".gitlab-ci.yml": "GitLab CI",
    "Jenkinsfile": "Jenkins",
    ".travis.yml": "Travis CI",
    ".circleci/config.yml": "CircleCI",
    "Makefile": "Make",
    "CMakeLists.txt": "CMake",
    "meson.build": "Meson",
    "WORKSPACE": "Bazel",
    ".terraform.lock.hcl": "Terraform",
}


def detect_languages(repo_path: Path, max_files: int = 500) -> dict[str, dict]:
    """Detect programming languages by scanning file extensions.

    Returns dict mapping language -> {count, percentage, sample_files}.
    """
    extension_counts: dict[str, int] = {}
    sample_files: dict[str, list[str]] = {}
    total_scanned = 0

    skip_dirs = {
        ".git", "node_modules", "__pycache__", ".venv", "venv",
        "target", "build", "dist", ".next", ".nuxt", ".output",
        ".cache", "coverage", ".pytest_cache", ".mypy_cache",
        ".ruff_cache", ".hypothesis", "bower_components",
        ".terraform", ".serverless", "vendor",
    }

    for entry in repo_path.rglob("*"):
        if total_scanned >= max_files:
            break
        if any(part in skip_dirs for part in entry.parts):
            continue
        if entry.is_file():
            total_scanned += 1
            suffix = entry.suffix.lower()
            if suffix in EXTENSION_LANGUAGE_MAP:
                lang = EXTENSION_LANGUAGE_MAP[suffix]
                extension_counts[lang] = extension_counts.get(lang, 0) + 1
                if lang not in sample_files:
                    sample_files[lang] = []
                if len(sample_files[lang]) < 5:
                    sample_files[lang].append(str(entry.relative_to(repo_path)))

    for entry in repo_path.rglob("Dockerfile*"):
        if total_scanned < max_files and entry.is_file():
            extension_counts["Docker"] = extension_counts.get("Docker", 0) + 1

    total_files = sum(extension_counts.values()) or 1
    results: dict[str, dict] = {}
    for lang, count in sorted(extension_counts.items(), key=lambda x: -x[1]):
        results[lang] = {
            "count": count,
            "percentage": round(count / total_files * 100, 1),
            "sample_files": sample_files.get(lang, []),
        }
    return results


def detect_frameworks(repo_path: Path) -> dict[str, str]:
    """Detect frameworks and build systems by scanning for known config files."""
    detected: dict[str, str] = {}
    for entry in repo_path.rglob("*"):
        if entry.is_file():
            name = entry.name
            if name in FRAMEWORK_INDICATORS:
                framework = FRAMEWORK_INDICATORS[name]
                if framework not in detected:
                    detected[framework] = str(entry.relative_to(repo_path))
    gh_workflows = repo_path / ".github" / "workflows"
    if gh_workflows.is_dir():
        detected["GitHub Actions"] = ".github/workflows/"
    circleci = repo_path / ".circleci"
    if circleci.is_dir():
        detected["CircleCI"] = ".circleci/"
    return detected
