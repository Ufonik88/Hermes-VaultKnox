"""Tests for VaultKnox Onboard — autonomous repository onboarding."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from vaultknox.onboard.analyzer.engine import AnalysisReport, RepoAnalyzer
from vaultknox.onboard.config import OnboardConfig
from vaultknox.onboard.documenter.engine import DocGenerator
from vaultknox.onboard.sandbox.executor import SandboxExecutor

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_node_project() -> Path:
    tmp = Path(tempfile.mkdtemp())
    (tmp / "package.json").write_text(json.dumps({
        "name": "test-project", "version": "1.0.0",
        "dependencies": {"express": "^4.18.0"},
        "devDependencies": {"jest": "^29.0.0"},
        "scripts": {"build": "tsc", "test": "jest", "lint": "eslint ."},
        "engines": {"node": ">=18"},
    }))
    (tmp / "src").mkdir(); (tmp / "src" / "index.js").write_text("console.log('hello');")  # noqa: E702
    (tmp / "tests").mkdir(); (tmp / "tests" / "index.test.js").write_text("test('works', () => {});")  # noqa: E702
    (tmp / "tsconfig.json").write_text(json.dumps({"compilerOptions": {"strict": True}}))
    (tmp / ".env.example").write_text("API_KEY=your_key_here\nDATABASE_URL=postgres://localhost:5432/db\n")
    return tmp


@pytest.fixture
def sample_python_project() -> Path:
    tmp = Path(tempfile.mkdtemp())
    (tmp / "pyproject.toml").write_text("""[project]
name = "test-python"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = ["click>=8.1.0"]
""")
    (tmp / "src").mkdir(); (tmp / "src" / "main.py").write_text("def main(): pass")  # noqa: E702
    (tmp / "tests").mkdir(); (tmp / "tests" / "test_main.py").write_text("def test_works(): assert True")  # noqa: E702
    return tmp


# ---------------------------------------------------------------------------
# Analyzer tests
# ---------------------------------------------------------------------------

class TestRepoAnalyzer:
    def test_analyze_node_project(self, sample_node_project: Path) -> None:
        config = OnboardConfig(repo_path=sample_node_project)
        analyzer = RepoAnalyzer(config)
        report = analyzer.analyze()
        assert isinstance(report, AnalysisReport)
        assert report.has_nodejs
        assert report.test_dirs == ["tests"]

    def test_analyze_python_project(self, sample_python_project: Path) -> None:
        config = OnboardConfig(repo_path=sample_python_project)
        analyzer = RepoAnalyzer(config)
        report = analyzer.analyze()
        assert isinstance(report, AnalysisReport)
        assert report.has_python
        assert report.test_dirs == ["tests"]

    def test_analyze_json(self, sample_node_project: Path) -> None:
        config = OnboardConfig(repo_path=sample_node_project)
        analyzer = RepoAnalyzer(config)
        report = analyzer.analyze()
        parsed = json.loads(report.to_json())
        assert parsed["repo_name"] == sample_node_project.name

    def test_no_cache_on_dry_run(self, sample_node_project: Path) -> None:
        config = OnboardConfig(repo_path=sample_node_project, dry_run=True)
        analyzer = RepoAnalyzer(config)
        analyzer.analyze()
        assert not (sample_node_project / ".vaultknox-onboard-cache").exists()


# ---------------------------------------------------------------------------
# Documenter tests
# ---------------------------------------------------------------------------

class TestDocGenerator:
    def test_generates_agents_md(self, sample_node_project: Path) -> None:
        config = OnboardConfig(repo_path=sample_node_project)
        report = RepoAnalyzer(config).analyze()
        doc_report = DocGenerator(config).generate_all(report)
        agents = [r for r in doc_report.results if r.filename == "AGENTS.md"]
        assert len(agents) == 1 and agents[0].generated
        content = (sample_node_project / "AGENTS.md").read_text()
        assert "AGENTS.md" in content and report.repo_name in content

    def test_generates_readme(self, sample_python_project: Path) -> None:
        config = OnboardConfig(repo_path=sample_python_project)
        report = RepoAnalyzer(config).analyze()
        doc_report = DocGenerator(config).generate_all(report)
        readme = [r for r in doc_report.results if r.filename == "README.md"]
        assert len(readme) == 1 and readme[0].generated

    def test_does_not_overwrite_user_readme(self, sample_node_project: Path) -> None:
        user_content = "## My Custom README"
        (sample_node_project / "README.md").write_text(user_content)
        config = OnboardConfig(repo_path=sample_node_project)
        report = RepoAnalyzer(config).analyze()
        doc_report = DocGenerator(config).generate_all(report)
        readme = [r for r in doc_report.results if r.filename == "README.md"]
        assert readme[0].skipped and "User-authored" in readme[0].skip_reason
        assert (sample_node_project / "README.md").read_text() == user_content

    def test_generates_all_docs(self, sample_node_project: Path) -> None:
        config = OnboardConfig(repo_path=sample_node_project)
        report = RepoAnalyzer(config).analyze()
        doc_report = DocGenerator(config).generate_all(report)
        assert {r.filename for r in doc_report.results} == {"AGENTS.md", "README.md", "SETUP.md", "ARCHITECTURE.md"}
        for r in doc_report.results:
            assert r.generated or r.skipped, f"Error for {r.filename}: {r.error}"


# ---------------------------------------------------------------------------
# Sandbox tests
# ---------------------------------------------------------------------------

class TestSandbox:
    def test_safe_command(self, sample_node_project: Path) -> None:
        executor = SandboxExecutor(repo_path=sample_node_project, allowed_commands=["echo"])
        result = executor.run("echo hello")
        assert result.success and "hello" in result.stdout

    def test_blocked_command(self, sample_node_project: Path) -> None:
        executor = SandboxExecutor(repo_path=sample_node_project, allowed_commands=[])
        result = executor.run("sudo rm -rf /")
        assert result.blocked and not result.success

    def test_timeout(self, sample_node_project: Path) -> None:
        executor = SandboxExecutor(repo_path=sample_node_project, allowed_commands=["sleep"], default_timeout=1)
        result = executor.run("sleep 10", timeout=1)
        assert not result.success

    def test_retry(self, sample_node_project: Path) -> None:
        executor = SandboxExecutor(repo_path=sample_node_project, allowed_commands=["echo"])
        result = executor.run_with_retry("echo works", retries=1)
        assert result.success


# ---------------------------------------------------------------------------
# Plugin tests
# ---------------------------------------------------------------------------

class TestPlugin:
    def test_detect_onboarding_trigger(self) -> None:
        from vaultknox.onboard.plugin import on_pre_gateway_dispatch
        result = on_pre_gateway_dispatch(user_message="please onboard this repo /Users/test/project")
        assert result is not None and result.get("action") == "onboard_repo"

    def test_no_trigger_for_normal_message(self) -> None:
        from vaultknox.onboard.plugin import on_pre_gateway_dispatch
        result = on_pre_gateway_dispatch(user_message="write a function that sorts an array")
        assert result is None

    def test_pre_llm_call_injects_snippet(self) -> None:
        from vaultknox.onboard.plugin import on_pre_llm_call
        result = on_pre_llm_call()
        assert result is not None and "onboard" in result.get("context", "")

    def test_pre_llm_skip_if_already_present(self) -> None:
        from vaultknox.onboard.plugin import on_pre_llm_call
        full_snippet = (
            "### Repository Onboarding\n\n"
            "Use `hermes-vault onboard analyze <repo>` to detect languages, frameworks, and dependencies.\n"
            "Use `hermes-vault onboard document <repo>` to generate AGENTS.md, README.md, SETUP.md.\n"
            "Use `hermes-vault onboard setup <repo>` to install deps and verify the build.\n"
            "Use `hermes-vault onboard full <repo>` for the complete pipeline."
        )
        result_with = on_pre_llm_call(conversation_history=[{"content": f"some prefix {full_snippet} some suffix"}])
        assert result_with is None

        result_without = on_pre_llm_call(conversation_history=[{"content": "just unrelated text"}])
        assert result_without is not None


# ---------------------------------------------------------------------------
# Skills tests
# ---------------------------------------------------------------------------

class TestSkills:
    def test_generate_onboard_skill(self, tmp_path: Path) -> None:
        from vaultknox.skills import generate_onboard_skill
        result = generate_onboard_skill(tmp_path)
        assert (tmp_path / "SKILL.md").exists()
        assert "path" in result and "content_hash" in result


    class TestSandboxSecurity:
        """Security regression tests for SandboxExecutor.

        These tests enforce the contract that the sandbox cannot be bypassed by
        shell metacharacters, environment leaks, or argument injection.
        """

        def test_shlex_split_preserves_quoted_args(self, sample_node_project: Path) -> None:
            executor = SandboxExecutor(repo_path=sample_node_project, allowed_commands=["echo"])
            result = executor.run('echo "hello world"')
            assert result.success
            assert "hello world" in result.stdout

        def test_shell_metacharacters_cannot_chain_commands(
            self, sample_node_project: Path
        ) -> None:
            executor = SandboxExecutor(
                repo_path=sample_node_project, allowed_commands=["echo"]
            )
            payload = "echo hello; rm -rf /"
            result = executor.run(payload)
            assert not result.success
            assert "hello" not in result.stdout

        def test_backtick_substitution_cannot_chain_commands(
            self, sample_node_project: Path
        ) -> None:
            executor = SandboxExecutor(
                repo_path=sample_node_project, allowed_commands=["echo"]
            )
            payload = "echo hello `rm -rf /`"
            result = executor.run(payload)
            assert not result.success
            assert "hello" not in result.stdout

        def test_semicolon_does_not_chain_execution(self, sample_node_project: Path) -> None:
            executor = SandboxExecutor(
                repo_path=sample_node_project, allowed_commands=["echo"]
            )
            # With shell=False, shlex.split turns this into
            # ['echo', 'BEFORE;', 'echo', 'AFTER'].
            # The shell never interprets the semicolon, so echo prints it literally
            # instead of running a second command.
            result = executor.run("echo BEFORE; echo AFTER")
            assert result.success
            assert result.stdout.strip() == "BEFORE; echo AFTER"

        def test_pipe_token_is_passed_as_literal_arg(self, sample_node_project: Path) -> None:
            executor = SandboxExecutor(
                repo_path=sample_node_project, allowed_commands=["echo"]
            )
            # With shell=False, `|` is not a pipe operator; it is argv[1].
            result = executor.run("echo hello | cat")
            assert result.success
            assert result.stdout.strip() == "hello | cat"

        def test_dollar_substitution_is_not_interpreted(self, sample_node_project: Path) -> None:
            executor = SandboxExecutor(
                repo_path=sample_node_project, allowed_commands=["echo"]
            )
            result = executor.run("echo '$(whoami)'")
            assert result.success
            assert "$(whoami)" in result.stdout

        def test_env_secrets_are_stripped_from_child(self, sample_node_project: Path) -> None:
            executor = SandboxExecutor(
                repo_path=sample_node_project, allowed_commands=["env"]
            )
            env_with_secrets = {
                "HOME": "/home/test",
                "GITHUB_TOKEN": "ghp_abc123secret",
                "DATABASE_URL": "postgres://localhost/db",
            }
            result = executor.run("env", env=env_with_secrets)
            assert result.success
            assert "ghp_abc123secret" not in result.stdout
            assert "GITHUB_TOKEN" not in result.stdout
            assert "DATABASE_URL" in result.stdout

        def test_sensitive_path_argument_is_blocked(self, sample_node_project: Path) -> None:
            executor = SandboxExecutor(
                repo_path=sample_node_project, allowed_commands=["cat"]
            )
            result = executor.run("cat /etc/passwd")
            assert result.blocked

        def test_timeout_kills_process_group(self, sample_node_project: Path) -> None:
            executor = SandboxExecutor(
                repo_path=sample_node_project,
                allowed_commands=["sleep"],
                default_timeout=2,
            )
            result = executor.run("sleep 30", timeout=2)
            assert not result.success
            assert "Timed out" in result.stderr
