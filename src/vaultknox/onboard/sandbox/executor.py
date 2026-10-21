"""Sandboxed execution — safe command running with whitelist, timeout, output limits.

Security model:
- shell=False (no /bin/sh interpretation).  Metacharacters such as `;`, `&&`,
  `$()`, backticks, pipes, and newlines cannot chain commands.
- argv is derived with shlex.split so quoted arguments stay intact.
- cwd is constrained to the repository tree.
- stdout/stderr are capped at max_output_bytes.
- process-group kill on timeout so child processes cannot survive the limit.
"""

from __future__ import annotations

import os
import shlex
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

BLOCKED_COMMAND_PATTERNS: list[str] = [
    "rm -rf /",
    "rm -rf ~",
    "rm -rf $HOME",
    "sudo ",
    "chmod 777",
    "chown ",
    "mkfs.",
    "dd if=",
    ":(){ :|:& };:",
    "> /dev/sda-blocked-device",
    "shutdown",
    "reboot",
    "halt",
    "poweroff",
]

# Paths that must never be touched, even as arguments to an otherwise allowed
# command.  Covers common secret-key material and system-critical directories.
BLOCKED_PATH_FRAGMENTS: tuple[str, ...] = (
    "/.ssh/",
    "/.gnupg/",
    "/etc/shadow",
    "/etc/passwd",
    "/proc/",
    "/sys/",
)


@dataclass(slots=True)
class SandboxResult:
    success: bool
    stdout: str
    stderr: str
    return_code: int
    command: str
    duration_seconds: float
    blocked: bool = False
    block_reason: str = ""


@dataclass(slots=True)
class SandboxExecutor:
    repo_path: Path
    allowed_commands: list[str] = field(default_factory=list)
    default_timeout: int = 300
    max_output_bytes: int = 1024 * 1024

    def __post_init__(self) -> None:
        if not self.repo_path.exists():
            raise ValueError(f"Repository path does not exist: {self.repo_path}")

    def run(
        self,
        command: str,
        *,
        timeout: int | None = None,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
    ) -> SandboxResult:
        block_reason = self._check_command(command)
        if block_reason:
            return SandboxResult(
                success=False,
                stdout="",
                stderr=block_reason,
                return_code=-1,
                command=command,
                duration_seconds=0.0,
                blocked=True,
                block_reason=block_reason,
            )

        try:
            argv = shlex.split(command)
        except ValueError as exc:
            return SandboxResult(
                success=False,
                stdout="",
                stderr=f"Command parsing failed: {exc}",
                return_code=-1,
                command=command,
                duration_seconds=0.0,
                blocked=True,
                block_reason="Malformed command",
            )

        block_reason = self._check_argv(argv)
        if block_reason:
            return SandboxResult(
                success=False,
                stdout="",
                stderr=block_reason,
                return_code=-1,
                command=command,
                duration_seconds=0.0,
                blocked=True,
                block_reason=block_reason,
            )

        effective_timeout = timeout or self.default_timeout
        work_dir = str(cwd) if cwd else str(self.repo_path)

        if not self._is_safe_path(work_dir):
            return SandboxResult(
                success=False,
                stdout="",
                stderr="Safety violation: working directory is outside repository",
                return_code=-1,
                command=command,
                duration_seconds=0.0,
                blocked=True,
                block_reason="Path outside repository",
            )

        merged_env = os.environ.copy()
        if env:
            merged_env.update(env)

        # Strip secrets from propagated environment.  We cannot ship secret
        # values to an arbitrary build/install script.
        merged_env = self._sanitize_env(merged_env)

        start = time.monotonic()
        try:
            process = subprocess.Popen(
                argv,
                shell=False,
                cwd=work_dir,
                env=merged_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
            stdout_lines: list[str] = []
            stderr_lines: list[str] = []
            stdout_total = [0]
            stderr_total = [0]

            def _read(stream, lines, total_ref):
                for line in iter(stream.readline, ""):
                    if total_ref[0] < self.max_output_bytes:
                        lines.append(line)
                        total_ref[0] += len(line)

            t1 = threading.Thread(target=_read, args=(process.stdout, stdout_lines, stdout_total))
            t2 = threading.Thread(target=_read, args=(process.stderr, stderr_lines, stderr_total))
            t1.start()
            t2.start()

            try:
                process.wait(timeout=effective_timeout)
            except subprocess.TimeoutExpired:
                self._kill_process_group(process.pid)
                t1.join(2)
                t2.join(2)
                return SandboxResult(
                    success=False,
                    stdout="".join(stdout_lines),
                    stderr="".join(stderr_lines) + f"\nTimed out after {effective_timeout}s",
                    return_code=-1,
                    command=command,
                    duration_seconds=time.monotonic() - start,
                )

            t1.join(5)
            t2.join(5)
            return SandboxResult(
                success=process.returncode == 0,
                stdout="".join(stdout_lines),
                stderr="".join(stderr_lines),
                return_code=process.returncode,
                command=command,
                duration_seconds=time.monotonic() - start,
            )
        except Exception as exc:
            return SandboxResult(
                success=False,
                stdout="",
                stderr=str(exc),
                return_code=-1,
                command=command,
                duration_seconds=time.monotonic() - start,
            )

    def run_with_retry(
        self,
        command: str,
        *,
        retries: int = 2,
        timeout: int | None = None,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
    ) -> SandboxResult:
        last = None
        for attempt in range(retries + 1):
            result = self.run(command, timeout=timeout, cwd=cwd, env=env)
            last = result
            if result.success or result.blocked:
                return result
            if attempt < retries:
                time.sleep(1 * (attempt + 1))
        assert last is not None
        return last

    def _check_command(self, command: str) -> str:
        # Pre-shlex sanity check (defense in depth — argv check is authoritative).
        cmd_lower = command.lower()
        for pattern in BLOCKED_COMMAND_PATTERNS:
            if pattern.lower() in cmd_lower:
                return f"Blocked dangerous command pattern: {pattern}"
        return ""

    def _check_argv(self, argv: list[str]) -> str:
        if not argv:
            return "Empty command"
        first = argv[0]
        if self.allowed_commands and first not in self.allowed_commands:
            return f"Command '{first}' is not in the allowed commands list"
        for arg in argv:
            for fragment in BLOCKED_PATH_FRAGMENTS:
                if fragment in arg:
                    return f"Blocked sensitive path in argument: {fragment}"
        return ""

    def _is_safe_path(self, path_str: str) -> bool:
        try:
            resolved = Path(path_str).resolve()
            repo_resolved = self.repo_path.resolve()
            return (
                str(resolved) == str(repo_resolved)
                or str(repo_resolved) in str(resolved) + os.sep
            )
        except Exception:
            return False

    @staticmethod
    def _sanitize_env(env: dict[str, str]) -> dict[str, str]:
        """Strip common secret-bearing variables from the child environment.

        This is a best-effort denylist.  It is not a substitute for running
        sandboxed code in a truly isolated environment (namespace, seccomp,
        or VM), but it blocks the most common leak path.
        """
        blocked_keys = frozenset(
            k.upper()
            for k in [
                "AWS_SECRET_ACCESS_KEY",
                "AWS_SESSION_TOKEN",
                "AZURE_CLIENT_SECRET",
                "GOOGLE_APPLICATION_CREDENTIALS",
                "GITHUB_TOKEN",
                "GH_TOKEN",
                "GITLAB_TOKEN",
                "OPENAI_API_KEY",
                "ANTHROPIC_API_KEY",
                "STRIPE_SECRET_KEY",
                "STRIPE_API_KEY",
                "TWILIO_AUTH_TOKEN",
                "VAPID_PRIVATE_KEY",
                "VAULTKNOX_MASTER_PASSWORD",
                "VAULTKNOX_TOKEN",
                "HERMES_VAULTKNOX_TOKEN",
                "NPM_TOKEN",
                "PYPI_TOKEN",
                "CARGO_TOKEN",
                "DOCKER_PASSWORD",
                "KUBECONFIG",
                "SSH_AUTH_SOCK",
                "GNUPGHOME",
                "PGP_KEY",
                "PRIVATE_KEY",
            ]
        )
        return {k: v for k, v in env.items() if k.upper() not in blocked_keys}

    @staticmethod
    def _kill_process_group(pid: int) -> None:
        try:
            os.killpg(os.getpgid(pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        except PermissionError:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
