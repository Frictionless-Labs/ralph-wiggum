from __future__ import annotations

import os
import hashlib
import resource
import signal
import subprocess
import tempfile
import time
import math
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from io import BufferedRandom
from pathlib import Path
from typing import Mapping, Optional, Sequence

from .models import ProviderOutcome, ProviderResult
from .limits import capture_workspace_baseline, workspace_limit_violation


_ALLOWED_ENVIRONMENT = ("PATH", "HOME", "USER", "LOGNAME", "SHELL", "TMPDIR", "LANG", "LC_ALL")
_TRUSTED_PATH = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
_OUTPUT_FILE_LIMIT = 1_048_576
_OUTPUT_TAIL_LIMIT = 65_536
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_INTEGER_METRICS = {"stdoutBytes", "stderrBytes", "turns", "inputTokens", "outputTokens"}
_DIGEST_METRICS = {"stdoutSha256", "stderrSha256"}
_BOOLEAN_METRICS = {"stdoutTruncated", "stderrTruncated"}
_STRING_METRICS = {"resourceLimit"}
_FLOAT_METRICS = {"costUsd"}


@dataclass(frozen=True)
class CapturedOutput:
    text: str
    total_bytes: int
    sha256: str
    truncated: bool


def normalize_provider_metrics(result: ProviderResult) -> dict[str, object]:
    if not isinstance(result.metrics, Mapping):
        raise ValueError("provider metrics must be a mapping")
    normalized: dict[str, object] = {}
    allowed = (
        _INTEGER_METRICS
        | _DIGEST_METRICS
        | _BOOLEAN_METRICS
        | _STRING_METRICS
        | _FLOAT_METRICS
    )
    for key, value in result.metrics.items():
        if key not in allowed:
            raise ValueError(f"unsupported provider metric: {key}")
        if key in _INTEGER_METRICS:
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"provider metric {key} must be a non-negative integer")
        elif key in _DIGEST_METRICS:
            if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
                raise ValueError(f"provider metric {key} must be a SHA-256 digest")
        elif key in _BOOLEAN_METRICS:
            if not isinstance(value, bool):
                raise ValueError(f"provider metric {key} must be boolean")
        elif key in _STRING_METRICS:
            if not isinstance(value, str) or not value.strip() or len(value) > 1024:
                raise ValueError(f"provider metric {key} must be a bounded non-empty string")
        else:
            if (
                not isinstance(value, (int, float))
                or isinstance(value, bool)
                or not math.isfinite(value)
                or value < 0
            ):
                raise ValueError(f"provider metric {key} must be a non-negative finite number")
            value = float(value)
        normalized[key] = value
    return normalized


def limit_subprocess_output() -> None:
    resource.setrlimit(resource.RLIMIT_FSIZE, (_OUTPUT_FILE_LIMIT, _OUTPUT_FILE_LIMIT))


def read_captured_output(stream: BufferedRandom) -> CapturedOutput:
    stream.flush()
    total = stream.seek(0, os.SEEK_END)
    stream.seek(0)
    digest = hashlib.sha256()
    while chunk := stream.read(65_536):
        digest.update(chunk)
    stream.seek(max(0, total - _OUTPUT_TAIL_LIMIT))
    tail = stream.read(_OUTPUT_TAIL_LIMIT)
    return CapturedOutput(
        tail.decode("utf-8", "replace"),
        total,
        digest.hexdigest(),
        total > _OUTPUT_TAIL_LIMIT,
    )


def terminate_process_group(
    process: subprocess.Popen[str], grace_seconds: float = 1.0
) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except OSError:
        pass
    try:
        process.communicate(timeout=grace_seconds)
        return
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            pass
    try:
        process.communicate(timeout=grace_seconds)
        return
    except subprocess.TimeoutExpired:
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()
        try:
            process.wait(timeout=grace_seconds)
        except subprocess.TimeoutExpired:
            pass


def build_safe_env(extra: Optional[Mapping[str, str]] = None) -> dict[str, str]:
    environment = {
        key: os.environ[key] for key in _ALLOWED_ENVIRONMENT if key in os.environ and key != "PATH"
    }
    environment["PATH"] = _TRUSTED_PATH
    if extra:
        if "PATH" in extra:
            raise ValueError("PATH override is prohibited")
        environment.update(extra)
    return environment


class Provider(ABC):
    name: str
    allows_host_checks = False

    @abstractmethod
    def run(self, prompt: str, cwd: Path, timeout_seconds: float) -> ProviderResult:
        raise NotImplementedError


class CommandProvider(Provider):
    def __init__(
        self,
        name: str,
        argv: Sequence[str],
        extra_env: Optional[Mapping[str, str]] = None,
        preflight_argv: Optional[Sequence[str]] = None,
        *,
        allows_host_checks: bool = False,
    ) -> None:
        if not argv:
            raise ValueError("provider argv must not be empty")
        self.name = name
        self.argv = tuple(argv)
        self.extra_env = dict(extra_env or {})
        self.preflight_argv = tuple(preflight_argv or ())
        self.allows_host_checks = allows_host_checks

    def preflight(self, cwd: Path, timeout_seconds: float = 30.0) -> Optional[str]:
        if not self.preflight_argv:
            return None
        try:
            result = subprocess.run(
                self.preflight_argv,
                cwd=cwd,
                env=build_safe_env(self.extra_env),
                text=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                timeout=timeout_seconds,
                check=False,
            )
        except FileNotFoundError as exc:
            return f"provider preflight unavailable: {exc}"
        except subprocess.TimeoutExpired:
            return f"provider preflight exceeded {timeout_seconds:g} seconds"
        if result.returncode == 0:
            return None
        detail = result.stderr.strip()[-500:] or "no diagnostic"
        return f"provider preflight failed with exit {result.returncode}: {detail}"

    def run(self, prompt: str, cwd: Path, timeout_seconds: float) -> ProviderResult:
        started = time.monotonic()
        try:
            workspace_baseline = capture_workspace_baseline(cwd)
        except OSError as exc:
            return ProviderResult(
                ProviderOutcome.INTERNAL_ERROR,
                "",
                f"workspace quota baseline failed: {type(exc).__name__}",
                None,
                time.monotonic() - started,
            )
        with tempfile.TemporaryFile(mode="w+b") as stdout_file, tempfile.TemporaryFile(
            mode="w+b"
        ) as stderr_file:
            try:
                process = subprocess.Popen(
                    self.argv,
                    cwd=cwd,
                    env=build_safe_env(self.extra_env),
                    text=True,
                    stdin=subprocess.PIPE,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    start_new_session=True,
                    preexec_fn=limit_subprocess_output,
                )
            except FileNotFoundError as exc:
                return ProviderResult(
                    ProviderOutcome.UNAVAILABLE,
                    "",
                    str(exc),
                    None,
                    time.monotonic() - started,
                )
            timed_out = False
            resource_violation: str | None = None
            pending_input: str | None = prompt
            deadline = started + timeout_seconds
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    terminate_process_group(process)
                    break
                try:
                    process.communicate(pending_input, timeout=min(0.5, remaining))
                    break
                except KeyboardInterrupt:
                    terminate_process_group(process)
                    raise
                except subprocess.TimeoutExpired:
                    pending_input = None
                    resource_violation = workspace_limit_violation(cwd, workspace_baseline)
                    if resource_violation is not None:
                        terminate_process_group(process)
                        break
            if resource_violation is None:
                resource_violation = workspace_limit_violation(cwd, workspace_baseline)
            stdout_capture = read_captured_output(stdout_file)
            stderr_capture = read_captured_output(stderr_file)
        stdout = stdout_capture.text
        stderr = stderr_capture.text
        metrics = {
            "stdoutBytes": stdout_capture.total_bytes,
            "stderrBytes": stderr_capture.total_bytes,
            "stdoutSha256": stdout_capture.sha256,
            "stderrSha256": stderr_capture.sha256,
            "stdoutTruncated": stdout_capture.truncated,
            "stderrTruncated": stderr_capture.truncated,
        }
        if resource_violation is not None:
            metrics["resourceLimit"] = resource_violation
            return ProviderResult(
                ProviderOutcome.RESOURCE_LIMIT,
                stdout,
                f"{stderr}\n{resource_violation}".strip(),
                process.returncode,
                time.monotonic() - started,
                metrics,
            )
        if timed_out:
            return ProviderResult(
                ProviderOutcome.TIMEOUT,
                stdout,
                stderr,
                process.returncode,
                time.monotonic() - started,
                metrics,
            )
        duration = time.monotonic() - started
        if process.returncode != 0:
            combined = f"{stdout}\n{stderr}".lower()
            outcome = (
                ProviderOutcome.RATE_LIMIT
                if "rate limit" in combined or "too many requests" in combined or "429" in combined
                else ProviderOutcome.NONZERO
            )
            return ProviderResult(outcome, stdout, stderr, process.returncode, duration, metrics)
        if not stdout.strip():
            return ProviderResult(
                ProviderOutcome.EMPTY_OUTPUT, stdout, stderr, process.returncode, duration, metrics
            )
        return ProviderResult(
            ProviderOutcome.SUCCESS, stdout, stderr, process.returncode, duration, metrics
        )
