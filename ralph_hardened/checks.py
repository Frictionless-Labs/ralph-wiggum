from __future__ import annotations

import os
import subprocess
import tempfile
import time
import uuid
import stat
from pathlib import Path
from typing import Optional, Sequence

from .models import CheckDefinition, CheckResult
from .gitops import materialize_index
from .provider import (
    build_safe_env,
    limit_subprocess_output,
    read_captured_output,
    terminate_process_group,
)


class CheckRunner:
    def _prepare_snapshot(
        self,
        definitions: Sequence[CheckDefinition],
        cwd: Path,
        temporary_root: Path,
    ) -> tuple[Path, Path]:
        snapshot = temporary_root / "candidate"
        scratch = temporary_root / "scratch"
        snapshot.mkdir()
        scratch.mkdir()
        materialize_index(cwd, snapshot)
        scratch_paths = sorted(
            {Path(relative) for definition in definitions for relative in definition.scratch_mounts}
        )
        for index, path in enumerate(scratch_paths):
            for other in scratch_paths[index + 1 :]:
                if path != other and path in other.parents:
                    raise ValueError(f"overlapping scratch mounts are prohibited: {path} and {other}")
        for definition in definitions:
            for relative in definition.scratch_mounts:
                target = snapshot / relative
                cursor = snapshot
                for part in Path(relative).parts:
                    cursor = cursor / part
                    if cursor.is_symlink():
                        raise ValueError(f"scratch mount traverses a symlink: {relative}")
                if target.exists() and not target.is_dir():
                    raise ValueError(f"scratch mount target is not a directory: {relative}")
                if target.is_dir() and any(target.iterdir()):
                    raise ValueError(f"scratch mount would hide staged content: {relative}")
                target.mkdir(parents=True, exist_ok=True)
                (scratch / relative).mkdir(parents=True, exist_ok=True)
        return snapshot, scratch

    def _argv(
        self,
        definition: CheckDefinition,
        cwd: Path,
        allow_host: bool,
        scratch_root: Optional[Path] = None,
        container_name: Optional[str] = None,
    ) -> tuple[tuple[str, ...], dict[str, str]]:
        if definition.container_image is None:
            if not allow_host:
                raise ValueError(f"check {definition.id} lacks a containerImage confinement boundary")
            return tuple(definition.argv), build_safe_env(definition.environment)
        argv = [
            "docker",
            "run",
            "--rm",
            "--name",
            container_name or f"ralph-check-{uuid.uuid4().hex}",
            "--pull=never",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges=true",
            "--network=bridge" if definition.network else "--network=none",
            "--pids-limit=256",
            "--memory=4g",
            "--cpus=2",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,size=512m",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "--env",
            "HOME=/tmp/ralph-home",
            "--env",
            "TMPDIR=/tmp",
            "--volume",
            f"{cwd}:/workspace:ro",
            "--workdir",
            "/workspace",
        ]
        if definition.scratch_mounts and scratch_root is None:
            raise ValueError(f"check {definition.id} lacks a scratch root")
        for relative, mode in sorted(definition.scratch_mounts.items()):
            assert scratch_root is not None
            source = self._safe_scratch_source(scratch_root, relative)
            argv.extend(("--volume", f"{source}:/workspace/{relative}:{mode}"))
        for key, value in sorted(definition.environment.items()):
            argv.extend(("--env", f"{key}={value}"))
        argv.append(definition.container_image)
        argv.extend(definition.argv)
        return tuple(argv), build_safe_env()

    @staticmethod
    def _safe_scratch_source(scratch_root: Path, relative: str) -> Path:
        root = scratch_root.resolve(strict=True)
        cursor = root
        for part in Path(relative).parts:
            cursor = cursor / part
            metadata = cursor.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise ValueError(f"scratch mount source traverses a symlink: {relative}")
        if not cursor.is_dir() or cursor.resolve(strict=True).parent != (root / relative).parent.resolve(
            strict=True
        ):
            raise ValueError(f"scratch mount source is not a contained directory: {relative}")
        try:
            cursor.resolve(strict=True).relative_to(root)
        except ValueError as exc:
            raise ValueError(f"scratch mount source escapes scratch root: {relative}") from exc
        return cursor

    def _run(
        self,
        definition: CheckDefinition,
        cwd: Path,
        *,
        allow_host: bool,
        scratch_root: Optional[Path],
    ) -> CheckResult:
        started = time.monotonic()
        container_name = (
            f"ralph-check-{os.getpid()}-{uuid.uuid4().hex[:12]}"
            if definition.container_image is not None
            else None
        )
        with tempfile.TemporaryFile(mode="w+b") as stdout_file, tempfile.TemporaryFile(
            mode="w+b"
        ) as stderr_file:
            try:
                argv, environment = self._argv(
                    definition, cwd, allow_host, scratch_root, container_name
                )
                process = subprocess.Popen(
                    argv,
                    cwd=cwd,
                    env=environment,
                    text=True,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    start_new_session=True,
                    preexec_fn=limit_subprocess_output,
                )
            except (FileNotFoundError, ValueError) as exc:
                return CheckResult(definition.id, False, None, "", str(exc), 0.0, "UNAVAILABLE")
            timed_out = False
            cleanup_succeeded = True
            try:
                process.communicate(timeout=definition.timeout_seconds)
            except KeyboardInterrupt:
                terminate_process_group(process)
                raise
            except subprocess.TimeoutExpired:
                timed_out = True
                terminate_process_group(process)
            finally:
                cleanup_succeeded = self._remove_container(container_name)
            stdout_capture = read_captured_output(stdout_file)
            stderr_capture = read_captured_output(stderr_file)
        stdout = stdout_capture.text
        stderr = stderr_capture.text
        if not cleanup_succeeded:
            outcome = "CLEANUP_FAILED"
        elif timed_out:
            outcome = "TIMEOUT"
        else:
            outcome = "PASS" if process.returncode == 0 else "FAIL"
        return CheckResult(
            definition.id,
            cleanup_succeeded and not timed_out and process.returncode == 0,
            process.returncode,
            stdout,
            stderr,
            time.monotonic() - started,
            outcome,
            stdout_capture.total_bytes,
            stderr_capture.total_bytes,
            stdout_capture.sha256,
            stderr_capture.sha256,
            stdout_capture.truncated,
            stderr_capture.truncated,
            definition.container_image,
        )

    def _remove_container(self, container_name: Optional[str]) -> bool:
        if container_name is None:
            return True
        try:
            result = subprocess.run(
                ("docker", "rm", "--force", container_name),
                env=build_safe_env(),
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        return result.returncode == 0 or "No such container" in result.stderr

    def run(
        self, definition: CheckDefinition, cwd: Path, *, allow_host: bool = False
    ) -> CheckResult:
        if definition.container_image is None:
            return self._run(
                definition, cwd, allow_host=allow_host, scratch_root=None
            )
        with tempfile.TemporaryDirectory(prefix="ralph-check-") as raw:
            try:
                snapshot, scratch = self._prepare_snapshot((definition,), cwd, Path(raw))
            except (OSError, ValueError) as exc:
                return CheckResult(
                    definition.id, False, None, "", str(exc), 0.0, "UNAVAILABLE"
                )
            return self._run(
                definition, snapshot, allow_host=allow_host, scratch_root=scratch
            )

    def run_all(
        self,
        definitions: Sequence[CheckDefinition],
        cwd: Path,
        *,
        allow_host: bool = False,
    ) -> tuple[CheckResult, ...]:
        if not any(definition.container_image is not None for definition in definitions):
            return tuple(
                self._run(
                    definition, cwd, allow_host=allow_host, scratch_root=None
                )
                for definition in definitions
            )
        with tempfile.TemporaryDirectory(prefix="ralph-checks-") as raw:
            try:
                snapshot, scratch = self._prepare_snapshot(definitions, cwd, Path(raw))
            except (OSError, ValueError) as exc:
                return tuple(
                    CheckResult(
                        definition.id,
                        False,
                        None,
                        "",
                        str(exc),
                        0.0,
                        "UNAVAILABLE",
                    )
                    for definition in definitions
                )
            return tuple(
                self._run(
                    definition,
                    snapshot if definition.container_image is not None else cwd,
                    allow_host=allow_host,
                    scratch_root=scratch,
                )
                for definition in definitions
            )
