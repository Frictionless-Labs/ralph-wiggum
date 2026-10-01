from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

from .errors import GitPolicyError, PreflightError
from .limits import WorkspaceBaseline, capture_workspace_baseline, workspace_limit_violation
from .provider import build_safe_env


_SECRET_NAMES = {".env", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}
_SECRET_SUFFIXES = (".pem", ".key", ".p12", ".pfx")


def _run(
    argv: Sequence[str],
    cwd: Path,
    *,
    check: bool = True,
    input_bytes: bytes | None = None,
) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            argv,
            cwd=cwd,
            env=build_safe_env(),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            input=input_bytes,
        )
    except FileNotFoundError as exc:
        raise PreflightError(f"required Git executable unavailable: {exc}") from exc
    if check and result.returncode != 0:
        diagnostic = result.stderr.decode("utf-8", "replace").strip()
        raise GitPolicyError(f"Git command failed ({' '.join(argv[:2])}): {diagnostic}")
    return result


def _decode_nul(payload: bytes) -> list[str]:
    return [item.decode("utf-8", "surrogateescape") for item in payload.split(b"\0") if item]


def _glob_regex(pattern: str) -> re.Pattern[str]:
    pieces = ["^"]
    index = 0
    while index < len(pattern):
        character = pattern[index]
        if character == "*":
            if index + 1 < len(pattern) and pattern[index + 1] == "*":
                if index + 2 < len(pattern) and pattern[index + 2] == "/":
                    pieces.append("(?:.*/)?")
                    index += 3
                    continue
                pieces.append(".*")
                index += 2
                continue
            pieces.append("[^/]*")
        elif character == "?":
            pieces.append("[^/]")
        else:
            pieces.append(re.escape(character))
        index += 1
    pieces.append("$")
    return re.compile("".join(pieces))


def _matches(path: str, patterns: Iterable[str]) -> bool:
    return any(_glob_regex(pattern).fullmatch(path) is not None for pattern in patterns)


def _secret_like(path: str) -> bool:
    name = Path(path).name.lower()
    return name in _SECRET_NAMES or name.startswith(".env.") or name.endswith(_SECRET_SUFFIXES)


def matches_path_patterns(path: str, patterns: Iterable[str]) -> bool:
    return _matches(path, patterns)


def is_secret_like(path: str) -> bool:
    return _secret_like(path)


@dataclass(frozen=True)
class GitWorkspace:
    source_repo: Path
    path: Path
    source_head: str
    baseline: WorkspaceBaseline

    @classmethod
    def create(cls, source_repo: Path, state_dir: Path, run_id: str, source_head: str) -> "GitWorkspace":
        source = source_repo.expanduser().resolve()
        actual_root = _run(("git", "rev-parse", "--show-toplevel"), source).stdout.decode().strip()
        if Path(actual_root).resolve() != source:
            raise PreflightError(f"repo must be its Git root: {source}")
        actual_head = _run(("git", "rev-parse", "HEAD"), source).stdout.decode().strip()
        if actual_head != source_head:
            raise PreflightError("source HEAD changed during preflight")
        worktree_path = state_dir.expanduser().resolve() / "worktrees" / run_id
        if worktree_path.exists():
            raise PreflightError(f"runtime worktree path already exists: {worktree_path}")
        worktree_path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        _run(("git", "worktree", "add", "--detach", str(worktree_path), source_head), source)
        try:
            baseline = capture_workspace_baseline(worktree_path)
        except OSError as exc:
            raise GitPolicyError(f"unable to establish workspace quota baseline: {exc}") from exc
        return cls(source, worktree_path, source_head, baseline)

    def enforce_workspace_limits(self) -> None:
        violation = workspace_limit_violation(self.path, self.baseline)
        if violation is not None:
            raise GitPolicyError(violation)

    def changed_paths(self) -> tuple[str, ...]:
        tracked = _decode_nul(_run(("git", "diff", "--name-only", "-z", "HEAD", "--"), self.path).stdout)
        untracked = _decode_nul(
            _run(("git", "ls-files", "--others", "--exclude-standard", "-z", "--"), self.path).stdout
        )
        return tuple(sorted(set(tracked + untracked)))

    def validate_manifest(
        self,
        allowed_paths: Sequence[str],
        protected_paths: Sequence[str],
        immutable_paths: Sequence[str] = (),
    ) -> tuple[str, ...]:
        self.enforce_workspace_limits()
        manifest = self.changed_paths()
        if not manifest:
            raise GitPolicyError("provider produced no candidate changes")
        for relative in manifest:
            if relative.startswith("/") or ".." in Path(relative).parts or "\x00" in relative:
                raise GitPolicyError(f"unsafe changed path: {relative}")
            if _secret_like(relative):
                raise GitPolicyError(f"secret-like changed path is prohibited: {relative}")
            if _matches(relative, protected_paths):
                raise GitPolicyError(f"protected changed path is prohibited: {relative}")
            if _matches(relative, immutable_paths) and self._exists_in_head(relative):
                raise GitPolicyError(f"immutable validator path is prohibited: {relative}")
            if not _matches(relative, allowed_paths):
                raise GitPolicyError(f"changed path is outside allowed paths: {relative}")
            candidate = self.path / relative
            head_mode = self._mode_in_head(relative)
            if candidate.is_symlink() or head_mode == "120000":
                raise GitPolicyError(f"symlink changed path is prohibited: {relative}")
            if head_mode == "160000":
                raise GitPolicyError(f"gitlink changed path is prohibited: {relative}")
            if candidate.is_dir():
                raise GitPolicyError(f"nested repository or directory entry is prohibited: {relative}")
        return manifest

    def _exists_in_head(self, relative: str) -> bool:
        return self._mode_in_head(relative) is not None

    def _mode_in_head(self, relative: str) -> str | None:
        output = _run(
            ("git", "--literal-pathspecs", "ls-tree", "HEAD", "--", relative), self.path
        ).stdout
        if not output:
            return None
        return output.split(b" ", 1)[0].decode("ascii", "strict")

    def ignored_digest(self) -> str:
        ignored = _decode_nul(
            _run(
                ("git", "ls-files", "--others", "--ignored", "--exclude-standard", "-z", "--"),
                self.path,
            ).stdout
        )
        digest = hashlib.sha256()
        for relative in sorted(ignored):
            digest.update(relative.encode("utf-8", "surrogateescape"))
            candidate = self.path / relative
            try:
                metadata = candidate.lstat()
            except FileNotFoundError:
                digest.update(b"\0missing\0")
                continue
            digest.update(str(stat.S_IMODE(metadata.st_mode)).encode())
            if stat.S_ISREG(metadata.st_mode):
                self._digest_file(digest, candidate)
            elif stat.S_ISLNK(metadata.st_mode):
                digest.update(os.readlink(candidate).encode("utf-8", "surrogateescape"))
            else:
                digest.update(b"\0non-regular\0")
        return digest.hexdigest()

    def candidate_digest(self, manifest: Sequence[str]) -> str:
        digest = hashlib.sha256()
        for relative in sorted(manifest):
            digest.update(relative.encode("utf-8", "surrogateescape"))
            candidate = self.path / relative
            try:
                metadata = candidate.lstat()
            except FileNotFoundError:
                digest.update(b"\0deleted\0")
                continue
            digest.update(str(stat.S_IMODE(metadata.st_mode)).encode())
            if stat.S_ISREG(metadata.st_mode):
                self._digest_file(digest, candidate)
            else:
                digest.update(b"\0non-regular\0")
        return digest.hexdigest()

    def workspace_digest(self) -> str:
        """Bind HEAD plus tracked, untracked, and ignored candidate state."""
        self.enforce_workspace_limits()
        manifest = self.changed_paths()
        digest = hashlib.sha256()
        digest.update(self.head().encode("ascii"))
        digest.update(self.candidate_digest(manifest).encode("ascii"))
        digest.update(self.ignored_digest().encode("ascii"))
        return digest.hexdigest()

    def stage_exact(self, manifest: Sequence[str]) -> str:
        _run(("git", "read-tree", "HEAD"), self.path)
        pathspec = b"".join(
            relative.encode("utf-8", "surrogateescape") + b"\0" for relative in manifest
        )
        _run(
            (
                "git",
                "--literal-pathspecs",
                "add",
                "-A",
                "--pathspec-from-file=-",
                "--pathspec-file-nul",
            ),
            self.path,
            input_bytes=pathspec,
        )
        staged = _decode_nul(_run(("git", "ls-files", "--stage", "-z"), self.path).stdout)
        manifest_set = set(manifest)
        for entry in staged:
            _, _, relative = entry.partition("\t")
            if relative not in manifest_set:
                continue
            mode = entry.split(" ", 1)[0]
            if mode not in {"100644", "100755"}:
                raise GitPolicyError(f"non-blob staged mode is prohibited: {mode}")
        return _run(("git", "write-tree"), self.path).stdout.decode().strip()

    @staticmethod
    def _digest_file(digest: "hashlib._Hash", path: Path) -> None:
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)

    def index_tree(self) -> str:
        return _run(("git", "write-tree"), self.path).stdout.decode().strip()

    def head(self) -> str:
        return _run(("git", "rev-parse", "HEAD"), self.path).stdout.decode().strip()

    def commit_verified(self, message: str) -> str:
        _run(
            (
                "git",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "commit.gpgSign=false",
                "commit",
                "-m",
                message,
            ),
            self.path,
        )
        return _run(("git", "rev-parse", "HEAD"), self.path).stdout.decode().strip()

    def commit_tree(self, commit: str) -> str:
        return _run(("git", "rev-parse", f"{commit}^{{tree}}"), self.path).stdout.decode().strip()
