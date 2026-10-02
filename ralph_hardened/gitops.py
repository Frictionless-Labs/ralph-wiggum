from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .errors import GitPolicyError, PreflightError
from .limits import WorkspaceBaseline, capture_workspace_baseline, workspace_limit_violation
from .provider import build_safe_env


_SECRET_NAMES = {".env", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}
_SECRET_SUFFIXES = (".pem", ".key", ".p12", ".pfx")


def _digest_field(digest: "hashlib._Hash", value: bytes) -> None:
    """Hash one unambiguously framed field without delimiter assumptions."""
    digest.update(len(value).to_bytes(8, "big"))
    digest.update(value)


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
    for component in Path(path).parts:
        name = component.lower()
        if name in _SECRET_NAMES or name.startswith(".env.") or name.endswith(_SECRET_SUFFIXES):
            return True
    return False


def matches_path_patterns(path: str, patterns: Iterable[str]) -> bool:
    return _matches(path, patterns)


def is_secret_like(path: str) -> bool:
    return _secret_like(path)


def materialize_index(cwd: Path, destination: Path) -> None:
    """Materialize the current index without running Git content filters."""
    result = subprocess.run(
        ("git", "ls-files", "--stage", "-z"),
        cwd=cwd,
        env=build_safe_env(),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise ValueError(f"unable to enumerate evaluated tree: {detail}")
    for entry in result.stdout.split(b"\0"):
        if not entry:
            continue
        metadata, separator, encoded_path = entry.partition(b"\t")
        fields = metadata.split()
        if not separator or len(fields) != 3 or fields[2] != b"0":
            raise ValueError("evaluated tree contains an invalid index entry")
        mode, object_id, _ = fields
        relative = encoded_path.decode("utf-8", "surrogateescape")
        relative_path = Path(relative)
        if (
            relative_path.is_absolute()
            or ".." in relative_path.parts
            or ".git" in relative_path.parts
        ):
            raise ValueError(f"evaluated tree contains an unsafe path: {relative}")
        target = destination / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        if mode == b"160000":
            target.mkdir(exist_ok=True)
            continue
        if mode not in {b"100644", b"100755", b"120000"}:
            raise ValueError(f"evaluated tree contains unsupported mode: {mode!r}")
        temporary_target = target
        if mode == b"120000":
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{target.name}.", suffix=".link", dir=target.parent
            )
            os.close(descriptor)
            temporary_target = Path(temporary_name)
        try:
            with temporary_target.open("wb") as stream:
                process = subprocess.Popen(
                    ("git", "cat-file", "blob", object_id.decode("ascii", "strict")),
                    cwd=cwd,
                    env=build_safe_env(),
                    stdout=stream,
                    stderr=subprocess.PIPE,
                    start_new_session=True,
                )
                _, stderr = process.communicate()
            if process.returncode != 0:
                detail = stderr.decode("utf-8", "replace").strip()
                raise ValueError(f"unable to read evaluated blob {relative}: {detail}")
            if mode == b"120000":
                if temporary_target.stat().st_size > 65_536:
                    raise ValueError(f"evaluated symlink target is too large: {relative}")
                link_target = os.fsdecode(temporary_target.read_bytes())
                temporary_target.unlink()
                os.symlink(link_target, target)
            else:
                target.chmod(0o755 if mode == b"100755" else 0o644)
        except BaseException:
            if temporary_target.exists() and not temporary_target.is_symlink():
                temporary_target.unlink()
            raise


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
        state_root = Path(os.path.abspath(state_dir.expanduser()))
        if os.path.lexists(state_root):
            if state_root.is_symlink() or not state_root.is_dir():
                raise PreflightError(f"state root must be a real directory: {state_root}")
        else:
            state_root.mkdir(parents=True, mode=0o700)
        if state_root.is_symlink() or not state_root.is_dir():
            raise PreflightError(f"state root must be a real directory: {state_root}")
        worktrees_root = state_root / "worktrees"
        if os.path.lexists(worktrees_root):
            if worktrees_root.is_symlink() or not worktrees_root.is_dir():
                raise PreflightError(
                    f"worktrees root must be a real directory: {worktrees_root}"
                )
        else:
            worktrees_root.mkdir(mode=0o700)
        if worktrees_root.resolve().parent != state_root.resolve():
            raise PreflightError("worktrees root escapes the state directory")
        worktree_path = worktrees_root / run_id
        if os.path.lexists(worktree_path):
            raise PreflightError(f"runtime worktree path already exists: {worktree_path}")
        _run(
            (
                "git",
                "-c",
                "core.hooksPath=/dev/null",
                "worktree",
                "add",
                "--no-checkout",
                "--detach",
                str(worktree_path),
                source_head,
            ),
            source,
        )
        try:
            _run(("git", "read-tree", "HEAD"), worktree_path)
            materialize_index(worktree_path, worktree_path)
        except (OSError, ValueError) as exc:
            _run(("git", "worktree", "remove", "--force", str(worktree_path)), source)
            raise GitPolicyError(f"unable to materialize runtime worktree: {exc}") from exc
        try:
            baseline = capture_workspace_baseline(worktree_path)
        except OSError as exc:
            raise GitPolicyError(f"unable to establish workspace quota baseline: {exc}") from exc
        return cls(source, worktree_path, source_head, baseline)

    @classmethod
    def open(
        cls,
        source_repo: Path,
        state_dir: Path,
        run_id: str,
        source_head: str,
        baseline_state: Any,
    ) -> "GitWorkspace":
        source = source_repo.expanduser().resolve()
        state_root = Path(os.path.abspath(state_dir.expanduser()))
        worktrees_root = state_root / "worktrees"
        worktree_path = worktrees_root / run_id
        for label, path in (
            ("state root", state_root),
            ("worktrees root", worktrees_root),
            ("runtime worktree", worktree_path),
        ):
            if path.is_symlink() or not path.is_dir():
                raise PreflightError(f"{label} must be a real directory: {path}")
        if worktree_path.resolve().parent != worktrees_root.resolve():
            raise PreflightError("runtime worktree escapes the worktrees root")
        actual_root = _run(("git", "rev-parse", "--show-toplevel"), worktree_path).stdout
        if Path(actual_root.decode().strip()).resolve() != worktree_path.resolve():
            raise PreflightError("saved runtime worktree identity mismatch")

        def common_dir(repo: Path) -> Path:
            raw = _run(("git", "rev-parse", "--git-common-dir"), repo).stdout.decode().strip()
            candidate = Path(raw)
            return (candidate if candidate.is_absolute() else repo / candidate).resolve()

        if common_dir(worktree_path) != common_dir(source):
            raise PreflightError("saved runtime worktree belongs to another repository")
        if not isinstance(baseline_state, dict):
            raise PreflightError("saved workspace baseline is missing")
        entries = baseline_state.get("entries")
        regular_sizes = baseline_state.get("regularSizes")
        root_type = baseline_state.get("rootType")
        root_mode = baseline_state.get("rootMode")
        if (
            not isinstance(entries, list)
            or any(not isinstance(item, str) or not item for item in entries)
            or len(entries) != len(set(entries))
            or not isinstance(regular_sizes, dict)
            or not isinstance(root_type, int)
            or isinstance(root_type, bool)
            or root_type != stat.S_IFDIR
            or not isinstance(root_mode, int)
            or isinstance(root_mode, bool)
            or root_mode < 0
            or root_mode > 0o7777
            or any(
                not isinstance(path, str)
                or path not in entries
                or not isinstance(size, int)
                or isinstance(size, bool)
                or size < 0
                for path, size in regular_sizes.items()
            )
        ):
            raise PreflightError("saved workspace baseline is invalid")
        baseline = WorkspaceBaseline(
            frozenset(entries), dict(regular_sizes), root_type, root_mode
        )
        return cls(source, worktree_path, source_head, baseline)

    def baseline_state(self) -> dict[str, Any]:
        return {
            "entries": sorted(self.baseline.entries),
            "regularSizes": dict(sorted(self.baseline.regular_sizes.items())),
            "rootType": self.baseline.root_type,
            "rootMode": self.baseline.root_mode,
        }

    def enforce_workspace_limits(self) -> None:
        violation = workspace_limit_violation(self.path, self.baseline)
        if violation is not None:
            raise GitPolicyError(violation)

    def changed_paths(
        self,
        baseline_inventory: Mapping[str, tuple[int, int, str]],
        current_inventory: Mapping[str, tuple[int, int, str]] | None = None,
    ) -> tuple[str, ...]:
        current = current_inventory or self.workspace_inventory()
        changed: list[str] = []
        for relative in sorted(set(baseline_inventory) | set(current)):
            before = baseline_inventory.get(relative)
            after = current.get(relative)
            if before == after:
                continue
            if before is not None and after is None and self._mode_in_head(relative) == "160000":
                changed.append(relative)
                continue
            if (before is not None and before[0] == stat.S_IFDIR) or (
                after is not None and after[0] == stat.S_IFDIR
            ):
                continue
            changed.append(relative)
        return tuple(changed)

    def validate_manifest(
        self,
        allowed_paths: Sequence[str],
        protected_paths: Sequence[str],
        immutable_paths: Sequence[str] = (),
        *,
        baseline_inventory: Mapping[str, tuple[int, int, str]] | None = None,
        known_manifest: Sequence[str] | None = None,
    ) -> tuple[str, ...]:
        self.enforce_workspace_limits()
        current_inventory = self.workspace_inventory()
        if known_manifest is not None:
            manifest = tuple(sorted(set(known_manifest)))
        elif baseline_inventory is not None:
            manifest = self.changed_paths(baseline_inventory, current_inventory)
        else:
            raise GitPolicyError("workspace baseline inventory is required")
        if not manifest:
            raise GitPolicyError("provider produced no candidate changes")
        manifest_set = set(manifest)
        if baseline_inventory is not None:
            for relative in sorted(set(baseline_inventory) | set(current_inventory)):
                before = baseline_inventory.get(relative)
                after = current_inventory.get(relative)
                if before == after or relative in manifest_set:
                    continue
                if ".git" in Path(relative).parts:
                    raise GitPolicyError(f"nested repository is prohibited: {relative}")
                is_new_candidate_parent = (
                    before is None
                    and after is not None
                    and after[0] == stat.S_IFDIR
                    and any(path.startswith(f"{relative}/") for path in manifest)
                )
                is_removed_candidate_parent = (
                    before is not None
                    and before[0] == stat.S_IFDIR
                    and after is None
                    and any(path.startswith(f"{relative}/") for path in manifest)
                )
                if is_new_candidate_parent or is_removed_candidate_parent:
                    continue
                raise GitPolicyError(f"non-Git workspace artifact is prohibited: {relative}")
        for relative in manifest:
            if relative.startswith("/") or ".." in Path(relative).parts or "\x00" in relative:
                raise GitPolicyError(f"unsafe changed path: {relative}")
            if ".git" in Path(relative).parts:
                raise GitPolicyError(f"nested repository is prohibited: {relative}")
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
            ancestor = Path(relative).parent
            while ancestor != Path("."):
                ancestor_mode = self._mode_in_head(ancestor.as_posix())
                if ancestor_mode == "160000":
                    raise GitPolicyError(
                        f"gitlink ancestor is prohibited: {ancestor.as_posix()}"
                    )
                if ancestor_mode == "120000":
                    raise GitPolicyError(
                        f"symlink ancestor is prohibited: {ancestor.as_posix()}"
                    )
                ancestor = ancestor.parent
            if candidate.is_dir():
                raise GitPolicyError(f"nested repository or directory entry is prohibited: {relative}")
        return manifest

    def workspace_inventory(self) -> dict[str, tuple[int, int, str]]:
        """Capture every non-Git entry's type, mode, and raw content identity."""
        root_metadata = self.path.lstat()
        inventory: dict[str, tuple[int, int, str]] = {
            ".": (
                stat.S_IFMT(root_metadata.st_mode),
                stat.S_IMODE(root_metadata.st_mode),
                "",
            )
        }
        for directory, names, files in os.walk(self.path, topdown=True, followlinks=False):
            relative_directory = Path(directory).relative_to(self.path)
            if relative_directory == Path("."):
                names[:] = [name for name in names if name != ".git"]
                files = [name for name in files if name != ".git"]
            names.sort()
            files.sort()
            for name in names + files:
                candidate = Path(directory) / name
                relative = candidate.relative_to(self.path).as_posix()
                metadata = candidate.lstat()
                content_identity = ""
                if stat.S_ISREG(metadata.st_mode):
                    content_digest = hashlib.sha256()
                    self._digest_file(content_digest, candidate)
                    content_identity = content_digest.hexdigest()
                elif stat.S_ISLNK(metadata.st_mode):
                    content_identity = os.readlink(candidate)
                inventory[relative] = (
                    stat.S_IFMT(metadata.st_mode),
                    stat.S_IMODE(metadata.st_mode),
                    content_identity,
                )
        return inventory

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
        _digest_field(digest, b"ralph-ignored-digest-v1")
        for relative in sorted(ignored):
            _digest_field(digest, relative.encode("utf-8", "surrogateescape"))
            candidate = self.path / relative
            try:
                metadata = candidate.lstat()
            except FileNotFoundError:
                _digest_field(digest, b"missing")
                continue
            _digest_field(digest, str(stat.S_IFMT(metadata.st_mode)).encode("ascii"))
            _digest_field(digest, str(stat.S_IMODE(metadata.st_mode)).encode("ascii"))
            if stat.S_ISREG(metadata.st_mode):
                self._digest_file(digest, candidate)
            elif stat.S_ISLNK(metadata.st_mode):
                _digest_field(
                    digest, os.readlink(candidate).encode("utf-8", "surrogateescape")
                )
            else:
                _digest_field(digest, b"non-regular")
        return digest.hexdigest()

    def candidate_digest(self, manifest: Sequence[str]) -> str:
        digest = hashlib.sha256()
        _digest_field(digest, b"ralph-candidate-digest-v1")
        for relative in sorted(manifest):
            _digest_field(digest, relative.encode("utf-8", "surrogateescape"))
            candidate = self.path / relative
            try:
                metadata = candidate.lstat()
            except FileNotFoundError:
                _digest_field(digest, b"deleted")
                continue
            _digest_field(digest, str(stat.S_IFMT(metadata.st_mode)).encode("ascii"))
            _digest_field(digest, str(stat.S_IMODE(metadata.st_mode)).encode("ascii"))
            if stat.S_ISREG(metadata.st_mode):
                self._digest_file(digest, candidate)
            else:
                _digest_field(digest, b"non-regular")
        return digest.hexdigest()

    def workspace_digest(self) -> str:
        """Bind HEAD plus every non-Git workspace entry and relevant metadata."""
        digest = hashlib.sha256()
        _digest_field(digest, b"ralph-workspace-digest-v1")
        _digest_field(digest, self.head().encode("ascii"))
        root_metadata = self.path.lstat()
        _digest_field(digest, b".")
        _digest_field(digest, str(stat.S_IFMT(root_metadata.st_mode)).encode("ascii"))
        _digest_field(digest, str(stat.S_IMODE(root_metadata.st_mode)).encode("ascii"))
        for directory, names, files in os.walk(self.path, topdown=True, followlinks=False):
            relative_directory = Path(directory).relative_to(self.path)
            if relative_directory == Path(".") and ".git" in files:
                files.remove(".git")
            names.sort()
            files.sort()
            for name in names + files:
                candidate = Path(directory) / name
                relative = candidate.relative_to(self.path).as_posix()
                metadata = candidate.lstat()
                _digest_field(digest, relative.encode("utf-8", "surrogateescape"))
                _digest_field(digest, str(stat.S_IFMT(metadata.st_mode)).encode("ascii"))
                _digest_field(digest, str(stat.S_IMODE(metadata.st_mode)).encode("ascii"))
                if stat.S_ISREG(metadata.st_mode):
                    self._digest_file(digest, candidate)
                elif stat.S_ISLNK(metadata.st_mode):
                    _digest_field(
                        digest, os.readlink(candidate).encode("utf-8", "surrogateescape")
                    )
        return digest.hexdigest()

    def stage_exact(self, manifest: Sequence[str]) -> str:
        _run(("git", "read-tree", "HEAD"), self.path)
        index_info = bytearray()
        head = self.head()
        if len(head) not in {40, 64} or re.fullmatch(r"[0-9a-f]+", head) is None:
            raise GitPolicyError("repository uses an unsupported object ID format")
        zero_object = "0" * len(head)
        for relative in manifest:
            encoded_path = relative.encode("utf-8", "surrogateescape")
            candidate = self.path / relative
            try:
                metadata = candidate.lstat()
            except FileNotFoundError:
                index_info.extend(f"0 {zero_object}\t".encode("ascii"))
                index_info.extend(encoded_path + b"\0")
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise GitPolicyError(f"non-regular candidate is prohibited: {relative}")
            object_id = _run(
                ("git", "hash-object", "-w", "--no-filters", "--", relative),
                self.path,
            ).stdout.decode("ascii", "strict").strip()
            mode = "100755" if metadata.st_mode & 0o111 else "100644"
            index_info.extend(f"{mode} {object_id}\t".encode("ascii"))
            index_info.extend(encoded_path + b"\0")
        _run(
            ("git", "update-index", "-z", "--index-info"),
            self.path,
            input_bytes=bytes(index_info),
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
        content_digest = hashlib.sha256()
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                content_digest.update(chunk)
        _digest_field(digest, content_digest.digest())

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
