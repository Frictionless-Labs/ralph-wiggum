from __future__ import annotations

import hashlib
import fcntl
import json
import os
import re
import stat
import tempfile
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .errors import StateError


_SENSITIVE_KEY = re.compile(r"token|secret|password|credential|authorization|api[_-]?key", re.IGNORECASE)
_STORY_TRANSITIONS = {
    "PENDING": {"RUNNING"},
    "RUNNING": {"PASS", "FAIL", "BLOCKED"},
    "FAIL": {"RUNNING"},
    "BLOCKED": {"RUNNING"},
    "PASS": {"FAIL"},
}


def _assert_nonreplaceable_ancestors(path: Path) -> None:
    current_uid = os.getuid()
    current = path
    while True:
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise StateError(f"unsafe state hierarchy at {current}: {exc}") from exc
        mode = metadata.st_mode
        if not stat.S_ISDIR(mode) or stat.S_ISLNK(mode):
            raise StateError(f"unsafe state hierarchy at {current}")
        if metadata.st_uid not in {0, current_uid}:
            raise StateError(f"unsafe state hierarchy at {current}")
        if mode & (stat.S_IWGRP | stat.S_IWOTH) and not mode & stat.S_ISVTX:
            raise StateError(f"unsafe state hierarchy at {current}")
        if current.parent == current:
            return
        current = current.parent


def _assert_owned_state_directory(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise StateError(f"unsafe state hierarchy at {path}: {exc}") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise StateError(f"unsafe state hierarchy at {path}")
    _assert_nonreplaceable_ancestors(path.parent)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _redact(value: Any, key: str = "") -> Any:
    if _SENSITIVE_KEY.search(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(child_key): _redact(child, str(child_key)) for child_key, child in value.items()}
    if isinstance(value, list):
        return [_redact(child) for child in value]
    return value


@contextmanager
def lock_resumable_run(run_dir: Path):
    requested = Path(os.path.abspath(run_dir.expanduser()))
    if requested.is_symlink() or not requested.is_dir():
        raise StateError(f"resume run must be a real directory: {requested}")
    _assert_owned_state_directory(requested)
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(requested / ".resume.lock", flags, 0o600)
    except OSError as exc:
        raise StateError(f"unable to open resume lock at {requested}: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
        ):
            raise StateError(f"resume lock is not an owned regular file: {requested}")
        os.fchmod(descriptor, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise StateError(f"resume run is already active: {requested}") from exc
        yield
    finally:
        os.close(descriptor)


class RunStore:
    def __init__(self, run_dir: Path, state: dict[str, Any]) -> None:
        self.run_dir = run_dir
        self.state = state
        self.run_id = str(state["runId"])
        self.state_path = run_dir / "run.json"
        self.events_path = run_dir / "events.jsonl"
        self.snapshot_path = run_dir / "prd.snapshot.json"
        self.config_snapshot_path = run_dir / "config.snapshot.json"

    @classmethod
    def create(
        cls,
        state_dir: Path,
        prd_path: Path,
        source_head: str,
        story_ids: list[str],
        *,
        config_path: Optional[Path] = None,
        prd_bytes: Optional[bytes] = None,
        config_bytes: Optional[bytes] = None,
    ) -> "RunStore":
        requested_state_root = Path(os.path.abspath(state_dir.expanduser()))
        if requested_state_root.is_symlink():
            raise StateError(f"state root must be a real directory: {requested_state_root}")
        state_root = requested_state_root.resolve()
        existing_ancestor = state_root
        while not existing_ancestor.exists():
            existing_ancestor = existing_ancestor.parent
        _assert_nonreplaceable_ancestors(existing_ancestor)
        state_root_created = not state_root.exists()
        state_root.mkdir(parents=True, mode=0o700, exist_ok=True)
        if state_root.is_symlink() or not state_root.is_dir():
            raise StateError(f"state root must be a real directory: {state_root}")
        if state_root_created:
            state_root.chmod(0o700)
        _assert_owned_state_directory(state_root)
        runs_root = state_root / "runs"
        runs_root_created = not runs_root.exists()
        runs_root.mkdir(mode=0o700, exist_ok=True)
        if runs_root.is_symlink() or not runs_root.is_dir():
            raise StateError(f"runs root must be a real directory: {runs_root}")
        if runs_root_created:
            runs_root.chmod(0o700)
        _assert_owned_state_directory(runs_root)
        run_id = f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:12]}"
        run_dir = runs_root / run_id
        run_dir.mkdir(mode=0o700)
        snapshot_path = run_dir / "prd.snapshot.json"
        snapshot_bytes = prd_bytes if prd_bytes is not None else prd_path.read_bytes()
        snapshot_path.write_bytes(snapshot_bytes)
        snapshot_path.chmod(0o600)
        config_bytes = (
            config_bytes
            if config_bytes is not None
            else config_path.read_bytes()
            if config_path is not None
            else None
        )
        if config_bytes is not None:
            config_snapshot_path = run_dir / "config.snapshot.json"
            config_snapshot_path.write_bytes(config_bytes)
            config_snapshot_path.chmod(0o600)
        state: dict[str, Any] = {
            "schemaVersion": 1,
            "runId": run_id,
            "status": "CREATED",
            "reason": "",
            "createdAt": _now(),
            "updatedAt": _now(),
            "sourceHead": source_head,
            "prdDigest": hashlib.sha256(snapshot_bytes).hexdigest(),
            "stories": {story_id: {"status": "PENDING", "attempts": 0} for story_id in story_ids},
        }
        if config_bytes is not None:
            state["configDigest"] = hashlib.sha256(config_bytes).hexdigest()
        store = cls(run_dir, state)
        store._write_state()
        store.event("run_created", detail={"sourceHead": source_head, "prdDigest": state["prdDigest"]})
        return store

    @classmethod
    def load(cls, run_dir: Path) -> "RunStore":
        resolved = run_dir.expanduser().resolve()
        _assert_owned_state_directory(resolved)
        try:
            state = json.loads((resolved / "run.json").read_text(encoding="utf-8"))
        except (FileNotFoundError, UnicodeError, json.JSONDecodeError) as exc:
            raise StateError(f"invalid run state at {resolved}") from exc
        if (
            not isinstance(state, dict)
            or state.get("schemaVersion") != 1
            or not isinstance(state.get("runId"), str)
            or not state["runId"]
            or not isinstance(state.get("status"), str)
            or not isinstance(state.get("sourceHead"), str)
            or not isinstance(state.get("prdDigest"), str)
            or state.get("runId") != resolved.name
            or not isinstance(state.get("stories"), dict)
            or any(
                not isinstance(story_id, str)
                or not story_id
                or not isinstance(story, dict)
                or not isinstance(story.get("status"), str)
                for story_id, story in state.get("stories", {}).items()
            )
        ):
            raise StateError(f"invalid run state at {resolved}")
        store = cls(resolved, state)
        try:
            digest = hashlib.sha256(store.snapshot_path.read_bytes()).hexdigest()
        except OSError as exc:
            raise StateError(f"invalid run state at {resolved}") from exc
        if digest != state.get("prdDigest"):
            raise StateError("immutable PRD snapshot digest mismatch")
        if "configDigest" in state:
            try:
                config_digest = hashlib.sha256(
                    store.config_snapshot_path.read_bytes()
                ).hexdigest()
            except OSError as exc:
                raise StateError(f"invalid run state at {resolved}") from exc
            if config_digest != state.get("configDigest"):
                raise StateError("immutable configuration snapshot digest mismatch")
        return store

    def _write_state(self) -> None:
        self.state["updatedAt"] = _now()
        payload = json.dumps(self.state, indent=2, sort_keys=True) + "\n"
        file_descriptor, temporary_name = tempfile.mkstemp(prefix=".run-", suffix=".json", dir=self.run_dir)
        try:
            with os.fdopen(file_descriptor, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary_name, 0o600)
            os.replace(temporary_name, self.state_path)
        finally:
            if os.path.exists(temporary_name):
                os.unlink(temporary_name)

    def event(
        self,
        event_type: str,
        *,
        story_id: Optional[str] = None,
        attempt: Optional[int] = None,
        detail: Optional[dict[str, Any]] = None,
    ) -> None:
        event = {
            "schemaVersion": 1,
            "timestamp": _now(),
            "runId": self.run_id,
            "storyId": story_id,
            "attempt": attempt,
            "type": event_type,
            "detail": _redact(detail or {}),
        }
        descriptor = os.open(self.events_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())

    def set_run_status(self, status: str, reason: str = "") -> None:
        if status == "COMPLETE" and any(
            story["status"] != "PASS" for story in self.state["stories"].values()
        ):
            raise StateError("run cannot complete while stories are not PASS")
        self.state["status"] = status
        self.state["reason"] = reason
        self._write_state()
        self.event("run_status", detail={"status": status, "reason": reason})

    def transition_story(
        self,
        story_id: str,
        status: str,
        *,
        attempt: Optional[int] = None,
        evidence: Optional[dict[str, Any]] = None,
        reason: str = "",
    ) -> None:
        try:
            story = self.state["stories"][story_id]
        except KeyError as exc:
            raise StateError(f"unknown story: {story_id}") from exc
        current = story["status"]
        if status not in _STORY_TRANSITIONS.get(current, set()):
            raise StateError(f"invalid story transition: {current} -> {status}")
        story["status"] = status
        if attempt is not None:
            story["attempts"] = attempt
        if evidence is not None:
            story["evidence"] = evidence
        if reason:
            story["reason"] = reason
        self._write_state()
        self.event(
            "story_status",
            story_id=story_id,
            attempt=attempt,
            detail={"from": current, "to": status, "reason": reason, "evidence": evidence or {}},
        )
