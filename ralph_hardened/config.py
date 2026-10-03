from __future__ import annotations

import json
import math
import re
from pathlib import Path, PurePosixPath
from typing import Any

from .errors import PreflightError
from .models import CheckDefinition, RalphConfig


_ENVIRONMENT_KEY = re.compile(r"^[A-Z][A-Z0-9_]*$")
_SENSITIVE_ENVIRONMENT_KEY = re.compile(
    r"TOKEN|SECRET|PASSWORD|CREDENTIAL|AUTHORIZATION|API_?KEY", re.IGNORECASE
)
_CONTAINER_IMAGE = re.compile(r"^[A-Za-z0-9._/-]+(?::[A-Za-z0-9._-]+|@sha256:[0-9a-f]{64})$")
_CONFIG_FIELDS = frozenset({"version", "checks", "protectedPaths"})
_CHECK_FIELDS = frozenset(
    {
        "argv",
        "timeoutSeconds",
        "kind",
        "environment",
        "immutablePaths",
        "containerImage",
        "network",
        "scratchMounts",
    }
)


def _safe_path_pattern(value: object, *, forbid_git: bool = False) -> bool:
    if (
        not isinstance(value, str)
        or not value
        or value == "."
        or value.startswith("/")
        or "\\" in value
        or ":" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        return False
    parts = PurePosixPath(value).parts
    if ".." in parts:
        return False
    return not forbid_git or all(part.lower() != ".git" for part in parts)


def _read_object(path: Path, content: bytes | None = None) -> dict[str, Any]:
    try:
        text = content.decode("utf-8") if content is not None else path.read_text(encoding="utf-8")
        raw = json.loads(text)
    except FileNotFoundError as exc:
        raise PreflightError(f"configuration not found: {path}") from exc
    except UnicodeError as exc:
        raise PreflightError(f"configuration is not valid UTF-8: {path}") from exc
    except json.JSONDecodeError as exc:
        raise PreflightError(f"configuration invalid JSON: {path}: {exc.msg}") from exc
    if not isinstance(raw, dict):
        raise PreflightError("configuration root must be an object")
    return raw


def load_config(path: Path, content: bytes | None = None) -> RalphConfig:
    resolved = path.expanduser().resolve()
    raw = _read_object(resolved, content)
    unsupported_root_fields = sorted(set(raw) - _CONFIG_FIELDS)
    if unsupported_root_fields:
        raise PreflightError(
            "configuration has unsupported root fields: "
            + ", ".join(unsupported_root_fields)
        )
    if raw.get("version") != 1:
        raise PreflightError("configuration version must be 1")
    checks_raw = raw.get("checks")
    if not isinstance(checks_raw, dict) or not checks_raw:
        raise PreflightError("configuration checks must be a non-empty object")
    checks: dict[str, CheckDefinition] = {}
    for check_id, definition in checks_raw.items():
        if not isinstance(check_id, str) or not check_id:
            raise PreflightError("check ids must be non-empty strings")
        if not isinstance(definition, dict):
            raise PreflightError(f"check {check_id!r} must be an object")
        unsupported_fields = sorted(set(definition) - _CHECK_FIELDS)
        if unsupported_fields:
            raise PreflightError(
                f"check {check_id!r} has unsupported fields: {', '.join(unsupported_fields)}"
            )
        argv = definition.get("argv")
        if (
            not isinstance(argv, list)
            or not argv
            or any(
                not isinstance(item, str) or not item or "\x00" in item
                for item in argv
            )
        ):
            raise PreflightError(f"check {check_id!r} argv must be a non-empty string array")
        timeout = definition.get("timeoutSeconds", 300)
        if (
            not isinstance(timeout, (int, float))
            or isinstance(timeout, bool)
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise PreflightError(f"check {check_id!r} timeoutSeconds must be positive")
        kind = definition.get("kind", "deterministic")
        if kind not in {"deterministic", "browser"}:
            raise PreflightError(f"check {check_id!r} kind must be deterministic or browser")
        environment = definition.get("environment", {})
        if not isinstance(environment, dict) or any(
            not isinstance(key, str)
            or _ENVIRONMENT_KEY.fullmatch(key) is None
            or key == "PATH"
            or _SENSITIVE_ENVIRONMENT_KEY.search(key)
            or not isinstance(value, str)
            or "\x00" in value
            for key, value in environment.items()
        ):
            raise PreflightError(f"check {check_id!r} environment must contain non-secret string values")
        immutable_paths = definition.get("immutablePaths", [])
        if not isinstance(immutable_paths, list) or any(
            not _safe_path_pattern(item)
            for item in immutable_paths
        ):
            raise PreflightError(f"check {check_id!r} immutablePaths must be safe path patterns")
        container_image = definition.get("containerImage")
        if container_image is not None and (
            not isinstance(container_image, str)
            or _CONTAINER_IMAGE.fullmatch(container_image) is None
            or container_image.endswith(":latest")
        ):
            raise PreflightError(f"check {check_id!r} containerImage must be a pinned image reference")
        network = definition.get("network", False)
        if not isinstance(network, bool):
            raise PreflightError(f"check {check_id!r} network must be boolean")
        scratch_mounts = definition.get("scratchMounts", {})
        if not isinstance(scratch_mounts, dict) or any(
            not _safe_path_pattern(item, forbid_git=True)
            or mode not in {"ro", "rw"}
            for item, mode in scratch_mounts.items()
        ):
            raise PreflightError(
                f"check {check_id!r} scratchMounts must map safe paths to ro or rw"
            )
        checks[check_id] = CheckDefinition(
            id=check_id,
            argv=tuple(argv),
            timeout_seconds=float(timeout),
            kind=kind,
            environment=dict(environment),
            immutable_paths=tuple(immutable_paths),
            container_image=container_image,
            network=network,
            scratch_mounts=dict(scratch_mounts),
        )
    protected = raw.get("protectedPaths", [])
    if not isinstance(protected, list) or any(
        not _safe_path_pattern(item) for item in protected
    ):
        raise PreflightError("protectedPaths must be a string array")
    return RalphConfig(resolved, checks, tuple(protected))
