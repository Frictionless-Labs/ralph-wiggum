from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath
from typing import Any

from .errors import PreflightError
from .models import PRD, RalphConfig, Story


MAX_REFERENCE_COUNT = 8
_SECRET_REFERENCE_NAMES = {
    ".aws",
    ".dockercfg",
    ".docker",
    ".env",
    ".gnupg",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".ssh",
    "auth.json",
    "credentials",
    "credentials.json",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
    "secrets.json",
    "service-account.json",
}
_SECRET_REFERENCE_SUFFIXES = (".pem", ".key", ".p12", ".pfx")
_SECRET_REFERENCE_COMPONENT = re.compile(
    r"(?:^|[._-])(?:auth|credential|credentials|secret|secrets|token)(?:[._-]|$)"
)


def _required_string(raw: dict[str, Any], field: str, context: str) -> str:
    value = raw.get(field)
    if not isinstance(value, str) or not value.strip():
        raise PreflightError(f"{context} {field} must be a non-empty string")
    return value


def _string_array(raw: dict[str, Any], field: str, context: str, required: bool = True) -> tuple[str, ...]:
    value = raw.get(field, [] if not required else None)
    if not isinstance(value, list) or (required and not value):
        raise PreflightError(f"{context} {field} must be a non-empty string array")
    if any(not isinstance(item, str) or not item.strip() for item in value):
        raise PreflightError(f"{context} {field} must contain non-empty strings")
    return tuple(value)


def _validate_allowed_path(value: str, story_id: str) -> None:
    if "\\" in value or "\x00" in value or value.startswith("/"):
        raise PreflightError(f"story {story_id} has unsafe allowed path: {value}")
    path = PurePosixPath(value)
    if value in {"", "."} or ".." in path.parts:
        raise PreflightError(f"story {story_id} has unsafe allowed path: {value}")


def _validate_reference_path(value: str, story_id: str) -> None:
    _validate_allowed_path(value, story_id)
    path = PurePosixPath(value)
    components = tuple(component.lower() for component in path.parts)
    if (
        ":" in value
        or any(ord(character) < 32 for character in value)
        or ".git" in path.parts
        or any(
            component in _SECRET_REFERENCE_NAMES
            or component.startswith(".env.")
            or component.endswith(_SECRET_REFERENCE_SUFFIXES)
            or _SECRET_REFERENCE_COMPONENT.search(component)
            for component in components
        )
    ):
        raise PreflightError(f"story {story_id} has protected or secret-like reference: {value}")


def _validate_dependencies(stories: list[Story]) -> None:
    ids = {story.id for story in stories}
    for story in stories:
        unknown = sorted(set(story.depends_on) - ids)
        if unknown:
            raise PreflightError(f"story {story.id} has unknown dependency: {unknown[0]}")
        if story.id in story.depends_on:
            raise PreflightError(f"dependency cycle includes {story.id}")
    graph = {story.id: tuple(story.depends_on) for story in stories}
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(story_id: str) -> None:
        if story_id in visiting:
            raise PreflightError(f"dependency cycle includes {story_id}")
        if story_id in visited:
            return
        visiting.add(story_id)
        for dependency in graph[story_id]:
            visit(dependency)
        visiting.remove(story_id)
        visited.add(story_id)

    for candidate in graph:
        visit(candidate)


def load_prd(path: Path, config: RalphConfig, content: bytes | None = None) -> PRD:
    resolved = path.expanduser().resolve()
    try:
        text = content.decode("utf-8") if content is not None else resolved.read_text(encoding="utf-8")
        raw = json.loads(text)
    except FileNotFoundError as exc:
        raise PreflightError(f"PRD not found: {resolved}") from exc
    except UnicodeError as exc:
        raise PreflightError(f"PRD is not valid UTF-8: {resolved}") from exc
    except json.JSONDecodeError as exc:
        raise PreflightError(f"PRD invalid JSON: {resolved}: {exc.msg}") from exc
    if not isinstance(raw, dict):
        raise PreflightError("PRD root must be an object")
    project = _required_string(raw, "project", "PRD")
    description = _required_string(raw, "description", "PRD")
    stories_raw = raw.get("userStories")
    if not isinstance(stories_raw, list) or not stories_raw:
        raise PreflightError("PRD userStories must be a non-empty array")
    stories: list[Story] = []
    seen: set[str] = set()
    for index, item in enumerate(stories_raw):
        if not isinstance(item, dict):
            raise PreflightError(f"story at index {index} must be an object")
        story_id = _required_string(item, "id", f"story at index {index}")
        if any(ord(character) < 32 or ord(character) == 127 for character in story_id):
            raise PreflightError(f"story at index {index} id contains control characters")
        if story_id in seen:
            raise PreflightError(f"duplicate story id: {story_id}")
        seen.add(story_id)
        priority = item.get("priority")
        if not isinstance(priority, int) or isinstance(priority, bool) or priority <= 0:
            raise PreflightError(f"story {story_id} priority must be a positive integer")
        allowed_paths = _string_array(item, "allowedPaths", f"story {story_id}")
        for allowed_path in allowed_paths:
            _validate_allowed_path(allowed_path, story_id)
        required_checks = _string_array(item, "requiredChecks", f"story {story_id}")
        for check_id in required_checks:
            if check_id not in config.checks:
                raise PreflightError(f"story {story_id} references unknown required check: {check_id}")
        requires_browser = item.get("requiresBrowser", False)
        if not isinstance(requires_browser, bool):
            raise PreflightError(f"story {story_id} requiresBrowser must be boolean")
        references = _string_array(item, "references", f"story {story_id}", required=False)
        if len(references) > MAX_REFERENCE_COUNT:
            raise PreflightError(
                f"story {story_id} references exceed the limit of {MAX_REFERENCE_COUNT}"
            )
        if len(references) != len(set(references)):
            raise PreflightError(f"story {story_id} references must be unique")
        for reference in references:
            _validate_reference_path(reference, story_id)
        stories.append(
            Story(
                id=story_id,
                title=_required_string(item, "title", f"story {story_id}"),
                description=_required_string(item, "description", f"story {story_id}"),
                acceptance_criteria=_string_array(item, "acceptanceCriteria", f"story {story_id}"),
                priority=priority,
                allowed_paths=allowed_paths,
                required_checks=required_checks,
                depends_on=_string_array(item, "dependsOn", f"story {story_id}", required=False),
                requires_browser=requires_browser,
                references=references,
            )
        )
    _validate_dependencies(stories)
    remaining = {story.id: story for story in stories}
    ordered: list[Story] = []
    completed: set[str] = set()
    while remaining:
        ready = [story for story in remaining.values() if set(story.depends_on) <= completed]
        if not ready:
            raise PreflightError("dependency cycle prevents scheduling")
        selected = min(ready, key=lambda story: (story.priority, story.id))
        ordered.append(selected)
        completed.add(selected.id)
        del remaining[selected.id]
    return PRD(resolved, project, description, tuple(ordered))
