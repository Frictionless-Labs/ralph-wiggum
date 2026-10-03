from __future__ import annotations

import json
import subprocess
from pathlib import Path


def run(*argv: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=cwd,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def init_repo(path: Path) -> str:
    path.mkdir(parents=True)
    run("git", "init", "-b", "main", cwd=path)
    run("git", "config", "user.name", "Ralph Test", cwd=path)
    run("git", "config", "user.email", "ralph-test@example.invalid", cwd=path)
    (path / "app.txt").write_text("baseline\n", encoding="utf-8")
    run("git", "add", "app.txt", cwd=path)
    run("git", "commit", "-m", "test: baseline", cwd=path)
    return run("git", "rev-parse", "HEAD", cwd=path).stdout.strip()


def write_config(path: Path, check_argv: list[str] | None = None) -> Path:
    payload = {
        "version": 1,
        "protectedPaths": [".git/**", ".ralph/**", "ralph-state/**"],
        "checks": {
            "required": {
                "argv": check_argv
                or ["python3", "-c", "from pathlib import Path; assert Path('app.txt').exists()"],
                "timeoutSeconds": 5,
            }
        },
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def prd_payload(**story_overrides: object) -> dict[str, object]:
    story: dict[str, object] = {
        "id": "US-001",
        "title": "Change the app",
        "description": "Make the requested bounded change.",
        "acceptanceCriteria": ["app.txt contains the requested content"],
        "priority": 1,
        "allowedPaths": ["app.txt"],
        "requiredChecks": ["required"],
    }
    story.update(story_overrides)
    return {
        "project": "fixture",
        "description": "Fixture PRD",
        "userStories": [story],
    }


def write_prd(path: Path, **story_overrides: object) -> Path:
    path.write_text(json.dumps(prd_payload(**story_overrides)), encoding="utf-8")
    return path
