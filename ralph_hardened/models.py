from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence


class ProviderOutcome(str, Enum):
    SUCCESS = "SUCCESS"
    NONZERO = "NONZERO"
    EMPTY_OUTPUT = "EMPTY_OUTPUT"
    TIMEOUT = "TIMEOUT"
    RATE_LIMIT = "RATE_LIMIT"
    UNAVAILABLE = "UNAVAILABLE"
    MALFORMED_RESULT = "MALFORMED_RESULT"
    CANCELLED = "CANCELLED"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class RunOutcome(str, Enum):
    COMPLETE = "COMPLETE"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


@dataclass(frozen=True)
class ProviderResult:
    outcome: ProviderOutcome
    stdout: str
    stderr: str
    exit_code: Optional[int]
    duration_seconds: float
    metrics: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CheckDefinition:
    id: str
    argv: Sequence[str]
    timeout_seconds: float
    kind: str = "deterministic"
    environment: Mapping[str, str] = field(default_factory=dict)
    immutable_paths: Sequence[str] = field(default_factory=tuple)
    container_image: Optional[str] = None
    network: bool = False
    scratch_mounts: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class RalphConfig:
    path: Path
    checks: Mapping[str, CheckDefinition]
    protected_paths: Sequence[str]


@dataclass(frozen=True)
class Story:
    id: str
    title: str
    description: str
    acceptance_criteria: Sequence[str]
    priority: int
    allowed_paths: Sequence[str]
    required_checks: Sequence[str]
    depends_on: Sequence[str] = field(default_factory=tuple)
    requires_browser: bool = False
    references: Sequence[str] = field(default_factory=tuple)


@dataclass(frozen=True)
class PRD:
    path: Path
    project: str
    description: str
    stories: Sequence[Story]


@dataclass(frozen=True)
class CheckResult:
    id: str
    passed: bool
    exit_code: Optional[int]
    stdout: str
    stderr: str
    duration_seconds: float
    outcome: str
    stdout_bytes: int = 0
    stderr_bytes: int = 0
    stdout_sha256: str = ""
    stderr_sha256: str = ""
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    container_image: Optional[str] = None


@dataclass(frozen=True)
class OrchestrationResult:
    outcome: RunOutcome
    reason: str
    run_dir: Path
