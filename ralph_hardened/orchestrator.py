from __future__ import annotations

import json
import hashlib
import math
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Optional

from .checks import CheckRunner
from .config import load_config
from .errors import GitPolicyError, PreflightError, RalphError, StateError
from .gitops import GitWorkspace, is_secret_like, matches_path_patterns
from .models import OrchestrationResult, ProviderOutcome, ProviderResult, RunOutcome, Story
from .prd import load_prd
from .provider import CommandProvider, Provider, build_safe_env, normalize_provider_metrics
from .state import RunStore


_DIAGNOSTIC_ASSIGNMENT = re.compile(
    r"(?i)(token|secret|password|credential|authorization|api[_-]?key)(\s*[:=]\s*)([^\s,;]+)"
)
_BEARER_VALUE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]+=*")
_KEY_SHAPE = re.compile(r"\b(?:sk|rk|pk)-[A-Za-z0-9_-]{12,}\b")
_MAX_REFERENCE_FILE_BYTES = 32_768
_MAX_REFERENCE_TOTAL_BYTES = 65_536
_MAX_WORKER_BRIEF_BYTES = 131_072


def _redact_diagnostic(value: str) -> str:
    value = _BEARER_VALUE.sub("Bearer [REDACTED]", value)
    value = _DIAGNOSTIC_ASSIGNMENT.sub(r"\1\2[REDACTED]", value)
    return _KEY_SHAPE.sub("[REDACTED]", value)


@dataclass(frozen=True)
class RunOptions:
    repo: Path
    prd_path: Path
    config_path: Path
    state_dir: Path
    max_iterations: int
    max_attempts: int
    timeout_seconds: float
    browser_evidence: Optional[Path]
    resume_run: Optional[Path] = None


def _git_text(repo: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ("git", *args),
            cwd=repo,
            env=build_safe_env(),
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except (FileNotFoundError, NotADirectoryError, PermissionError, OSError) as exc:
        raise PreflightError(f"Git preflight could not access repository: {repo}: {exc}") from exc
    if result.returncode != 0:
        raise PreflightError(f"Git preflight failed: {result.stderr.strip()}")
    return result.stdout.strip()


def _story_prompt(story: Story, references: tuple[dict[str, str], ...] = ()) -> str:
    payload = {
        "id": story.id,
        "title": story.title,
        "description": story.description,
        "acceptanceCriteria": list(story.acceptance_criteria),
        "allowedPaths": list(story.allowed_paths),
        "requiredChecks": list(story.required_checks),
        "requiresBrowser": story.requires_browser,
        "references": list(references),
    }
    prompt = (
        "You are an untrusted implementation worker. Implement only the current story below. "
        "Do not commit, edit canonical Ralph state, push, merge, deploy, or claim release completion. "
        "The orchestrator independently validates all output.\n\n"
        + json.dumps(payload, indent=2, sort_keys=True)
        + "\n"
    )
    if len(prompt.encode("utf-8")) > _MAX_WORKER_BRIEF_BYTES:
        raise PreflightError(
            f"worker brief exceeds {_MAX_WORKER_BRIEF_BYTES} bytes for story {story.id}"
        )
    return prompt


def _read_story_references(
    repo: Path, source_head: str, story: Story, protected_paths: tuple[str, ...]
) -> tuple[dict[str, str], ...]:
    references: list[dict[str, str]] = []
    total_bytes = 0
    for relative in story.references:
        if is_secret_like(relative) or matches_path_patterns(relative, protected_paths):
            raise PreflightError(f"story {story.id} reference is protected: {relative}")
        object_spec = f"{source_head}:{relative}"
        try:
            entry = _git_text(
                repo, "--literal-pathspecs", "ls-tree", source_head, "--", relative
            )
            object_type = _git_text(repo, "cat-file", "-t", object_spec)
        except PreflightError as exc:
            raise PreflightError(
                f"story {story.id} reference is not a tracked file: {relative}"
            ) from exc
        mode = entry.split(" ", 1)[0] if entry else ""
        if object_type != "blob" or mode not in {"100644", "100755"}:
            raise PreflightError(f"story {story.id} reference is not a tracked file: {relative}")
        try:
            size = int(_git_text(repo, "cat-file", "-s", object_spec))
        except ValueError as exc:
            raise PreflightError(f"story {story.id} reference size is invalid: {relative}") from exc
        if size > _MAX_REFERENCE_FILE_BYTES:
            raise PreflightError(
                f"story {story.id} reference exceeds {_MAX_REFERENCE_FILE_BYTES} bytes: {relative}"
            )
        total_bytes += size
        if total_bytes > _MAX_REFERENCE_TOTAL_BYTES:
            raise PreflightError(
                f"story {story.id} references exceed {_MAX_REFERENCE_TOTAL_BYTES} bytes"
            )
        result = subprocess.run(
            ("git", "cat-file", "blob", object_spec),
            cwd=repo,
            env=build_safe_env(),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if result.returncode != 0:
            raise PreflightError(f"story {story.id} reference cannot be read: {relative}")
        try:
            content = result.stdout.decode("utf-8")
        except UnicodeError as exc:
            raise PreflightError(
                f"story {story.id} reference must be valid UTF-8: {relative}"
            ) from exc
        references.append(
            {
                "path": relative,
                "sha256": hashlib.sha256(result.stdout).hexdigest(),
                "content": content,
            }
        )
    return tuple(references)


def _check_evidence(results: tuple[Any, ...]) -> list[dict[str, Any]]:
    return [
        {
            "id": result.id,
            "outcome": result.outcome,
            "exitCode": result.exit_code,
            "durationSeconds": round(result.duration_seconds, 6),
            "stdoutBytes": result.stdout_bytes,
            "stderrBytes": result.stderr_bytes,
            "stdoutSha256": result.stdout_sha256,
            "stderrSha256": result.stderr_sha256,
            "stdoutTruncated": result.stdout_truncated,
            "stderrTruncated": result.stderr_truncated,
            "containerImage": result.container_image,
            "stdoutTail": _redact_diagnostic(result.stdout),
            "stderrTail": _redact_diagnostic(result.stderr),
        }
        for result in results
    ]


def _browser_evidence_for_story(
    path: Optional[Path], story_id: str, evaluated_tree: str
) -> Optional[dict[str, Any]]:
    if path is None:
        return None
    try:
        resolved = path.expanduser().resolve(strict=True)
        if path.expanduser().is_symlink() or not resolved.is_file() or resolved.stat().st_size > 1_048_576:
            return None
        raw = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(raw, dict) or raw.get("schemaVersion") != 1:
        return None
    entries = raw.get("evidence")
    if not isinstance(entries, list):
        return None
    for entry in entries:
        if (
            isinstance(entry, dict)
            and entry.get("storyId") == story_id
            and entry.get("status") == "PASS"
            and entry.get("evaluatedTree") == evaluated_tree
            and isinstance(entry.get("verifier"), str)
            and entry["verifier"].strip()
        ):
            return {
                "storyId": story_id,
                "status": "PASS",
                "evaluatedTree": evaluated_tree,
                "verifier": entry["verifier"],
            }
    return None


class Orchestrator:
    def __init__(self, options: RunOptions, provider: Provider) -> None:
        self.options = options
        self.provider = provider

    def _preflight(
        self,
    ) -> tuple[
        Path,
        str,
        Any,
        Any,
        bytes,
        bytes,
        dict[str, str],
        Optional[RunStore],
    ]:
        if self.options.max_iterations <= 0 or self.options.max_attempts <= 0:
            raise PreflightError("iteration and attempt ceilings must be positive")
        if not math.isfinite(self.options.timeout_seconds) or self.options.timeout_seconds <= 0:
            raise PreflightError("provider timeout must be positive")
        repo = self.options.repo.expanduser().resolve()
        if not repo.is_dir():
            raise PreflightError(f"repository directory not found: {repo}")
        if Path(_git_text(repo, "rev-parse", "--show-toplevel")).resolve() != repo:
            raise PreflightError(f"repo must be its Git root: {repo}")
        resume_store = None
        if self.options.resume_run is not None:
            requested_run = Path(os.path.abspath(self.options.resume_run.expanduser()))
            if requested_run.is_symlink():
                raise PreflightError(f"resume run must be a real directory: {requested_run}")
            try:
                resume_store = RunStore.load(requested_run)
            except (OSError, StateError) as exc:
                raise PreflightError(f"unable to load resumable run: {exc}") from exc
            if (
                resume_store.state.get("status") != "BLOCKED"
                or resume_store.state.get("reason") != "BLOCKED_VERIFIER"
            ):
                raise PreflightError("only a BLOCKED_VERIFIER run may be resumed")
            source_head = str(resume_store.state["sourceHead"])
            _git_text(repo, "cat-file", "-e", f"{source_head}^{{commit}}")
            config_path = resume_store.config_snapshot_path
            prd_path = resume_store.snapshot_path
        else:
            source_head = _git_text(repo, "rev-parse", "HEAD")
            config_path = self.options.config_path.expanduser().resolve()
            prd_path = self.options.prd_path.expanduser().resolve()
        state_dir = Path(os.path.abspath(self.options.state_dir.expanduser()))
        try:
            state_dir.resolve().relative_to(repo)
        except ValueError:
            pass
        else:
            raise PreflightError("state directory must be outside the source repository")
        try:
            config_bytes = config_path.read_bytes()
            prd_bytes = prd_path.read_bytes()
        except OSError as exc:
            raise PreflightError(f"unable to read immutable run inputs: {exc}") from exc
        config = load_config(config_path, config_bytes)
        prd = load_prd(prd_path, config, prd_bytes)
        references = {
            story.id: _read_story_references(
                repo, source_head, story, tuple(config.protected_paths)
            )
            for story in prd.stories
        }
        worker_briefs = {
            story.id: _story_prompt(story, references[story.id]) for story in prd.stories
        }
        for story in prd.stories:
            scratch_paths = sorted(
                {
                    Path(relative)
                    for check_id in story.required_checks
                    for relative in config.checks[check_id].scratch_mounts
                }
            )
            for index, path in enumerate(scratch_paths):
                for other in scratch_paths[index + 1 :]:
                    if path != other and path in other.parents:
                        raise PreflightError(
                            f"story {story.id} has overlapping scratch mounts: "
                            f"{path} and {other}"
                        )
        safe_path = build_safe_env().get("PATH", "")
        execution_required = resume_store is None or any(
            story_state.get("status") == "PENDING"
            for story_state in resume_store.state["stories"].values()
        )
        stories_requiring_execution = (
            prd.stories
            if resume_store is None
            else tuple(
                story
                for story in prd.stories
                if resume_store.state["stories"][story.id].get("status") == "PENDING"
            )
        )
        required_check_ids = {
            check
            for story in stories_requiring_execution
            for check in story.required_checks
        }
        resolved_checks = dict(config.checks)
        for check_id in sorted(required_check_ids):
            definition = config.checks[check_id]
            if definition.container_image is not None:
                if shutil.which("docker", path=safe_path) is None:
                    raise PreflightError("containerized checks require Docker")
                image = subprocess.run(
                    (
                        "docker",
                        "image",
                        "inspect",
                        "--format={{.Id}}",
                        definition.container_image,
                    ),
                    env=build_safe_env(),
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                if image.returncode != 0:
                    raise PreflightError(
                        f"check container image unavailable: {definition.container_image}"
                    )
                image_id = image.stdout.strip()
                if not image_id.startswith("sha256:") or len(image_id) != 71:
                    raise PreflightError(
                        f"check container image identity unavailable: {definition.container_image}"
                    )
                resolved_checks[check_id] = replace(
                    definition, container_image=image_id
                )
                continue
            if not self.provider.allows_host_checks:
                raise PreflightError(
                    f"check {check_id!r} requires a containerImage confinement boundary"
                )
            executable = definition.argv[0]
            if "/" in executable:
                candidate = Path(executable)
                if candidate.is_absolute():
                    available = candidate.is_file() and bool(candidate.stat().st_mode & 0o111)
                else:
                    if "\\" in executable or ".." in candidate.parts:
                        raise PreflightError(f"check executable has unsafe path: {executable}")
                    relative = executable[2:] if executable.startswith("./") else executable
                    entry = _git_text(repo, "ls-tree", source_head, "--", relative)
                    available = entry.startswith("100755 ")
            else:
                available = shutil.which(executable, path=safe_path) is not None
            if not available:
                raise PreflightError(f"check executable unavailable: {executable}")
        config = replace(config, checks=resolved_checks)
        if isinstance(self.provider, CommandProvider) and execution_required:
            executable = self.provider.argv[0]
            if shutil.which(executable, path=safe_path) is None:
                raise PreflightError(f"provider executable unavailable: {executable}")
            provider_preflight_error = self.provider.preflight(repo)
            if provider_preflight_error:
                raise PreflightError(provider_preflight_error)
        if not _git_text(repo, "config", "user.name") or not _git_text(repo, "config", "user.email"):
            raise PreflightError("Git commit user.name and user.email are required")
        return (
            repo,
            source_head,
            config,
            prd,
            config_bytes,
            prd_bytes,
            worker_briefs,
            resume_store,
        )

    def run(self) -> OrchestrationResult:
        (
            repo,
            source_head,
            config,
            prd,
            config_bytes,
            prd_bytes,
            worker_briefs,
            resume_store,
        ) = self._preflight()
        if resume_store is None:
            try:
                store = RunStore.create(
                    self.options.state_dir,
                    prd.path,
                    source_head,
                    [story.id for story in prd.stories],
                    config_path=config.path,
                    prd_bytes=prd_bytes,
                    config_bytes=config_bytes,
                )
            except (OSError, StateError) as exc:
                raise PreflightError(f"unable to initialize run state: {exc}") from exc
            try:
                workspace = GitWorkspace.create(
                    repo, self.options.state_dir, store.run_id, source_head
                )
            except (RalphError, OSError) as exc:
                store.set_run_status("FAILED", "WORKTREE_SETUP_FAILED")
                store.event("terminal_error", detail={"type": type(exc).__name__})
                return OrchestrationResult(
                    RunOutcome.FAILED, "WORKTREE_SETUP_FAILED", store.run_dir
                )
            store.state["worktreePath"] = str(workspace.path)
            store.state["workspaceBaseline"] = workspace.baseline_state()
            store._write_state()
        else:
            store = resume_store
            state_root = store.run_dir.parent.parent
            requested_state_root = Path(os.path.abspath(self.options.state_dir.expanduser()))
            if state_root.resolve() != requested_state_root.resolve():
                raise PreflightError("resume run does not belong to the requested state directory")
            try:
                workspace = GitWorkspace.open(
                    repo,
                    requested_state_root,
                    store.run_id,
                    source_head,
                    store.state.get("workspaceBaseline"),
                )
            except (RalphError, OSError) as exc:
                raise PreflightError(f"unable to reopen runtime worktree: {exc}") from exc
            if Path(str(store.state.get("worktreePath", ""))).resolve() != workspace.path.resolve():
                raise PreflightError("saved runtime worktree path mismatch")
        store.set_run_status("RUNNING")
        completed: set[str] = {
            story_id
            for story_id, story_state in store.state["stories"].items()
            if story_state["status"] == "PASS"
        }
        iterations = sum(
            story_state["status"] != "PENDING"
            for story_state in store.state["stories"].values()
        )
        active_story_id: Optional[str] = None
        active_attempt = 0
        try:
            for story in prd.stories:
                story_state = store.state["stories"][story.id]
                if story_state["status"] == "PASS":
                    continue
                if story_state["status"] == "BLOCKED":
                    active_story_id = story.id
                    active_attempt = int(story_state.get("attempts", 0))
                    pending = story_state.get("pendingEvidence")
                    if story_state.get("reason") != "BLOCKED_VERIFIER" or not isinstance(
                        pending, dict
                    ):
                        reason = "RESUME_STATE_INVALID"
                        store.set_run_status("FAILED", reason)
                        return OrchestrationResult(RunOutcome.FAILED, reason, store.run_dir)
                    manifest = tuple(pending.get("changedPaths", ()))
                    definitions = tuple(
                        config.checks[check_id] for check_id in story.required_checks
                    )
                    immutable_paths = tuple(
                        pattern
                        for definition in definitions
                        for pattern in definition.immutable_paths
                    )
                    try:
                        current_manifest = workspace.validate_manifest(
                            story.allowed_paths,
                            config.protected_paths,
                            immutable_paths,
                            known_manifest=manifest,
                        )
                        candidate_matches = (
                            tuple(current_manifest) == manifest
                            and workspace.head() == pending.get("baseSha")
                            and workspace.candidate_digest(manifest)
                            == pending.get("candidateDigest")
                            and workspace.workspace_digest() == pending.get("workspaceDigest")
                            and workspace.index_tree() == pending.get("evaluatedTree")
                        )
                    except GitPolicyError:
                        candidate_matches = False
                    if not candidate_matches:
                        reason = "RESUME_CANDIDATE_MISMATCH"
                        store.set_run_status("FAILED", reason)
                        return OrchestrationResult(RunOutcome.FAILED, reason, store.run_dir)
                    browser_evidence = _browser_evidence_for_story(
                        self.options.browser_evidence,
                        story.id,
                        str(pending["evaluatedTree"]),
                    )
                    if browser_evidence is None:
                        store.set_run_status("BLOCKED", "BLOCKED_VERIFIER")
                        return OrchestrationResult(
                            RunOutcome.BLOCKED, "BLOCKED_VERIFIER", store.run_dir
                        )
                    store.transition_story(
                        story.id,
                        "RUNNING",
                        attempt=active_attempt,
                        reason="BROWSER_EVIDENCE_RECEIVED",
                    )
                    commit = workspace.commit_verified(
                        f"feat(ralph-story): complete {story.id.lower()}\n\n"
                        "Problem: the story required an independently validated implementation.\n"
                        "Solution: accept the exact candidate tree after all configured gates passed.\n"
                        f"Scope: {story.id}.\n"
                        "Tests: orchestrator-owned required checks passed.\n\n"
                        "Co-authored-by: Codex <codex@frictionlessfuture.com>"
                    )
                    commit_tree = workspace.commit_tree(commit)
                    if commit_tree != pending["evaluatedTree"]:
                        reason = "TREE_IDENTITY_MISMATCH"
                        store.transition_story(
                            story.id, "FAIL", attempt=active_attempt, reason=reason
                        )
                        store.set_run_status("FAILED", reason)
                        return OrchestrationResult(RunOutcome.FAILED, reason, store.run_dir)
                    evidence = {
                        key: value
                        for key, value in pending.items()
                        if key not in {"candidateDigest", "workspaceDigest"}
                    }
                    evidence.update(
                        {
                            "browser": browser_evidence,
                            "commit": commit,
                            "commitTree": commit_tree,
                            "treeIdentityVerified": True,
                        }
                    )
                    story_state.pop("pendingEvidence", None)
                    story_state.pop("reason", None)
                    store.transition_story(
                        story.id, "PASS", attempt=active_attempt, evidence=evidence
                    )
                    completed.add(story.id)
                    active_story_id = None
                    continue
                if iterations >= self.options.max_iterations:
                    store.set_run_status("BLOCKED", "BLOCKED_BUDGET")
                    return OrchestrationResult(RunOutcome.BLOCKED, "BLOCKED_BUDGET", store.run_dir)
                if any(dependency not in completed for dependency in story.depends_on):
                    store.set_run_status("BLOCKED", "BLOCKED_DEPENDENCY")
                    return OrchestrationResult(RunOutcome.BLOCKED, "BLOCKED_DEPENDENCY", store.run_dir)
                iterations += 1
                active_story_id = story.id
                active_attempt = 1
                store.transition_story(story.id, "RUNNING", attempt=1)
                expected_head = workspace.head()
                definitions = tuple(config.checks[check_id] for check_id in story.required_checks)
                immutable_paths = tuple(
                    pattern for definition in definitions for pattern in definition.immutable_paths
                )
                ignored_before = workspace.ignored_digest()
                for attempt in range(1, self.options.max_attempts + 1):
                    active_attempt = attempt
                    if attempt > 1:
                        store.state["stories"][story.id]["attempts"] = attempt
                        store._write_state()
                    attempt_inventory_before = workspace.workspace_inventory()
                    attempt_digest_before = workspace.workspace_digest()
                    result = self.provider.run(
                        worker_briefs[story.id],
                        workspace.path,
                        self.options.timeout_seconds,
                    )
                    attempt_digest_after = workspace.workspace_digest()
                    if not isinstance(result, ProviderResult):
                        reason = "MALFORMED_PROVIDER_RESULT"
                        store.transition_story(story.id, "FAIL", attempt=attempt, reason=reason)
                        store.set_run_status("FAILED", reason)
                        store.event(
                            "terminal_error",
                            story_id=story.id,
                            attempt=attempt,
                            detail={"type": reason},
                        )
                        return OrchestrationResult(RunOutcome.FAILED, reason, store.run_dir)
                    try:
                        provider_metrics = normalize_provider_metrics(result)
                    except ValueError:
                        reason = "MALFORMED_PROVIDER_RESULT"
                        store.transition_story(story.id, "FAIL", attempt=attempt, reason=reason)
                        store.set_run_status("FAILED", reason)
                        store.event(
                            "terminal_error",
                            story_id=story.id,
                            attempt=attempt,
                            detail={"type": reason},
                        )
                        return OrchestrationResult(RunOutcome.FAILED, reason, store.run_dir)
                    store.event(
                        "provider_result",
                        story_id=story.id,
                        attempt=attempt,
                        detail={
                            "outcome": result.outcome.value,
                            "exitCode": result.exit_code,
                            "durationSeconds": round(result.duration_seconds, 6),
                            "metrics": provider_metrics,
                        },
                    )
                    if result.outcome == ProviderOutcome.SUCCESS:
                        if attempt_digest_after == attempt_digest_before:
                            reason = "BLOCKED_NO_PROGRESS"
                            store.transition_story(
                                story.id, "BLOCKED", attempt=attempt, reason=reason
                            )
                            store.set_run_status("BLOCKED", reason)
                            return OrchestrationResult(
                                RunOutcome.BLOCKED, reason, store.run_dir
                            )
                        break
                    if attempt_digest_after != attempt_digest_before:
                        reason = "PROVIDER_RESIDUAL_CHANGES"
                        store.transition_story(story.id, "FAIL", attempt=attempt, reason=reason)
                        store.set_run_status("FAILED", reason)
                        return OrchestrationResult(RunOutcome.FAILED, reason, store.run_dir)
                    retryable = result.outcome == ProviderOutcome.RATE_LIMIT or (
                        result.outcome == ProviderOutcome.TIMEOUT
                        and self.provider.timeout_retry_isolation_proven
                    )
                    if retryable and attempt < self.options.max_attempts:
                        continue
                    reason = f"PROVIDER_{result.outcome.value}"
                    store.transition_story(story.id, "FAIL", attempt=attempt, reason=reason)
                    store.set_run_status("FAILED", reason)
                    return OrchestrationResult(RunOutcome.FAILED, reason, store.run_dir)
                if workspace.head() != expected_head:
                    reason = "WORKER_MUTATED_HEAD"
                    store.transition_story(story.id, "FAIL", attempt=attempt, reason=reason)
                    store.set_run_status("FAILED", reason)
                    return OrchestrationResult(RunOutcome.FAILED, reason, store.run_dir)
                try:
                    workspace.enforce_workspace_limits()
                    if workspace.ignored_digest() != ignored_before:
                        raise GitPolicyError("provider mutated ignored files")
                    manifest = workspace.validate_manifest(
                        story.allowed_paths,
                        config.protected_paths,
                        immutable_paths,
                        baseline_inventory=attempt_inventory_before,
                    )
                except GitPolicyError as exc:
                    reason = "BLOCKED_NO_PROGRESS" if "no candidate changes" in str(exc) else "GIT_POLICY"
                    story_status = "BLOCKED" if reason == "BLOCKED_NO_PROGRESS" else "FAIL"
                    run_status = "BLOCKED" if reason == "BLOCKED_NO_PROGRESS" else "FAILED"
                    store.transition_story(
                        story.id, story_status, attempt=attempt, reason=reason
                    )
                    store.set_run_status(run_status, reason)
                    outcome = (
                        RunOutcome.BLOCKED
                        if run_status == "BLOCKED"
                        else RunOutcome.FAILED
                    )
                    return OrchestrationResult(outcome, reason, store.run_dir)
                before_checks = workspace.candidate_digest(manifest)
                evaluated_tree = workspace.stage_exact(manifest)
                checks = CheckRunner().run_all(
                    definitions,
                    workspace.path,
                    allow_host=self.provider.allows_host_checks,
                )
                if any(not check.passed for check in checks):
                    reason = "VALIDATION_FAILED"
                    store.transition_story(story.id, "FAIL", attempt=attempt, reason=reason)
                    store.event(
                        "validation_result",
                        story_id=story.id,
                        attempt=attempt,
                        detail={"checks": _check_evidence(checks)},
                    )
                    store.set_run_status("FAILED", reason)
                    return OrchestrationResult(RunOutcome.FAILED, reason, store.run_dir)
                if workspace.head() != expected_head:
                    reason = "VALIDATOR_MUTATED_HEAD"
                    store.transition_story(story.id, "FAIL", attempt=attempt, reason=reason)
                    store.set_run_status("FAILED", reason)
                    return OrchestrationResult(RunOutcome.FAILED, reason, store.run_dir)
                current_manifest = workspace.validate_manifest(
                    story.allowed_paths,
                    config.protected_paths,
                    immutable_paths,
                    baseline_inventory=attempt_inventory_before,
                )
                if tuple(manifest) != tuple(current_manifest) or workspace.candidate_digest(manifest) != before_checks:
                    reason = "VALIDATOR_MUTATED_CANDIDATE"
                    store.transition_story(story.id, "FAIL", attempt=attempt, reason=reason)
                    store.set_run_status("FAILED", reason)
                    return OrchestrationResult(RunOutcome.FAILED, reason, store.run_dir)
                if workspace.index_tree() != evaluated_tree:
                    reason = "VALIDATOR_MUTATED_INDEX"
                    store.transition_story(story.id, "FAIL", attempt=attempt, reason=reason)
                    store.set_run_status("FAILED", reason)
                    return OrchestrationResult(RunOutcome.FAILED, reason, store.run_dir)
                browser_evidence = None
                if story.requires_browser:
                    browser_result = next(
                        (
                            result
                            for definition, result in zip(definitions, checks)
                            if definition.kind == "browser" and result.passed
                        ),
                        None,
                    )
                    if browser_result is not None:
                        browser_evidence = {
                            "storyId": story.id,
                            "status": "PASS",
                            "evaluatedTree": evaluated_tree,
                            "verifier": browser_result.id,
                        }
                    else:
                        browser_evidence = _browser_evidence_for_story(
                            self.options.browser_evidence, story.id, evaluated_tree
                        )
                if story.requires_browser and browser_evidence is None:
                    reason = "BLOCKED_VERIFIER"
                    store.state["stories"][story.id]["pendingEvidence"] = {
                        "runId": store.run_id,
                        "storyId": story.id,
                        "attempt": attempt,
                        "prdDigest": store.state["prdDigest"],
                        "configDigest": store.state["configDigest"],
                        "baseSha": expected_head,
                        "providerOutcome": result.outcome.value,
                        "providerMetrics": provider_metrics,
                        "changedPaths": list(manifest),
                        "checks": _check_evidence(checks),
                        "evaluatedTree": evaluated_tree,
                        "candidateDigest": workspace.candidate_digest(manifest),
                        "workspaceDigest": workspace.workspace_digest(),
                    }
                    store._write_state()
                    store.transition_story(story.id, "BLOCKED", attempt=attempt, reason=reason)
                    store.set_run_status("BLOCKED", reason)
                    return OrchestrationResult(RunOutcome.BLOCKED, reason, store.run_dir)
                commit = workspace.commit_verified(
                    f"feat(ralph-story): complete {story.id.lower()}\n\n"
                    "Problem: the story required an independently validated implementation.\n"
                    "Solution: accept the exact candidate tree after all configured gates passed.\n"
                    f"Scope: {story.id}.\n"
                    "Tests: orchestrator-owned required checks passed.\n\n"
                    "Co-authored-by: Codex <codex@frictionlessfuture.com>"
                )
                commit_tree = workspace.commit_tree(commit)
                if commit_tree != evaluated_tree:
                    reason = "TREE_IDENTITY_MISMATCH"
                    store.transition_story(story.id, "FAIL", attempt=attempt, reason=reason)
                    store.set_run_status("FAILED", reason)
                    return OrchestrationResult(RunOutcome.FAILED, reason, store.run_dir)
                evidence = {
                    "runId": store.run_id,
                    "storyId": story.id,
                    "attempt": attempt,
                    "prdDigest": store.state["prdDigest"],
                    "configDigest": store.state["configDigest"],
                    "baseSha": expected_head,
                    "providerOutcome": result.outcome.value,
                    "providerMetrics": provider_metrics,
                    "changedPaths": list(manifest),
                    "checks": _check_evidence(checks),
                    "evaluatedTree": evaluated_tree,
                    "commit": commit,
                    "commitTree": commit_tree,
                    "treeIdentityVerified": True,
                }
                if browser_evidence is not None:
                    evidence["browser"] = browser_evidence
                store.transition_story(story.id, "PASS", attempt=attempt, evidence=evidence)
                completed.add(story.id)
                active_story_id = None
            store.set_run_status("COMPLETE")
            return OrchestrationResult(RunOutcome.COMPLETE, "VERIFIED_COMPLETE", store.run_dir)
        except KeyboardInterrupt:
            if active_story_id is not None:
                story_state = store.state["stories"][active_story_id]
                if story_state["status"] == "RUNNING":
                    store.transition_story(
                        active_story_id,
                        "BLOCKED",
                        attempt=active_attempt,
                        reason="USER_CANCELLED",
                    )
            store.set_run_status("CANCELLED", "USER_CANCELLED")
            return OrchestrationResult(RunOutcome.CANCELLED, "USER_CANCELLED", store.run_dir)
        except RalphError as exc:
            if active_story_id is not None:
                story_state = store.state["stories"][active_story_id]
                if story_state["status"] == "RUNNING":
                    store.transition_story(
                        active_story_id,
                        "FAIL",
                        attempt=active_attempt,
                        reason=type(exc).__name__,
                    )
            store.set_run_status("FAILED", type(exc).__name__)
            store.event("terminal_error", detail={"type": type(exc).__name__})
            return OrchestrationResult(RunOutcome.FAILED, type(exc).__name__, store.run_dir)
        except Exception as exc:
            if active_story_id is not None:
                story_state = store.state["stories"][active_story_id]
                if story_state["status"] == "RUNNING":
                    store.transition_story(
                        active_story_id,
                        "FAIL",
                        attempt=active_attempt,
                        reason="INTERNAL_ERROR",
                    )
            store.set_run_status("FAILED", "INTERNAL_ERROR")
            store.event("terminal_error", detail={"type": type(exc).__name__})
            return OrchestrationResult(RunOutcome.FAILED, "INTERNAL_ERROR", store.run_dir)
