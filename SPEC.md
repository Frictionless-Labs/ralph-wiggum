---
title: Ralph Wiggum Hardened Runtime Specification
version: 2.0.0
status: implemented-candidate
created_date: 2026-09-05
tags: [LAB, ralph-wiggum, security]
confidence: 97
owner: MIKKOH Chen
---

# Ralph Wiggum Hardened Runtime Specification

## Scope

This specification is normative for P0 `REQ-001–007`, P1 `REQ-008–014`, and P2 `REQ-015–021`. It preserves the fresh-context, one-story iteration model and replaces prompt-owned state, Git, validation, and completion authority with a deterministic standard-library Python control plane.

Automatic push, merge, deployment, repository administration, live n8n integration, and unsupported statistical accuracy claims are out of scope. The repository implements only a data-contract boundary for outer schedulers and a deterministic report gate for independently labeled observations.

## Invariants

| ID | Invariant |
|---|---|
| `INV-001` | A provider process can produce candidate files and observations, but cannot author canonical PASS or COMPLETE state. |
| `INV-002` | Preflight completes before provider invocation. Invalid PRD/config/path/tool conditions cause zero provider calls. |
| `INV-003` | Every run starts from a recorded source HEAD in a dedicated detached Git worktree. Dirty parent content is excluded. |
| `INV-004` | PRD check IDs resolve only through a frozen named argv registry. No PRD shell string is executed. |
| `INV-005` | Failed, timed-out, or unavailable checks block PASS. UI verification never silently downgrades. |
| `INV-006` | Checks may not mutate candidate content. The evaluated tree must equal the committed tree. |
| `INV-007` | Iteration, attempt, provider-timeout, and check-timeout limits are positive and enforced. |
| `INV-008` | Shared Git and deployment mutation is absent from the runtime. |

## Inputs

The CLI accepts explicit `--repo`, `--prd`, `--config`, and `--state-dir` paths and prints their resolved values before execution. The legacy positional iteration count is supported; safe defaults resolve from the installed repository, with state outside the source checkout.

`schemas/prd.schema.json` defines the structural format. The standard-library semantic validator additionally enforces unique IDs, positive priorities, known acyclic dependencies, safe repository-relative path patterns, known check IDs, Boolean browser declarations, and no more than eight unique safe reference paths. Legacy `passes` is inert migration data.

References are read only as regular tracked blobs from the immutable source HEAD, never from the live checkout. Each reference is limited to 32 KiB, their aggregate is limited to 64 KiB, and the complete story prompt is limited to 128 KiB. Missing, untracked, protected, credential-bearing, API-key-named, secret-like, symlink, gitlink, invalid UTF-8, or oversized references fail before provider execution.

`ralph.config.json` has version `1`, protected path patterns, and named check objects containing non-empty argv arrays and positive timeouts. It is operator policy, not provider output.

## Trusted state and evidence

Each run directory contains:

| Artifact | Contract |
|---|---|
| `prd.snapshot.json` | Byte-exact immutable input snapshot with SHA-256 in state |
| `config.snapshot.json` | Byte-exact immutable check-policy snapshot with SHA-256 in state |
| `run.json` | Atomically replaced canonical state with run/story status and evidence |
| `events.jsonl` | Append-only, fsynced, structured transition/event records with sensitive-key redaction |
| `worktrees/<run-id>` | Disposable runtime worktree outside provider-owned state |

Run states are `CREATED`, `RUNNING`, `COMPLETE`, `BLOCKED`, `FAILED`, and `CANCELLED`. Story states are `PENDING`, `RUNNING`, `PASS`, `FAIL`, and `BLOCKED`. Illegal transitions raise a state error, except that final-tree revalidation may downgrade PASS to FAIL. Canonical state directories must be owned by the invoking user, deny group/other writes, and have no replaceable ancestor owned by an untrusted principal; sticky shared ancestors owned by the user or root remain valid. The hierarchy is revalidated before loading state or acquiring a resume lock. Resuming a blocked run requires the persisted run ID to equal its canonical directory name and holds an exclusive owner-only per-run lock from state load through terminal persistence; a concurrent resume fails before reopening shared state or its worktree.

Every PASS evidence object includes run ID, story ID, attempt, PRD/config digests, source/base SHA, provider outcome and typed metrics, exact changed paths, named check outcomes and immutable image identities, output digests and bounded redacted tails, browser evidence when required, evaluated tree, commit ID, commit tree, and an explicit tree-equality proof. COMPLETE is valid only when every frozen story is PASS.

## Provider execution

All providers implement the same `run(prompt, cwd, timeout)` contract and return `SUCCESS`, `NONZERO`, `EMPTY_OUTPUT`, `TIMEOUT`, `RATE_LIMIT`, `UNAVAILABLE`, `MALFORMED_RESULT`, `CANCELLED`, `RESOURCE_LIMIT`, or `INTERNAL_ERROR`.

Subprocesses receive an allowlisted environment with a fixed trusted executable path, a bounded timeout, bounded output files, captured exit status, and their own process group. Evidence retains full-stream byte counts and SHA-256 digests plus bounded, secret-pattern-redacted output tails. Provider-supplied turns, tokens, cost, truncation, byte counts, and digests are accepted only through the typed allowlist; missing telemetry stays absent and malformed telemetry is terminal. Candidate growth is guarded during execution and checked before Git enumeration: at most 2,048 new filesystem entries, 64 MiB growth per file, and 512 MiB aggregate growth from the immutable worktree baseline. The provider container additionally enforces a hard 64 MiB file-size resource limit. Cancellation or a resource violation terminates the process group. Rate-limit outcomes may retry only within the configured attempt ceiling and only when the complete HEAD plus every non-Git workspace entry, type, mode, and content digest is unchanged. Timeout outcomes additionally require provider-specific teardown proof; the production Codex adapter fails terminally because container removal cannot be proved after forced process-group termination. Residual edits, mode changes, and empty directories fail terminally rather than entering a later attempt. Resource-limit and other deterministic failures do not retry blindly. A successful provider attempt with no attempt-local change blocks immediately as `BLOCKED_NO_PROGRESS`.

Codex runs non-interactively inside the pinned `ralph-codex-provider:0.145.0-r1` image. The outer container is read-only, capability-dropped except for the minimum `SYS_ADMIN` needed to create Codex's nested bubblewrap namespace, has no Docker socket, and mounts only the disposable worktree plus a read-only authentication file. The inner custom permission profile grants the worktree, denies worker reads of the authentication file, blocks direct worker network access, and produces a zero-effective-capability child. Preflight proves these boundaries before any provider call; Docker/image/auth/sandbox failure invokes zero providers.

The image uses the official Codex package at version `0.145.0`, strict configuration, approval policy `never`, ignored user configuration and exec-policy rules, documented non-repository mode because linked-worktree Git metadata is intentionally hidden, and ephemeral session state. The launcher resolves the reviewed image tag to its immutable local image ID and repeats the confinement proof against that same ID immediately before every provider invocation. Host-native Codex is disabled because its verified `workspace-write` policy permits reads outside the worktree and custom macOS profiles abort on the installed version. Claude and Amp also fail closed pending enforceable confinement and verified contracts. No enabled provider adapter uses a permission/sandbox bypass flag.

## Git and evaluation

The worktree is registered without checkout and materialized from raw recorded-HEAD blobs, so repository Git filters never execute on the host and parent working-tree content cannot enter the run. Source trees containing gitlinks, cross-platform case or Unicode-normalization path collisions, and symlinked materialization parents fail closed because they cannot preserve an exact portable filesystem tree. The orchestrator builds the changed-path manifest from tracked changes and untracked non-ignored files, then separately rejects provider-created ignored files. It compares the final non-Git filesystem inventory with the attempt baseline and permits only new parent directories required by manifest files, so empty directories, worktree-root metadata, and directory-mode mutations cannot bypass scope. It rejects empty candidates, paths outside `allowedPaths`, configured protected paths, secret-like path components, traversal, nested `.git` metadata, current or source-tree symlinks, and worker changes to existing validator files matched by required checks' `immutablePaths`.

Only regular blob manifest paths are staged; symlinks, directories, nested repositories, and gitlinks are rejected. Workspace quotas are enforced before inventory expansion, file digests stream in bounded chunks, and exact staging uses raw `hash-object --no-filters` plus NUL-delimited index plumbing. Snapshot materialization reads index blobs directly, so repository clean/smudge filters never execute on the host. Worktree creation and verified commits both disable repository hooks. State, worktrees, and resumed worktrees are lexical-path and repository-identity checked before use. The orchestrator records a candidate digest and staged tree, resolves each reviewed validator tag to an immutable local image ID, materializes only the staged index into a temporary snapshot, and mounts that snapshot read-only for every named check. Every validator `immutablePaths` pattern used anywhere in the run applies to every story. Explicit `scratchMounts` provide only the reviewed cache/build paths needed across checks; combined parent/child overlaps fail before run creation, every source component is revalidated immediately before each bind mount, and candidate source plus validators remain read-only. Network remains disabled unless the reviewed check enables it. Named containers are forcibly removed after every check outcome, including Docker-client output-limit termination. Evidence records the resolved image ID, full-output digests, and redacted bounded tails. A later story may not modify a path owned by prior PASS evidence, every earlier story's named checks are rerun against the final descendant tree, and browser-required stories must retain synchronous or external evidence bound to that same final tree before COMPLETE. Resumed runs resolve immutable image IDs for both pending stories and any blocked story whose checks can be rerun against a later descendant. Every final validator is followed by a complete workspace digest and index-tree identity check, and every PASS story must retain structured tree-bound evidence before COMPLETE. The orchestrator then revalidates scope and digest, validates a passing current-run `kind: browser` check or exact-tree external evidence when required, commits with repository hooks disabled, and verifies `commit^{tree}` equals the evaluated tree. A `BLOCKED_VERIFIER` run persists the staged candidate and its digests; `--resume-run` reopens only that exact worktree, revalidates the candidate/index identity, and accepts matching external evidence without rerunning the blocked provider attempt. Any mismatch is terminal and cannot PASS.

## Exit and recovery contract

| Exit | Meaning |
|---:|---|
| `0` | Verified COMPLETE |
| `2` | Preflight/configuration rejection before provider execution |
| `3` | Explicit BLOCKED/incomplete outcome |
| `4` | Provider, validation, Git, cancellation, or internal failure |

Failed, blocked, and cancelled state/worktrees are preserved. Safe recovery is inspection followed by a new run from the intended HEAD; the runtime never cleans the operator checkout.

## P0/P1 traceability

| REQ | Modules | Tasks | Tests/evidence |
|---|---|---|---|
| `REQ-001` | `MOD-02`, `MOD-06` | `TASK-GUIDE-002`, `TASK-GUIDE-006` | `TEST-001`; magic token cannot complete |
| `REQ-002` | `MOD-02`, `MOD-06` | `TASK-GUIDE-002`, `TASK-GUIDE-006` | `TEST-008`; state outside worker authority |
| `REQ-003` | `MOD-04` | `TASK-GUIDE-004` | `TEST-002`; nonzero result preserved |
| `REQ-004` | `MOD-03` | `TASK-GUIDE-003` | `TEST-005`; dirty parent excluded |
| `REQ-005` | `MOD-01` | `TASK-GUIDE-001` | `TEST-003`, `TEST-004`; fail-closed semantic validation |
| `REQ-006` | `MOD-04`, `MOD-06` | `TASK-GUIDE-004`, `TASK-GUIDE-006` | `TEST-011`; bounded timeout/retry/budget |
| `REQ-007` | `MOD-03`, `MOD-05`, `MOD-06` | `TASK-GUIDE-003`, `TASK-GUIDE-005`, `TASK-GUIDE-006` | `TEST-006`, `TEST-007`, `TEST-009`; scope/check/tree gates |
| `REQ-008` | `MOD-02` | `TASK-GUIDE-008` | `TEST-012`; immutable digest/snapshot |
| `REQ-009` | `MOD-01`, `MOD-06` | `TASK-GUIDE-011` | `TEST-016`; explicit printed paths and legacy positional count |
| `REQ-010` | `MOD-05`, `MOD-07` | `TASK-GUIDE-008` | `TEST-010`; `BLOCKED_VERIFIER` |
| `REQ-011` | `MOD-02`, `MOD-08` | `TASK-GUIDE-008` | `TEST-017`; append-only redacted events/evidence |
| `REQ-012` | `MOD-09` | `TASK-GUIDE-009` | `TEST-018`; ESLint passes without rule relaxation |
| `REQ-013` | `MOD-09` | `TASK-GUIDE-009` | `TEST-019`; repository-name base build |
| `REQ-014` | `MOD-09` | `TASK-GUIDE-010` | `TEST-014`, `TEST-020`; PR CI, deploy dependency, SHA pins, permissions |

## P2 traceability

| REQ | Modules | Tasks | Tests/evidence |
|---|---|---|---|
| `REQ-015` | `MOD-01`, `MOD-06` | `TASK-GUIDE-011` | `TEST-013`, `TEST-022`; bounded immutable references and worker brief |
| `REQ-016` | `MOD-04`, `MOD-06` | `TASK-GUIDE-006` | `TEST-023`; shared typed provider result and fail-closed adapters |
| `REQ-017` | `MOD-04`, `MOD-08` | `TASK-GUIDE-008` | `TEST-024`; optional schema-checked observed metrics |
| `REQ-018` | `MOD-06` | `TASK-GUIDE-006` | `TEST-025`; immediate typed no-progress block |
| `REQ-019` | `MOD-02`, `MOD-06` | `TASK-GUIDE-008` | `TEST-017`; complete run/input/check/tree-bound PASS evidence |
| `REQ-020` | `MOD-10` | `TASK-GUIDE-012` | `TEST-026`; strict data-only outer-scheduler command contract |
| `REQ-021` | `MOD-10` | `TASK-GUIDE-012` | `TEST-027`; independently labeled confusion-count report gate |

## Outer scheduler and accuracy boundary

`ralph_hardened.governance.validate_outer_command` accepts only action-specific schema version 1 objects for `submit`, `status`, `events`, `request_approval`, and `cancel`. The outer layer supplies data, never shell commands or state transitions; the orchestrator retains input validation, provider credentials, Git, PASS/COMPLETE, and release authority. No live n8n deployment is implied.

`ralph_hardened.governance.build_accuracy_report` requires a named independent label source, a positive sample count, and non-negative integer TP/TN/FP/FN counts whose sum exactly matches the sample count. Undefined denominators yield `null`. No repository test result is converted into an accuracy claim.

## Compatibility divergences

| Change | Reason | Impact | Reversal |
|---|---|---|---|
| Python coordinator behind `ralph.sh` | Structured state, errors, and tests exceed safe shell ergonomics | Python 3.9+ becomes required | Revert hardening branch; unsafe legacy behavior returns |
| Default provider is containerized Codex | Prevent host reads while retaining the verified provider contract | Docker and a locally built pinned image become required; host-native Codex, Claude, and Amp stay blocked | Rebuild the pinned image after reviewing a Codex upgrade and rerun confinement proof |
| `passes` and completion tokens are inert | Eliminate self-certification | Legacy PRDs need scope/check fields | No safe reversal; migrate the PRD |
| Runtime commits in detached worktree | Preserve user work and bind evidence | Operator must explicitly integrate the verified commit | Cherry-pick or merge only after review |
| Progress text is not loaded | Bound context and protect state | Prior prose is not automatic memory | Select reviewed tracked blobs with bounded `references` |
