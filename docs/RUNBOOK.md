---
title: Ralph Wiggum Hardened Operator Runbook
version: 2.0.0
status: implemented-candidate
created_date: 2026-09-05
tags: [LAB, ralph-wiggum, operations]
confidence: 97
owner: MIKKOH Chen
---

# Ralph Wiggum Hardened Operator Runbook

## Terminal Command

````bash
cd /absolute/path/to/ralph-wiggum
./ralph.sh --repo /absolute/path/to/target-repository --prd /absolute/path/to/prd.json --config /absolute/path/to/ralph.config.json --state-dir /absolute/path/to/ralph-state --tool codex --max-iterations 10 --max-attempts 2 --timeout-seconds 1800
````

## Session Title

`CODEX_RALPH_WIGGUM_HARDENING_RUNTIME`

## Runbook

**Objective:** complete small stories in fresh provider contexts while preserving user work and requiring independent scope, validation, evidence, and Git identity gates.

**Allowed paths:** each story's non-empty `allowedPaths` only. Runtime state and worktrees must be explicit and outside the source repository. Push, merge, deploy, branch protection, repository settings, and credential changes are not runtime capabilities.

### 1. Preflight

````bash
cd /absolute/path/to/ralph-wiggum
python3 --version
git --version
docker version
docker image inspect ralph-codex-provider:0.145.0-r1
docker image inspect ralph-validator:1.0.1
stat -f '%Sp %u %N' "$HOME/.codex/auth.json"
./scripts/run-codex-provider.sh --preflight
python3 -m json.tool /absolute/path/to/prd.json >/dev/null
python3 -m json.tool /absolute/path/to/ralph.config.json >/dev/null
git -C /absolute/path/to/target-repository rev-parse --show-toplevel
git -C /absolute/path/to/target-repository rev-parse HEAD
git -C /absolute/path/to/target-repository status --short
````

If either runtime image is absent, build it from the reviewed Dockerfiles before running:

````bash
cd /absolute/path/to/ralph-wiggum
docker build --pull --tag ralph-codex-provider:0.145.0-r1 --build-arg CODEX_VERSION=0.145.0 docker/codex-provider
docker build --pull --tag ralph-validator:1.0.1 docker/validator
./scripts/run-codex-provider.sh --preflight
````

The source checkout may be dirty because execution uses a detached worktree from HEAD. Confirm that excluding uncommitted parent content is intended. Fix malformed inputs, unknown checks, unsafe paths, duplicate IDs, dependency cycles, source-tree gitlinks, missing author identity, insecure authentication-file metadata, or unavailable required tools before running. Do not mount additional host paths into the provider container. Validator `scratchMounts` must be reviewed cache/output directories only; parent/child overlaps are prohibited, source components are revalidated before each bind, and candidate source plus validators remain in the read-only staged-tree snapshot.

### 2. Execute

Run the terminal command exactly once. Ralph prints the resolved repository, PRD, configuration, state, provider, and iteration limit before provider invocation.

Use a story's optional `references` only for reviewed, tracked, repository-relative text blobs from the source HEAD. Do not reference generated progress history, credentials, symlinks, untracked files, or protected paths. The runtime enforces eight files, 32 KiB per file, 64 KiB aggregate, and a 128 KiB complete worker brief.

For a UI story, the preferred synchronous path is a required named check declared with `kind: browser` in the operator-reviewed configuration. Ralph runs that verifier after staging and binds its PASS to the current tree automatically.

If no synchronous browser check is available, pass an independent JSON evidence file with one entry per verified story. Each PASS must bind the story to the exact staged Git tree and name the verifier:

````json
{
  "schemaVersion": 1,
  "evidence": [
    {
      "storyId": "US-001",
      "status": "PASS",
      "evaluatedTree": "<exact-git-tree-id>",
      "verifier": "<independent-verifier-name>"
    }
  ]
}
````

Absence, malformed evidence, a stale tree ID, or evidence for another story yields `BLOCKED_VERIFIER`; Ralph does not downgrade to prose verification. If the candidate tree is not known in advance and no browser check is configured, let the first run block, independently verify the preserved staged tree, and record that exact tree ID. Resume the same run so Ralph revalidates the unchanged candidate and index before committing it; the provider is not rerun for the blocked story. A per-run exclusive lock rejects concurrent resume attempts before shared state or the worktree is reopened:

````bash
cd /absolute/path/to/ralph-wiggum
./ralph.sh \
  --repo /absolute/path/to/target-repository \
  --resume-run /absolute/path/to/ralph-state/runs/<run-id> \
  --browser-evidence /absolute/path/to/browser-evidence.json \
  --tool codex \
  --max-iterations 10 \
  --max-attempts 2 \
  --timeout-seconds 1800
````

### 3. Inspect evidence

````bash
cd /absolute/path/to/run-directory
python3 -m json.tool run.json
tail -n 50 events.jsonl
git -C /absolute/path/to/runtime-worktree status --short
git -C /absolute/path/to/runtime-worktree log --oneline --decorate -5
git -C /absolute/path/to/runtime-worktree write-tree
````

For each PASS, confirm the run/story/attempt, PRD/config digests, source SHA, changed paths, provider outcome/typed metrics, check evidence, browser evidence when required, and tree identity are present. `evaluatedTree` must equal `commitTree`, every named check must PASS, every `containerImage` must be an immutable `sha256:` image ID, and full-output digests plus redacted bounded tails must be present. Provider prose is not evidence.

### 4. Interpret outcomes

| Outcome/reason | Meaning | Safe next action |
|---|---|---|
| `VERIFIED_COMPLETE` / exit `0` | Every frozen story has tree-bound PASS evidence | Review detached commits; integrate only with explicit authorization |
| `PRECHECK_REJECTED` / exit `2` | Input/config/environment failed before provider use | Correct the named defect and start a new run |
| `BLOCKED_VERIFIER` / exit `3` | UI evidence capability/result absent | Verify the staged tree independently and resume the same run with exact-tree evidence |
| `BLOCKED_BUDGET` / exit `3` | Iteration ceiling reached with work pending | Review remaining stories; raise ceiling only after scope/cost review |
| `BLOCKED_NO_PROGRESS` / exit `3` | Worker returned success text without an authorized file change | Refine the story/provider instructions; do not mark PASS manually |
| `PROVIDER_NONZERO` / exit `4` | Provider exited nonzero | Inspect provider authentication/configuration outside logs; do not expose secrets |
| `PROVIDER_TIMEOUT` / exit `4` | Provider timed out; production does not retry without teardown proof | Inspect preserved state, then reduce story size or raise timeout deliberately |
| `PROVIDER_RESIDUAL_CHANGES` / exit `4` | A failed retryable attempt changed the workspace | Inspect the preserved worktree; never inherit partial edits into another attempt |
| `PROVIDER_RESOURCE_LIMIT` / exit `4` | Candidate exceeded entry, file-growth, or aggregate-growth limits | Split the story or narrow generated artifacts; do not raise limits without security review |
| `PRECHECK_REJECTED` with provider confinement detail / exit `2` | Docker, image, authentication metadata, or inner sandbox proof failed | Repair only the named boundary and rerun `./scripts/run-codex-provider.sh --preflight` |
| `PROVIDER_UNAVAILABLE` / exit `4` | Selected executable became unavailable after preflight | Restore the verified provider dependency; do not bypass its container |
| `VALIDATION_FAILED` / exit `4` | Named check failed or was unavailable | Fix the candidate/check dependency; never skip the check |
| `GIT_POLICY` / exit `4` | Scope, protected path, secret, traversal, or symlink policy failed | Narrow the implementation or explicitly revise reviewed scope |
| `TREE_IDENTITY_MISMATCH` / exit `4` | Committed content differs from evaluated content | Treat as a security failure; do not integrate the commit |
| `USER_CANCELLED` / exit `4` | Execution was interrupted | Inspect preserved state/worktree; start a new run from the intended HEAD |

### 5. Recovery and restart

State and runtime worktrees are intentionally preserved on failure. Do not delete, reset, clean, stash, or restore the operator checkout. Record the failed run directory, inspect its evidence, correct only the proved cause, and start a new run; the old snapshot and event log remain the audit record.

If a runtime worktree must later be removed, obtain explicit authorization and verify its exact path and Git status first. This runbook does not authorize removal.

### 6. Outer scheduler and accuracy reporting

An outer scheduler may submit an approved data-only request, query status, receive redacted events, request human approval, or cancel an existing run. Validate every such object with `validate_outer_command`; action-specific extra fields are rejected. The outer scheduler cannot write `run.json`, mark PASS/COMPLETE, supply a shell command, mutate Git, access provider credentials, merge, deploy, or administer GitHub.

No numerical accuracy or reliability result may be reported from deterministic tests alone. `build_accuracy_report` requires an independent label source and raw sample/TP/TN/FP/FN counts; mismatched counts fail and undefined rates remain `null`. Human-labeled observations and any business-performance conclusion remain external evidence.

### 7. Local release validation

````bash
cd /absolute/path/to/ralph-wiggum
python3 -m unittest discover -s tests -v
bash -n ralph.sh
bash -n scripts/run-codex-provider.sh
./scripts/run-codex-provider.sh --preflight
npm --prefix flowchart ci --ignore-scripts
npm --prefix flowchart audit --audit-level=high
npm --prefix flowchart run lint
VITE_BASE_PATH=/ralph-wiggum/ npm --prefix flowchart run build
````

Remote CI is `configured but remote run not observed` until the branch is explicitly published and an actual run is inspected. This runbook does not authorize publication or deployment.

## Stop Condition

`CODEX_RALPH_WIGGUM_HARDENING_RUNTIME_COMPLETE` when exit `0`, every story is PASS, tree identities match, local required checks pass, and the candidate is independently reviewed.

`CODEX_RALPH_WIGGUM_HARDENING_RUNTIME_BLOCKED_<REASON>` for any typed blocked/failure outcome or missing remote authorization/evidence.

## After Completion

| Outcome | Next action |
|---|---|
| Local candidate validated; no remote authority | Preserve branch/worktree and request explicit publish/PR authority |
| Published candidate with green CI | Request independent human review; do not merge automatically |
| Any required check or security finding fails | Repair in isolation and repeat the entire validation ladder |
| Deployment is explicitly authorized after green CI | Run a separate deployment preflight with rollback and target-runtime evidence |
