# Ralph Agent Instructions

## Authority boundary

Ralph preserves one fresh provider context per story, but the provider is an untrusted candidate producer. Only the orchestrator may validate inputs, create runtime worktrees, stage or commit files, write canonical state/evidence, mark a story PASS, or mark a run COMPLETE.

Provider output, `passes` fields, completion tokens, and prose test claims have no state authority. Providers must not push, merge, deploy, change repository settings, or administer shared infrastructure.

## Canonical commands

````bash
./ralph.sh --repo /absolute/path/to/project --prd /absolute/path/to/prd.json --config /absolute/path/to/ralph.config.json --state-dir /absolute/path/to/state --tool codex --max-iterations 10
docker build --pull --tag ralph-codex-provider:0.145.0-r1 --build-arg CODEX_VERSION=0.145.0 docker/codex-provider
docker build --pull --tag ralph-validator:1.0.1 docker/validator
./scripts/run-codex-provider.sh --preflight
python3 -m unittest discover -s tests -v
bash -n ralph.sh
npm --prefix flowchart run lint
VITE_BASE_PATH=/ralph-wiggum/ npm --prefix flowchart run build
````

Legacy positional iteration count remains supported: `./ralph.sh 10`. Verified provider names are containerized `codex` and fixture-only `mock`. Host-native Codex, Claude, and Amp fail closed until enforceable filesystem confinement and their installed CLI contracts can be verified. Docker, the pinned image, authentication-file metadata, and the nested filesystem/network/capability boundary are proved before any provider call.

## Required input contract

Every PRD story requires non-empty `allowedPaths` and `requiredChecks`. Optional `dependsOn` IDs must exist and be acyclic. `requiresBrowser: true` requires either a passing required check with `kind: browser` or exact-tree external evidence; absence blocks with `BLOCKED_VERIFIER`. Optional `references` select at most eight tracked regular blobs from the frozen source tree. References are repository-relative, unique, protected/secret-safe, individually limited to 32 KiB, and collectively limited to 64 KiB; the complete worker brief is limited to 128 KiB.

Named check commands live in the operator-reviewed `ralph.config.json`, are argv arrays, and require a pinned `containerImage`; they are never PRD-authored shell strings. The orchestrator freezes config and PRD objects before invoking a provider.
Existing files matched by a check's `immutablePaths` cannot be worker-modified, and provider-created ignored files are rejected before validation.

## P2 governance contracts

- Provider metrics are optional typed observations. Missing values stay absent; unknown, estimated, non-finite, or malformed values fail closed.
- An unchanged successful attempt blocks immediately as `BLOCKED_NO_PROGRESS`; provider prose never resets progress. A timed-out or rate-limited attempt may retry only if its complete workspace digest is unchanged; residual edits are terminal and cannot contaminate a later attempt.
- PASS evidence binds run/story/attempt, immutable input digests, source SHA, paths, named checks, provider metrics, evaluated tree, commit, and equality proof.
- Outer schedulers may submit an approved data-only request, query status, receive redacted events, request approval, or cancel by run ID. They cannot write state, provide commands, mutate Git, mark PASS/COMPLETE, access credentials, or release software.
- Numerical accuracy reports require an independently labeled sample count and raw TP/TN/FP/FN counts. Deterministic test success is implementation evidence, not a reliability percentage.

## Mutation contract

- The source checkout may be dirty; Ralph records its HEAD and creates a detached runtime worktree from that commit.
- Provider changes are accepted only when every changed path matches the story allowlist and no path is protected, secret-like, traversing, or a symlink.
- Checks run outside provider authority in a capability-dropped container against a read-only snapshot of the exact staged tree. Only reviewed `scratchMounts` may be writable. A check that fails, times out, or is unavailable blocks PASS.
- The candidate digest must remain unchanged while checks run.
- The evaluated staged tree must equal the resulting commit tree.
- Runtime state lives outside the provider worktree and is written atomically with append-only events.

## Validation ladder

Run targeted Python tests while changing control-plane modules. Before any commit, run the full Python suite, shell syntax, dependency audit, flowchart lint, fork-base build, workflow policy checks, and a representative runtime fixture. Never weaken or skip a gate to obtain PASS.

## Recovery

Ralph preserves failed, blocked, and cancelled run directories and runtime worktrees. Inspect `run.json` and `events.jsonl`; fix the input or external dependency; then start a new run from the intended source HEAD. Never clean a user checkout as recovery.

## Durable files

- `SPEC.md` — normative contracts and traceability.
- `docs/RUNBOOK.md` — operator procedure and failure recovery.
- `schemas/prd.schema.json` — structural PRD contract.
- `ralph.config.json` — named deterministic check registry.
- `prompt.md` and `CLAUDE.md` — legacy provider boundary documentation only.
