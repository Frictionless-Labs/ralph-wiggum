# Ralph

![Ralph](ralph.webp)

Ralph runs one small coding story per fresh AI context. The hardened runtime keeps that useful loop while moving state, validation, Git commits, failure handling, and completion authority into a deterministic local orchestrator.

## Safety model

| Component | May do | May not do |
|---|---|---|
| Worker provider | Edit story-allowed files in a disposable worktree; report observations | Commit, write canonical state, mark PASS/COMPLETE, push, merge, deploy |
| Orchestrator | Validate inputs, isolate Git, run named checks, write evidence/state, create verified local commits | Push, merge, deploy, or administer repository settings |
| Operator | Review evidence and authorize later shared actions | Treat provider prose as release evidence |

Completion is derived only when every story in the immutable PRD snapshot has orchestrator-authored PASS evidence and every evaluated Git tree equals its commit tree. Legacy `passes` fields and completion tokens are ignored.

## Requirements

- Python 3.9 or newer.
- Git with an existing target repository and configured commit identity.
- A running Docker daemon for the isolated Codex worker image.
- A host Codex authentication file at `$HOME/.codex/auth.json`, owned by the current user with no group or world permissions.
- Node.js 22+ only for host-side flowchart development; production checks use the validator image.

The runtime uses only the Python standard library. Provider subprocesses receive an allowlisted environment with a fixed trusted executable path, bounded output capture, and candidate-growth guards; no enabled adapter uses a permission/sandbox bypass flag. Candidate output is capped at 2,048 new entries, 64 MiB growth per file, and 512 MiB aggregate growth, with a hard container file-size limit plus continuous host-side enforcement. Codex runs in a pinned, read-only container that mounts only the disposable worktree and the read-only authentication file. Its inner Linux permission profile denies worker access to that file, removes worker capabilities, and blocks direct worker network access while the Codex process retains only the provider transport it needs.

Build the reviewed local provider and validator images before the first run:

````bash
cd /absolute/path/to/ralph-wiggum
docker build --pull --tag ralph-codex-provider:0.145.0 --build-arg CODEX_VERSION=0.145.0 docker/codex-provider
docker build --pull --tag ralph-validator:1.0.0 docker/validator
./scripts/run-codex-provider.sh --preflight
````

The preflight fails closed when Docker, either required image, secure authentication-file metadata, worktree readability, authentication-file denial, capability removal, or direct-network denial is not proved. Provider and validator tags resolve to immutable local image IDs before use; the provider repeats confinement against the exact ID used for each story. Required checks run against a read-only snapshot of the exact staged tree with no host home, source Git metadata, Docker socket, or network unless the reviewed check explicitly enables it. Only configured, non-overlapping `scratchMounts` are writable for dependency caches and build output; their source paths are revalidated before every bind and named containers are removed after every outcome. Frontend dependency lifecycle scripts are disabled with `npm ci --ignore-scripts`.

## Configure

Copy `prd.json.example` to an operator-owned location and edit the stories. Every story requires:

- `allowedPaths`: repository-relative patterns for candidate changes.
- `requiredChecks`: IDs from the reviewed `ralph.config.json` registry.
- `dependsOn`: optional existing story IDs without cycles.
- `requiresBrowser`: optional Boolean; true requires a passing `kind: browser` check or exact-tree external evidence.
- `references`: optional unique tracked text blobs from the frozen source tree; at most eight, 32 KiB each, 64 KiB total, and never protected, secret-like, symlinked, or untracked.

PRD-authored shell commands are not supported. Add or revise commands only in the operator-reviewed configuration as argv arrays with a pinned `containerImage`. Use `network: true` only when a check must fetch locked dependencies. Use `scratchMounts` only for reviewed cache/output directories, with `rw` limited to checks that must write them. Use `immutablePaths` to identify existing validator implementation files that a worker must not change; use a non-secret `environment` mapping for deterministic values such as `VITE_BASE_PATH`.

## Run

````bash
cd /absolute/path/to/ralph-wiggum
./ralph.sh \
  --repo /absolute/path/to/target-repository \
  --prd /absolute/path/to/prd.json \
  --config /absolute/path/to/ralph.config.json \
  --state-dir /absolute/path/to/ralph-state \
  --tool codex \
  --max-iterations 10 \
  --max-attempts 2 \
  --timeout-seconds 1800
````

`./ralph.sh 10` remains valid legacy syntax for the iteration ceiling. The default provider is containerized Codex. Host-native Codex, Claude, and Amp fail closed because their verified local modes do not provide the required read boundary; fixture-only `mock` remains available for tests.

Exit codes are `0` verified complete, `2` preflight rejection, `3` blocked/incomplete, and `4` terminal provider/validation/Git/cancellation failure. Resolved paths and the final run directory are printed.

## Evidence and recovery

Each run preserves immutable PRD and check-configuration snapshots with SHA-256 digests, atomic `run.json`, append-only redacted `events.jsonl`, and a detached runtime worktree. Dirty tracked or untracked content in the operator checkout never enters that worktree.

Provider metrics remain absent unless they are schema-checked observations. A successful attempt with no authorized change becomes `BLOCKED_NO_PROGRESS`. Every PASS binds its run/story/attempt, input digests, source SHA, paths, checks, output evidence, evaluated tree, commit, and equality proof.

The repository also exposes data-only governance helpers: outer schedulers may submit approved requests, query status/events, request approval, or cancel, but cannot write state, provide commands, mutate Git, access credentials, or release. Accuracy reports require independently labeled raw confusion counts; test success is never presented as a reliability percentage.

Failed, blocked, and cancelled runs are preserved. Inspect them and start a new run from the intended HEAD; never clean or reset user work as recovery. See [SPEC.md](SPEC.md) for contracts and [docs/RUNBOOK.md](docs/RUNBOOK.md) for exact operating steps.

## Validate this repository

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

CI runs these gates for pull requests and main pushes. Pages deployment is a separate workflow triggered only after successful main-branch CI. Actions are pinned to reviewed full commit SHAs with minimum workflow permissions.

## Flowchart

The interactive flowchart now shows the hardened authority path: preflight, immutable state, worktree isolation, bounded worker, scope enforcement, named checks, exact Git identity, evidence, and state-derived completion.

````bash
cd /absolute/path/to/ralph-wiggum/flowchart
npm ci
npm run dev
````

Set `VITE_BASE_PATH` for a repository-specific production path. The Pages workflow derives it from the repository name.

## Compatibility

`prompt.md` and `CLAUDE.md` remain only as legacy provider-boundary documentation. `AGENTS.md` is the canonical Codex instruction surface. The runtime does not read unbounded `progress.txt`; each worker receives only the current story's bounded brief.

Based on [Geoffrey Huntley's Ralph pattern](https://ghuntley.com/ralph/).
