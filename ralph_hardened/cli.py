from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Optional, Sequence

from .errors import PreflightError
from .models import RunOutcome
from .orchestrator import Orchestrator, RunOptions
from .provider import CommandProvider


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ralph",
        description="Run one-story fresh-context iterations behind deterministic safety gates.",
    )
    parser.add_argument("legacy_max_iterations", nargs="?", type=int)
    parser.add_argument("--repo", type=Path)
    parser.add_argument("--prd", type=Path)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--tool", default="codex")
    parser.add_argument("--max-iterations", type=int)
    parser.add_argument("--max-attempts", type=int, default=2)
    parser.add_argument("--timeout-seconds", type=float, default=1800)
    parser.add_argument("--browser-evidence", type=Path)
    parser.add_argument("--resume-run", type=Path)
    return parser


def provider_from_name(name: str) -> CommandProvider:
    if name == "codex":
        runner = Path(__file__).resolve().parent.parent / "scripts" / "run-codex-provider.sh"
        return CommandProvider(
            "codex-container",
            (str(runner),),
            preflight_argv=(str(runner), "--preflight"),
        )
    if name == "claude":
        raise PreflightError(
            "Claude adapter lacks a verified filesystem confinement boundary and fails closed"
        )
    if name == "amp":
        raise PreflightError("Amp adapter is not verified in this environment and fails closed")
    if name == "mock":
        return CommandProvider(
            "mock",
            (sys.executable, "-c", "print('mock provider produced no changes')"),
            allows_host_checks=True,
        )
    raise PreflightError(f"unsupported provider: {name}")


def _resolve_paths(arguments: argparse.Namespace) -> tuple[Path, Path, Path, Path]:
    package_root = Path(__file__).resolve().parent.parent
    repo = (arguments.repo or package_root).expanduser().resolve()
    prd = (arguments.prd or repo / "prd.json").expanduser().resolve()
    config = (arguments.config or repo / "ralph.config.json").expanduser().resolve()
    if arguments.state_dir is not None:
        state = arguments.state_dir
    elif arguments.resume_run is not None:
        state = arguments.resume_run.expanduser().absolute().parent.parent
    else:
        state = repo.parent / ".ralph-state" / repo.name
    state = state.expanduser()
    state = Path(os.path.abspath(state))
    return repo, prd, config, state


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    repo, prd, config, state = _resolve_paths(arguments)
    if arguments.max_iterations is not None:
        max_iterations = arguments.max_iterations
    elif arguments.legacy_max_iterations is not None:
        max_iterations = arguments.legacy_max_iterations
    else:
        max_iterations = 10
    print(f"repo={repo}")
    print(f"prd={prd}")
    print(f"config={config}")
    print(f"stateDir={state}")
    print(f"provider={arguments.tool}")
    print(f"maxIterations={max_iterations}")
    try:
        provider = provider_from_name(arguments.tool)
        result = Orchestrator(
            RunOptions(
                repo=repo,
                prd_path=prd,
                config_path=config,
                state_dir=state,
                max_iterations=max_iterations,
                max_attempts=arguments.max_attempts,
                timeout_seconds=arguments.timeout_seconds,
                browser_evidence=arguments.browser_evidence,
                resume_run=arguments.resume_run,
            ),
            provider,
        ).run()
    except PreflightError as exc:
        print(f"PRECHECK_REJECTED: {exc}", file=sys.stderr)
        return 2
    print(f"runDir={result.run_dir}")
    print(f"outcome={result.outcome.value}")
    print(f"reason={result.reason}")
    if result.outcome == RunOutcome.COMPLETE:
        return 0
    if result.outcome == RunOutcome.BLOCKED:
        return 3
    return 4
