from __future__ import annotations

import json
import math
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from ralph_hardened.models import ProviderOutcome, ProviderResult, RunOutcome
from ralph_hardened.errors import GitPolicyError, PreflightError
from ralph_hardened.orchestrator import (
    Orchestrator,
    RunOptions,
    _browser_evidence_for_story,
    _check_evidence,
)
from ralph_hardened.provider import CommandProvider, Provider

from tests.helpers import init_repo, run, write_config, write_prd


class FixtureProvider(Provider):
    name = "fixture"
    allows_host_checks = True

    def __init__(self, behavior: str) -> None:
        self.behavior = behavior
        self.calls = 0
        self.prompts: list[str] = []

    def run(self, prompt: str, cwd: Path, timeout_seconds: float) -> ProviderResult:
        self.calls += 1
        self.prompts.append(prompt)
        if self.behavior == "nonzero":
            return ProviderResult(ProviderOutcome.NONZERO, "", "auth failed", 9, 0.01)
        if self.behavior == "empty":
            return ProviderResult(ProviderOutcome.EMPTY_OUTPUT, "", "", 0, 0.01)
        if self.behavior == "timeout":
            return ProviderResult(ProviderOutcome.TIMEOUT, "", "timed out", None, 0.01)
        if self.behavior == "rate-limit":
            return ProviderResult(ProviderOutcome.RATE_LIMIT, "", "rate limited", 1, 0.01)
        if self.behavior == "timeout-with-edit":
            (cwd / "app.txt").write_text("partial timeout output\n", encoding="utf-8")
            return ProviderResult(ProviderOutcome.TIMEOUT, "", "timed out", None, 0.01)
        if self.behavior == "rate-then-write":
            if self.calls == 1:
                return ProviderResult(ProviderOutcome.RATE_LIMIT, "", "rate limited", 1, 0.01)
            (cwd / "app.txt").write_text("verified\n", encoding="utf-8")
            return ProviderResult(ProviderOutcome.SUCCESS, "implemented", "", 0, 0.01)
        if self.behavior == "write-sequential":
            target = "app.txt" if self.calls == 1 else "second.txt"
            (cwd / target).write_text(f"verified {self.calls}\n", encoding="utf-8")
            return ProviderResult(ProviderOutcome.SUCCESS, "implemented", "", 0, 0.01)
        if self.behavior == "magic-only":
            return ProviderResult(ProviderOutcome.SUCCESS, "<promise>COMPLETE</promise>", "", 0, 0.01)
        if self.behavior == "write-app":
            (cwd / "app.txt").write_text("verified\n", encoding="utf-8")
            return ProviderResult(ProviderOutcome.SUCCESS, "implemented", "", 0, 0.01)
        if self.behavior == "commit-app":
            (cwd / "app.txt").write_text("provider commit\n", encoding="utf-8")
            run("git", "add", "app.txt", cwd=cwd)
            run("git", "commit", "-m", "feat(fixture): bypass orchestrator", cwd=cwd)
            return ProviderResult(ProviderOutcome.SUCCESS, "committed", "", 0, 0.01)
        if self.behavior == "interrupt":
            raise KeyboardInterrupt
        if self.behavior == "malformed":
            return None  # type: ignore[return-value]
        raise AssertionError(self.behavior)


class OrchestratorTests(unittest.TestCase):
    def make_options(self, root: Path, repo: Path, **overrides: object) -> RunOptions:
        values: dict[str, object] = {
            "repo": repo,
            "prd_path": write_prd(root / "prd.json"),
            "config_path": write_config(root / "config.json"),
            "state_dir": root / "state",
            "max_iterations": 1,
            "max_attempts": 1,
            "timeout_seconds": 1.0,
            "browser_evidence": None,
        }
        values.update(overrides)
        return RunOptions(**values)  # type: ignore[arg-type]

    def test_magic_completion_token_has_no_authority(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "repo"
            init_repo(repo)
            provider = FixtureProvider("magic-only")
            result = Orchestrator(self.make_options(root, repo), provider).run()
            self.assertNotEqual(result.outcome, RunOutcome.COMPLETE)
            self.assertEqual(result.outcome, RunOutcome.BLOCKED)
            self.assertEqual(provider.calls, 1)

    def test_invalid_prd_invokes_zero_providers(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "repo"
            init_repo(repo)
            provider = FixtureProvider("write-app")
            options = self.make_options(root, repo)
            options.prd_path.write_text("{", encoding="utf-8")
            with self.assertRaisesRegex(Exception, "invalid JSON"):
                Orchestrator(options, provider).run()
            self.assertEqual(provider.calls, 0)

    def test_unavailable_check_binary_invokes_zero_providers(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "repo"
            init_repo(repo)
            provider = FixtureProvider("write-app")
            options = self.make_options(root, repo)
            write_config(options.config_path, ["ralph-command-that-does-not-exist"])
            with self.assertRaisesRegex(Exception, "check executable unavailable"):
                Orchestrator(options, provider).run()
            self.assertEqual(provider.calls, 0)

    def test_production_provider_rejects_unconfined_host_check(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "repo"
            init_repo(repo)
            provider = CommandProvider(
                "production-fixture",
                [sys.executable, "-c", "print('must not run')"],
            )
            with self.assertRaisesRegex(Exception, "containerImage confinement"):
                Orchestrator(self.make_options(root, repo), provider).run()

    def test_failed_provider_preflight_creates_no_run(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "repo"
            init_repo(repo)
            marker = root / "provider-called"
            provider = CommandProvider(
                "container-fixture",
                [
                    sys.executable,
                    "-c",
                    f"from pathlib import Path; Path({str(marker)!r}).touch()",
                ],
                preflight_argv=[sys.executable, "-c", "raise SystemExit(12)"],
                allows_host_checks=True,
            )
            options = self.make_options(root, repo)
            with self.assertRaisesRegex(Exception, "provider preflight failed with exit 12"):
                Orchestrator(options, provider).run()
            self.assertFalse(marker.exists())
            self.assertFalse(options.state_dir.exists())

    def test_untracked_relative_check_is_not_accepted_from_live_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "repo"
            init_repo(repo)
            check = repo / "untracked-check.sh"
            check.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            check.chmod(0o700)
            provider = FixtureProvider("write-app")
            options = self.make_options(root, repo)
            write_config(options.config_path, ["./untracked-check.sh"])
            with self.assertRaisesRegex(Exception, "check executable unavailable"):
                Orchestrator(options, provider).run()
            self.assertEqual(provider.calls, 0)

    def test_state_directory_inside_source_repo_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "repo"
            init_repo(repo)
            provider = FixtureProvider("write-app")
            options = self.make_options(root, repo, state_dir=repo / ".ralph-state")
            with self.assertRaisesRegex(Exception, "state directory must be outside"):
                Orchestrator(options, provider).run()
            self.assertEqual(provider.calls, 0)

    def test_non_finite_provider_timeout_fails_before_state_or_provider(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "repo"
            init_repo(repo)
            for timeout in (math.nan, math.inf, -math.inf):
                with self.subTest(timeout=timeout):
                    provider = FixtureProvider("write-app")
                    options = self.make_options(root, repo, timeout_seconds=timeout)
                    with self.assertRaisesRegex(PreflightError, "provider timeout"):
                        Orchestrator(options, provider).run()
                    self.assertEqual(provider.calls, 0)

    def test_provider_failure_cannot_pass(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "repo"
            head = init_repo(repo)
            result = Orchestrator(self.make_options(root, repo), FixtureProvider("nonzero")).run()
            self.assertEqual(result.outcome, RunOutcome.FAILED)
            self.assertEqual(run("git", "rev-parse", "HEAD", cwd=repo).stdout.strip(), head)

    def test_empty_provider_output_cannot_pass(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "repo"
            init_repo(repo)
            provider = FixtureProvider("empty")
            result = Orchestrator(self.make_options(root, repo), provider).run()
            self.assertEqual(result.outcome, RunOutcome.FAILED)
            self.assertEqual(result.reason, "PROVIDER_EMPTY_OUTPUT")
            self.assertEqual(provider.calls, 1)

    def test_timeout_and_rate_limit_stop_at_attempt_ceiling(self) -> None:
        for behavior, reason in (
            ("timeout", "PROVIDER_TIMEOUT"),
            ("rate-limit", "PROVIDER_RATE_LIMIT"),
        ):
            with self.subTest(behavior=behavior), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                repo = root / "repo"
                init_repo(repo)
                provider = FixtureProvider(behavior)
                options = self.make_options(root, repo, max_attempts=2)
                result = Orchestrator(options, provider).run()
                self.assertEqual(result.outcome, RunOutcome.FAILED)
                self.assertEqual(result.reason, reason)
                self.assertEqual(provider.calls, 2)

    def test_failed_attempt_edits_are_not_inherited_by_retry(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "repo"
            init_repo(repo)
            provider = FixtureProvider("timeout-with-edit")
            options = self.make_options(root, repo, max_attempts=2)
            result = Orchestrator(options, provider).run()
            self.assertEqual(result.outcome, RunOutcome.FAILED)
            self.assertEqual(result.reason, "PROVIDER_RESIDUAL_CHANGES")
            self.assertEqual(provider.calls, 1)

    def test_clean_retry_may_complete_after_rate_limit(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "repo"
            init_repo(repo)
            provider = FixtureProvider("rate-then-write")
            options = self.make_options(root, repo, max_attempts=2)
            result = Orchestrator(options, provider).run()
            self.assertEqual(result.outcome, RunOutcome.COMPLETE)
            self.assertEqual(provider.calls, 2)

    def test_worker_authored_commit_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "repo"
            init_repo(repo)
            result = Orchestrator(self.make_options(root, repo), FixtureProvider("commit-app")).run()
            self.assertEqual(result.outcome, RunOutcome.FAILED)
            self.assertEqual(result.reason, "WORKER_MUTATED_HEAD")
            state = json.loads((result.run_dir / "run.json").read_text(encoding="utf-8"))
            self.assertEqual(state["stories"]["US-001"]["status"], "FAIL")

    def test_failed_required_check_blocks_pass_and_commit(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "repo"
            head = init_repo(repo)
            options = self.make_options(root, repo)
            write_config(options.config_path, ["python3", "-c", "raise SystemExit(12)"])
            result = Orchestrator(options, FixtureProvider("write-app")).run()
            self.assertEqual(result.outcome, RunOutcome.FAILED)
            self.assertEqual(run("git", "rev-parse", "HEAD", cwd=repo).stdout.strip(), head)

    def test_required_browser_evidence_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "repo"
            init_repo(repo)
            options = self.make_options(root, repo)
            write_prd(options.prd_path, requiresBrowser=True)
            result = Orchestrator(options, FixtureProvider("write-app")).run()
            self.assertEqual(result.outcome, RunOutcome.BLOCKED)
            self.assertEqual(result.reason, "BLOCKED_VERIFIER")

    def test_browser_check_verifies_current_tree_synchronously(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "repo"
            init_repo(repo)
            options = self.make_options(root, repo)
            write_prd(options.prd_path, requiresBrowser=True)
            payload = json.loads(options.config_path.read_text(encoding="utf-8"))
            payload["checks"]["required"]["kind"] = "browser"
            options.config_path.write_text(json.dumps(payload), encoding="utf-8")
            result = Orchestrator(options, FixtureProvider("write-app")).run()
            self.assertEqual(result.outcome, RunOutcome.COMPLETE)
            state = json.loads((result.run_dir / "run.json").read_text(encoding="utf-8"))
            browser = state["stories"]["US-001"]["evidence"]["browser"]
            self.assertEqual(browser["evaluatedTree"], state["stories"]["US-001"]["evidence"]["commitTree"])
            self.assertEqual(browser["verifier"], "required")

    def test_browser_evidence_is_per_story_and_tree_bound(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "browser.json"
            path.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "evidence": [
                            {"storyId": "US-001", "status": "PASS", "evaluatedTree": "tree-1", "verifier": "playwright"},
                            {"storyId": "US-002", "status": "PASS", "evaluatedTree": "tree-2", "verifier": "playwright"}
                        ]
                    }
                ),
                encoding="utf-8",
            )
            self.assertIsNotNone(_browser_evidence_for_story(path, "US-001", "tree-1"))
            self.assertIsNotNone(_browser_evidence_for_story(path, "US-002", "tree-2"))
            self.assertIsNone(_browser_evidence_for_story(path, "US-001", "stale-tree"))

    def test_check_evidence_persists_bounded_redacted_diagnostic_tails(self) -> None:
        from ralph_hardened.models import CheckResult

        result = CheckResult(
            "fixture",
            False,
            1,
            "api_key=sk-syntheticsecret123456 detail",
            "Authorization: Bearer synthetic-token-value",
            0.1,
            "FAIL",
        )
        evidence = _check_evidence((result,))[0]
        self.assertIn("stdoutTail", evidence)
        self.assertIn("stderrTail", evidence)
        self.assertNotIn("syntheticsecret", evidence["stdoutTail"])
        self.assertNotIn("synthetic-token", evidence["stderrTail"])
        self.assertIn("[REDACTED]", evidence["stdoutTail"])

    def test_interrupted_execution_is_recorded_as_cancelled(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "repo"
            init_repo(repo)
            result = Orchestrator(self.make_options(root, repo), FixtureProvider("interrupt")).run()
            self.assertEqual(result.outcome, RunOutcome.CANCELLED)
            state = json.loads((result.run_dir / "run.json").read_text(encoding="utf-8"))
            self.assertEqual(state["status"], "CANCELLED")

    def test_malformed_provider_result_is_terminal_and_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "repo"
            init_repo(repo)
            result = Orchestrator(self.make_options(root, repo), FixtureProvider("malformed")).run()
            self.assertEqual(result.outcome, RunOutcome.FAILED)
            self.assertEqual(result.reason, "MALFORMED_PROVIDER_RESULT")

    def test_iteration_ceiling_is_explicit_block(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "repo"
            init_repo(repo)
            options = self.make_options(root, repo, max_iterations=1)
            payload = json.loads(options.prd_path.read_text(encoding="utf-8"))
            second = dict(payload["userStories"][0])
            second.update({"id": "US-002", "title": "Second story", "priority": 2})
            payload["userStories"].append(second)
            options.prd_path.write_text(json.dumps(payload), encoding="utf-8")
            result = Orchestrator(options, FixtureProvider("write-app")).run()
            self.assertEqual(result.outcome, RunOutcome.BLOCKED)
            self.assertEqual(result.reason, "BLOCKED_BUDGET")

    def test_check_index_mutation_is_rejected_before_commit(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "repo"
            source_head = init_repo(repo)
            options = self.make_options(root, repo)
            write_config(options.config_path, ["git", "rm", "--cached", "app.txt"])
            result = Orchestrator(options, FixtureProvider("write-app")).run()
            self.assertEqual(result.outcome, RunOutcome.FAILED)
            self.assertEqual(result.reason, "VALIDATOR_MUTATED_INDEX")
            state = json.loads((result.run_dir / "run.json").read_text(encoding="utf-8"))
            runtime_head = run(
                "git", "rev-parse", "HEAD", cwd=Path(state["worktreePath"])
            ).stdout.strip()
            self.assertEqual(runtime_head, source_head)

    def test_check_out_of_scope_mutation_finalizes_story_failure(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "repo"
            init_repo(repo)
            options = self.make_options(root, repo)
            write_config(
                options.config_path,
                ["python3", "-c", "from pathlib import Path; Path('outside.txt').write_text('bad')"],
            )
            result = Orchestrator(options, FixtureProvider("write-app")).run()
            self.assertEqual(result.outcome, RunOutcome.FAILED)
            state = json.loads((result.run_dir / "run.json").read_text(encoding="utf-8"))
            self.assertEqual(state["stories"]["US-001"]["status"], "FAIL")

    def test_worktree_setup_failure_is_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "repo"
            init_repo(repo)
            with mock.patch(
                "ralph_hardened.orchestrator.GitWorkspace.create",
                side_effect=GitPolicyError("fixture worktree failure"),
            ):
                result = Orchestrator(self.make_options(root, repo), FixtureProvider("write-app")).run()
            self.assertEqual(result.outcome, RunOutcome.FAILED)
            state = json.loads((result.run_dir / "run.json").read_text(encoding="utf-8"))
            self.assertEqual(state["status"], "FAILED")
            self.assertEqual(state["reason"], "WORKTREE_SETUP_FAILED")

    def test_worktree_setup_os_error_is_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "repo"
            init_repo(repo)
            options = self.make_options(root, repo)
            options.state_dir.mkdir()
            (options.state_dir / "worktrees").write_text("not a directory", encoding="utf-8")
            result = Orchestrator(options, FixtureProvider("write-app")).run()
            self.assertEqual(result.outcome, RunOutcome.FAILED)
            self.assertEqual(result.reason, "WORKTREE_SETUP_FAILED")
            state = json.loads((result.run_dir / "run.json").read_text(encoding="utf-8"))
            self.assertEqual(state["status"], "FAILED")
            self.assertEqual(state["reason"], "WORKTREE_SETUP_FAILED")

    def test_worker_prompt_is_bounded_to_current_story(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "repo"
            init_repo(repo)
            provider = FixtureProvider("magic-only")
            Orchestrator(self.make_options(root, repo), provider).run()
            prompt = provider.prompts[0]
            self.assertIn("US-001", prompt)
            self.assertNotIn("events.jsonl", prompt)
            self.assertNotIn("progress.txt", prompt)
            self.assertLess(len(prompt), 4096)

    def test_verified_change_completes_with_tree_bound_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "repo"
            init_repo(repo)
            result = Orchestrator(self.make_options(root, repo), FixtureProvider("write-app")).run()
            self.assertEqual(result.outcome, RunOutcome.COMPLETE)
            state = json.loads((result.run_dir / "run.json").read_text(encoding="utf-8"))
            story = state["stories"]["US-001"]
            self.assertEqual(story["status"], "PASS")
            self.assertEqual(story["evidence"]["evaluatedTree"], story["evidence"]["commitTree"])
            self.assertIn("stdoutSha256", story["evidence"]["checks"][0])
            self.assertIn("stderrSha256", story["evidence"]["checks"][0])
            self.assertEqual(state["status"], "COMPLETE")

    def test_tree_identity_mismatch_is_terminal(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "repo"
            init_repo(repo)
            with mock.patch(
                "ralph_hardened.orchestrator.GitWorkspace.commit_tree",
                return_value="0" * 40,
            ):
                result = Orchestrator(
                    self.make_options(root, repo), FixtureProvider("write-app")
                ).run()
            self.assertEqual(result.outcome, RunOutcome.FAILED)
            self.assertEqual(result.reason, "TREE_IDENTITY_MISMATCH")

    def test_each_story_evidence_uses_its_actual_commit_parent_as_base(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "repo"
            init_repo(repo)
            options = self.make_options(root, repo, max_iterations=2)
            payload = json.loads(options.prd_path.read_text(encoding="utf-8"))
            second = dict(payload["userStories"][0])
            second.update(
                {
                    "id": "US-002",
                    "title": "Second story",
                    "priority": 2,
                    "allowedPaths": ["second.txt"],
                    "dependsOn": ["US-001"],
                }
            )
            payload["userStories"].append(second)
            options.prd_path.write_text(json.dumps(payload), encoding="utf-8")
            result = Orchestrator(options, FixtureProvider("write-sequential")).run()
            self.assertEqual(result.outcome, RunOutcome.COMPLETE)
            state = json.loads((result.run_dir / "run.json").read_text(encoding="utf-8"))
            first = state["stories"]["US-001"]["evidence"]
            second_evidence = state["stories"]["US-002"]["evidence"]
            self.assertEqual(second_evidence["baseSha"], first["commit"])
            actual_parent = run(
                "git",
                "rev-parse",
                f"{second_evidence['commit']}^",
                cwd=Path(state["worktreePath"]),
            ).stdout.strip()
            self.assertEqual(second_evidence["baseSha"], actual_parent)


if __name__ == "__main__":
    unittest.main()
