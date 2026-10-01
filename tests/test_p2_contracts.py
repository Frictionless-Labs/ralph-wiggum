from __future__ import annotations

import importlib
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

from ralph_hardened.config import load_config
from ralph_hardened.errors import PreflightError
from ralph_hardened.models import ProviderOutcome, ProviderResult, RunOutcome
from ralph_hardened.orchestrator import Orchestrator
from ralph_hardened.prd import load_prd
import ralph_hardened.provider as provider_module

from tests.helpers import init_repo, prd_payload, run, write_config
from tests import test_orchestrator as orchestrator_tests


class P2ContractTests(unittest.TestCase):
    def test_selected_references_are_validated_and_loaded_into_the_worker_brief(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "repo"
            init_repo(repo)
            reference = repo / "docs" / "reference.md"
            reference.parent.mkdir()
            reference.write_text("bounded reference\n", encoding="utf-8")
            run("git", "add", "docs/reference.md", cwd=repo)
            run("git", "commit", "-m", "docs(fixture): add reference", cwd=repo)
            config_path = write_config(root / "config.json")
            payload = prd_payload(references=["docs/reference.md"])
            prd_path = root / "prd.json"
            prd_path.write_text(json.dumps(payload), encoding="utf-8")
            prd = load_prd(prd_path, load_config(config_path))
            self.assertEqual(
                getattr(prd.stories[0], "references", None), ("docs/reference.md",)
            )

            provider = orchestrator_tests.FixtureProvider("magic-only")
            options = orchestrator_tests.OrchestratorTests().make_options(
                root,
                repo,
                prd_path=prd_path,
                config_path=config_path,
            )
            prd_path.write_text(json.dumps(payload), encoding="utf-8")
            result = Orchestrator(options, provider).run()
            self.assertEqual(result.outcome, RunOutcome.BLOCKED)
            self.assertIn("docs/reference.md", provider.prompts[0])
            self.assertIn("bounded reference", provider.prompts[0])
            self.assertLessEqual(len(provider.prompts[0].encode("utf-8")), 131_072)

    def test_duplicate_or_unsafe_references_fail_before_provider_use(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            config = load_config(write_config(root / "config.json"))
            for references in (["docs/a.md", "docs/a.md"], ["../escape.md"], [".env"]):
                with self.subTest(references=references):
                    path = root / "prd.json"
                    path.write_text(
                        json.dumps(prd_payload(references=references)), encoding="utf-8"
                    )
                    with self.assertRaises(PreflightError):
                        load_prd(path, config)

    def test_missing_or_untracked_reference_fails_closed_before_provider_use(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "repo"
            init_repo(repo)
            untracked = repo / "untracked.md"
            untracked.write_text("not immutable\n", encoding="utf-8")
            provider = orchestrator_tests.FixtureProvider("write-app")
            options = orchestrator_tests.OrchestratorTests().make_options(root, repo)
            options.prd_path.write_text(
                json.dumps(prd_payload(references=["untracked.md"])), encoding="utf-8"
            )
            with self.assertRaisesRegex(PreflightError, "reference"):
                Orchestrator(options, provider).run()
            self.assertEqual(provider.calls, 0)

    def test_tracked_symlink_reference_fails_closed_before_provider_use(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "repo"
            init_repo(repo)
            os.symlink("app.txt", repo / "reference.md")
            run("git", "add", "reference.md", cwd=repo)
            run("git", "commit", "-m", "test(fixture): add symlink reference", cwd=repo)
            provider = orchestrator_tests.FixtureProvider("write-app")
            options = orchestrator_tests.OrchestratorTests().make_options(root, repo)
            options.prd_path.write_text(
                json.dumps(prd_payload(references=["reference.md"])), encoding="utf-8"
            )
            with self.assertRaisesRegex(PreflightError, "reference"):
                Orchestrator(options, provider).run()
            self.assertEqual(provider.calls, 0)

    def test_provider_metrics_accept_only_schema_checked_observations(self) -> None:
        normalize_provider_metrics = getattr(provider_module, "normalize_provider_metrics", None)
        self.assertTrue(callable(normalize_provider_metrics))
        result = ProviderResult(
            ProviderOutcome.SUCCESS,
            "ok",
            "",
            0,
            0.25,
            {
                "stdoutBytes": 3,
                "stdoutSha256": "a" * 64,
                "stdoutTruncated": False,
                "inputTokens": 12,
            },
        )
        self.assertEqual(normalize_provider_metrics(result)["inputTokens"], 12)
        absent = ProviderResult(ProviderOutcome.SUCCESS, "ok", "", 0, 0.25)
        self.assertNotIn("inputTokens", normalize_provider_metrics(absent))
        malformed = ProviderResult(
            ProviderOutcome.SUCCESS, "ok", "", 0, 0.25, {"inputTokens": "unknown"}
        )
        with self.assertRaises(ValueError):
            normalize_provider_metrics(malformed)
        unknown = ProviderResult(
            ProviderOutcome.SUCCESS, "ok", "", 0, 0.25, {"estimatedCost": 0}
        )
        with self.assertRaises(ValueError):
            normalize_provider_metrics(unknown)

    def test_pass_evidence_contains_complete_run_and_tree_identity(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "repo"
            base_sha = init_repo(repo)
            options = orchestrator_tests.OrchestratorTests().make_options(root, repo)
            result = Orchestrator(
                options, orchestrator_tests.FixtureProvider("write-app")
            ).run()
            self.assertEqual(result.outcome, RunOutcome.COMPLETE)
            state = json.loads((result.run_dir / "run.json").read_text(encoding="utf-8"))
            evidence = state["stories"]["US-001"]["evidence"]
            self.assertTrue(
                {
                    "runId",
                    "storyId",
                    "attempt",
                    "prdDigest",
                    "configDigest",
                    "baseSha",
                    "treeIdentityVerified",
                }
                <= evidence.keys()
            )
            self.assertEqual(evidence["runId"], state["runId"])
            self.assertEqual(evidence["storyId"], "US-001")
            self.assertEqual(evidence["attempt"], 1)
            self.assertEqual(evidence["prdDigest"], state["prdDigest"])
            self.assertEqual(evidence["configDigest"], state["configDigest"])
            self.assertEqual(evidence["baseSha"], base_sha)
            self.assertTrue(evidence["treeIdentityVerified"])
            self.assertEqual(evidence["evaluatedTree"], evidence["commitTree"])

    def test_no_progress_blocks_immediately_without_retry(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "repo"
            init_repo(repo)
            provider = orchestrator_tests.FixtureProvider("magic-only")
            options = orchestrator_tests.OrchestratorTests().make_options(
                root, repo, max_attempts=3
            )
            result = Orchestrator(options, provider).run()
            self.assertEqual(result.reason, "BLOCKED_NO_PROGRESS")
            self.assertEqual(provider.calls, 1)

    def test_outer_contract_rejects_control_plane_authority(self) -> None:
        self.assertIsNotNone(importlib.util.find_spec("ralph_hardened.governance"))
        governance = importlib.import_module("ralph_hardened.governance")
        command = governance.validate_outer_command(
            {
                "schemaVersion": 1,
                "action": "submit",
                "runRequest": {"requestId": "REQ-001", "approvedBy": "operator"},
            }
        )
        self.assertEqual(command.action, "submit")
        for action in ("status", "events", "cancel"):
            with self.subTest(action=action):
                allowed = governance.validate_outer_command(
                    {"schemaVersion": 1, "action": action, "runId": "RUN-001"}
                )
                self.assertEqual(allowed.action, action)
        approval = governance.validate_outer_command(
            {
                "schemaVersion": 1,
                "action": "request_approval",
                "runId": "RUN-001",
                "reason": "operator decision required",
            }
        )
        self.assertEqual(approval.action, "request_approval")
        for denied in ("write_state", "pass", "complete", "shell", "commit", "merge", "deploy"):
            with self.subTest(action=denied), self.assertRaises(ValueError):
                governance.validate_outer_command({"schemaVersion": 1, "action": denied})
        with self.assertRaises(ValueError):
            governance.validate_outer_command(
                {
                    "schemaVersion": 1,
                    "action": "submit",
                    "runRequest": {
                        "requestId": "REQ-001",
                        "approvedBy": "operator",
                        "command": "git commit --all",
                    },
                }
            )
        for smuggled in (
            {"schemaVersion": 1, "action": "events", "runId": "RUN-001", "reason": "x"},
            {
                "schemaVersion": 1,
                "action": "cancel",
                "runId": "RUN-001",
                "runRequest": {"requestId": "REQ-001", "approvedBy": "operator"},
            },
            {
                "schemaVersion": 1,
                "action": "submit",
                "runId": "RUN-001",
                "runRequest": {"requestId": "REQ-001", "approvedBy": "operator"},
            },
        ):
            with self.subTest(smuggled=smuggled), self.assertRaises(ValueError):
                governance.validate_outer_command(smuggled)

    def test_accuracy_report_requires_independent_labeled_raw_counts(self) -> None:
        self.assertIsNotNone(importlib.util.find_spec("ralph_hardened.governance"))
        governance = importlib.import_module("ralph_hardened.governance")
        with self.assertRaises(ValueError):
            governance.build_accuracy_report(
                {"truePositive": 1, "trueNegative": 1, "falsePositive": 0, "falseNegative": 0}
            )
        with self.assertRaises(ValueError):
            governance.build_accuracy_report(
                {
                    "labelSource": "human-review",
                    "sampleCount": 2,
                    "truePositive": 1,
                    "trueNegative": 1,
                    "falsePositive": 0,
                    "falseNegative": 0,
                    "claimedAccuracy": 1.0,
                }
            )
        with self.assertRaises(ValueError):
            governance.build_accuracy_report(
                {
                    "labelSource": "human-review",
                    "sampleCount": 3,
                    "truePositive": 1,
                    "trueNegative": 1,
                    "falsePositive": 0,
                    "falseNegative": 0,
                }
            )
        report = governance.build_accuracy_report(
            {
                "labelSource": "human-review",
                "sampleCount": 4,
                "truePositive": 1,
                "trueNegative": 2,
                "falsePositive": 0,
                "falseNegative": 1,
            }
        )
        self.assertEqual(report["counts"]["sampleCount"], 4)
        self.assertEqual(report["metrics"]["accuracy"], 0.75)
        undefined = governance.build_accuracy_report(
            {
                "labelSource": "human-review",
                "sampleCount": 2,
                "truePositive": 0,
                "trueNegative": 2,
                "falsePositive": 0,
                "falseNegative": 0,
            }
        )
        self.assertIsNone(undefined["metrics"]["precision"])
        self.assertIsNone(undefined["metrics"]["recall"])


if __name__ == "__main__":
    unittest.main()
