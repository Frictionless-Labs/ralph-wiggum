from __future__ import annotations

import signal
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from ralph_hardened.checks import CheckRunner
from ralph_hardened.models import CheckDefinition
from tests.helpers import init_repo, run


class CheckRunnerTests(unittest.TestCase):
    def test_container_check_mounts_evaluated_snapshot_read_only(self) -> None:
        definition = CheckDefinition(
            "container",
            ("true",),
            2,
            container_image="sha256:" + "a" * 64,
            scratch_mounts={"build/cache": "rw"},
        )
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            candidate = root / "candidate"
            scratch = root / "scratch"
            (scratch / "build" / "cache").mkdir(parents=True)
            argv, _ = CheckRunner()._argv(definition, candidate, False, scratch)
        self.assertIn(f"{candidate}:/workspace:ro", argv)
        self.assertIn(f"{scratch.resolve()}/build/cache:/workspace/build/cache:rw", argv)
        self.assertNotIn(f"{candidate}:/workspace:rw", argv)

    def test_snapshot_materializes_only_the_staged_tree(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "repo"
            init_repo(repo)
            (repo / "app.txt").write_text("staged\n", encoding="utf-8")
            run("git", "add", "app.txt", cwd=repo)
            (repo / "app.txt").write_text("unstaged\n", encoding="utf-8")
            definition = CheckDefinition(
                "container",
                ("true",),
                2,
                container_image="sha256:" + "a" * 64,
                scratch_mounts={"build/cache": "rw"},
            )
            temporary_root = root / "validation"
            temporary_root.mkdir()
            snapshot, scratch = CheckRunner()._prepare_snapshot(
                (definition,), repo, temporary_root
            )
            self.assertEqual((snapshot / "app.txt").read_text(encoding="utf-8"), "staged\n")
            self.assertTrue((snapshot / "build" / "cache").is_dir())
            self.assertTrue((scratch / "build" / "cache").is_dir())

    def test_scratch_mount_cannot_hide_staged_content(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "repo"
            init_repo(repo)
            definition = CheckDefinition(
                "container",
                ("true",),
                2,
                container_image="sha256:" + "a" * 64,
                scratch_mounts={".": "rw"},
            )
            temporary_root = root / "validation"
            temporary_root.mkdir()
            with self.assertRaisesRegex(ValueError, "hide staged content"):
                CheckRunner()._prepare_snapshot((definition,), repo, temporary_root)

    def test_overlapping_scratch_mounts_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "repo"
            init_repo(repo)
            definitions = (
                CheckDefinition(
                    "first", ("true",), 2, container_image="sha256:" + "a" * 64,
                    scratch_mounts={"cache": "rw"},
                ),
                CheckDefinition(
                    "second", ("true",), 2, container_image="sha256:" + "a" * 64,
                    scratch_mounts={"cache/subdir": "ro"},
                ),
            )
            temporary_root = root / "validation"
            temporary_root.mkdir()
            with self.assertRaisesRegex(ValueError, "overlapping scratch"):
                CheckRunner()._prepare_snapshot(definitions, repo, temporary_root)

    def test_scratch_source_symlink_substitution_is_rejected_at_execution(self) -> None:
        definition = CheckDefinition(
            "container", ("true",), 2, container_image="sha256:" + "a" * 64,
            scratch_mounts={"cache": "rw"},
        )
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            candidate = root / "candidate"
            candidate.mkdir()
            scratch = root / "scratch"
            scratch.mkdir()
            target = root / "outside"
            target.mkdir()
            (scratch / "cache").symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symlink"):
                CheckRunner()._argv(definition, candidate, False, scratch)

    def test_unconfined_check_fails_closed(self) -> None:
        definition = CheckDefinition("unsafe", (sys.executable, "-c", "pass"), 1)
        with tempfile.TemporaryDirectory() as raw:
            result = CheckRunner().run(definition, Path(raw))
        self.assertFalse(result.passed)
        self.assertEqual(result.outcome, "UNAVAILABLE")
        self.assertIn("containerImage", result.stderr)

    def test_interrupt_terminates_check_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            marker = Path(raw) / "child-finished"
            script = (
                "import time; from pathlib import Path; time.sleep(0.5); "
                f"Path({str(marker)!r}).write_text('alive')"
            )
            definition = CheckDefinition("fixture", (sys.executable, "-c", script), 2)
            previous = signal.getsignal(signal.SIGALRM)

            def interrupt(*_: object) -> None:
                raise KeyboardInterrupt

            signal.signal(signal.SIGALRM, interrupt)
            signal.setitimer(signal.ITIMER_REAL, 0.05)
            try:
                with self.assertRaises(KeyboardInterrupt):
                    CheckRunner().run(definition, Path(raw), allow_host=True)
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)
                signal.signal(signal.SIGALRM, previous)
            time.sleep(0.6)
            self.assertFalse(marker.exists())

    def test_output_capture_is_bounded(self) -> None:
        definition = CheckDefinition(
            "fixture", (sys.executable, "-c", "print('x' * 100000)"), 2
        )
        with tempfile.TemporaryDirectory() as raw:
            result = CheckRunner().run(definition, Path(raw), allow_host=True)
        self.assertTrue(result.passed)
        self.assertLessEqual(len(result.stdout.encode("utf-8")), 65_536)
        self.assertGreater(result.stdout_bytes, 65_536)
        self.assertTrue(result.stdout_truncated)
        self.assertEqual(len(result.stdout_sha256), 64)

    def test_container_cleanup_runs_after_docker_client_output_failure(self) -> None:
        definition = CheckDefinition(
            "container", ("true",), 2, container_image="sha256:" + "a" * 64
        )

        class FailedDockerClient:
            returncode = -25

            def communicate(self, timeout: float) -> tuple[None, None]:
                return None, None

        with tempfile.TemporaryDirectory() as raw, mock.patch(
            "ralph_hardened.checks.subprocess.Popen", return_value=FailedDockerClient()
        ), mock.patch.object(CheckRunner, "_remove_container", return_value=True) as cleanup:
            result = CheckRunner()._run(
                definition, Path(raw), allow_host=False, scratch_root=Path(raw)
            )
        self.assertFalse(result.passed)
        self.assertEqual(result.outcome, "FAIL")
        cleanup.assert_called_once()


if __name__ == "__main__":
    unittest.main()
