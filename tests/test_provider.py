from __future__ import annotations

import os
import signal
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from ralph_hardened.models import ProviderOutcome
from ralph_hardened.provider import CommandProvider, build_safe_env


class ProviderTests(unittest.TestCase):
    def test_nonzero_exit_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            provider = CommandProvider("test", [sys.executable, "-c", "raise SystemExit(7)"])
            result = provider.run("prompt", Path(raw), timeout_seconds=2)
            self.assertEqual(result.outcome, ProviderOutcome.NONZERO)
            self.assertEqual(result.exit_code, 7)

    def test_empty_output_is_failure(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            provider = CommandProvider("test", [sys.executable, "-c", "pass"])
            result = provider.run("prompt", Path(raw), timeout_seconds=2)
            self.assertEqual(result.outcome, ProviderOutcome.EMPTY_OUTPUT)

    def test_output_capture_retains_bounded_tail_and_full_digest_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            provider = CommandProvider(
                "test", [sys.executable, "-c", "print('x' * 100000)"]
            )
            result = provider.run("prompt", Path(raw), timeout_seconds=2)
            self.assertEqual(result.outcome, ProviderOutcome.SUCCESS)
            self.assertLessEqual(len(result.stdout.encode("utf-8")), 65_536)
            self.assertGreater(result.metrics["stdoutBytes"], 65_536)
            self.assertTrue(result.metrics["stdoutTruncated"])
            self.assertEqual(len(result.metrics["stdoutSha256"]), 64)

    def test_timeout_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            provider = CommandProvider("test", [sys.executable, "-c", "import time; time.sleep(5)"])
            started = time.monotonic()
            result = provider.run("prompt", Path(raw), timeout_seconds=0.2)
            self.assertEqual(result.outcome, ProviderOutcome.TIMEOUT)
            self.assertLess(time.monotonic() - started, 2)

    def test_workspace_growth_limit_terminates_provider(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            provider = CommandProvider(
                "test",
                [
                    sys.executable,
                    "-c",
                    "from pathlib import Path; Path('large.bin').write_bytes(b'x' * 4096)",
                ],
            )
            with mock.patch("ralph_hardened.limits.MAX_FILE_GROWTH_BYTES", 128):
                result = provider.run("prompt", Path(raw), timeout_seconds=2)
            self.assertEqual(result.outcome, ProviderOutcome.RESOURCE_LIMIT)
            self.assertIn("file growth limit exceeded", result.stderr)
            self.assertIn("resourceLimit", result.metrics)

    def test_timeout_pipe_drain_is_bounded_for_detached_descendant(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            script = (
                "import subprocess,sys,time; "
                "subprocess.Popen([sys.executable,'-c','import time; time.sleep(5)'], "
                "start_new_session=True); time.sleep(5)"
            )
            provider = CommandProvider("test", [sys.executable, "-c", script])
            started = time.monotonic()
            result = provider.run("prompt", Path(raw), timeout_seconds=0.1)
            self.assertEqual(result.outcome, ProviderOutcome.TIMEOUT)
            self.assertLess(time.monotonic() - started, 3.5)

    def test_interrupt_terminates_provider_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            marker = Path(raw) / "child-finished"
            script = (
                "import time; from pathlib import Path; time.sleep(0.5); "
                f"Path({str(marker)!r}).write_text('alive')"
            )
            provider = CommandProvider("test", [sys.executable, "-c", script])
            previous = signal.getsignal(signal.SIGALRM)

            def interrupt(*_: object) -> None:
                raise KeyboardInterrupt

            signal.signal(signal.SIGALRM, interrupt)
            signal.setitimer(signal.ITIMER_REAL, 0.05)
            try:
                with self.assertRaises(KeyboardInterrupt):
                    provider.run("prompt", Path(raw), timeout_seconds=2)
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)
                signal.signal(signal.SIGALRM, previous)
            time.sleep(0.6)
            self.assertFalse(marker.exists())

    def test_environment_is_allowlisted(self) -> None:
        original = os.environ.get("RALPH_SYNTHETIC_SECRET")
        original_path = os.environ.get("PATH")
        os.environ["RALPH_SYNTHETIC_SECRET"] = "must-not-cross-boundary"
        os.environ["PATH"] = "/tmp/provider-controlled"
        try:
            env = build_safe_env()
            self.assertNotIn("RALPH_SYNTHETIC_SECRET", env)
            self.assertEqual(
                env["PATH"],
                "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
            )
        finally:
            if original is None:
                del os.environ["RALPH_SYNTHETIC_SECRET"]
            else:
                os.environ["RALPH_SYNTHETIC_SECRET"] = original
            if original_path is None:
                del os.environ["PATH"]
            else:
                os.environ["PATH"] = original_path

    def test_explicit_path_override_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "PATH override"):
            build_safe_env({"PATH": "/tmp/provider-controlled"})

    def test_provider_preflight_failure_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            provider = CommandProvider(
                "test",
                [sys.executable, "-c", "print('unused')"],
                preflight_argv=[
                    sys.executable,
                    "-c",
                    "import sys; print('confinement failed', file=sys.stderr); raise SystemExit(6)",
                ],
            )
            error = provider.preflight(Path(raw), timeout_seconds=2)
            self.assertIsNotNone(error)
            self.assertIn("exit 6", error or "")
            self.assertIn("confinement failed", error or "")

    def test_provider_preflight_timeout_terminates_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            script = root / "preflight.sh"
            script.write_text(
                "#!/bin/sh\n"
                "sleep 30 &\n"
                "wait\n",
                encoding="utf-8",
            )
            script.chmod(0o700)
            provider = CommandProvider(
                "test",
                [sys.executable, "-c", "print('unused')"],
                preflight_argv=[str(script)],
            )

            with mock.patch(
                "ralph_hardened.provider.os.killpg", wraps=os.killpg
            ) as kill_process_group:
                error = provider.preflight(root, timeout_seconds=0.2)

            self.assertEqual(error, "provider preflight exceeded 0.2 seconds")
            kill_process_group.assert_any_call(mock.ANY, signal.SIGTERM)


if __name__ == "__main__":
    unittest.main()
