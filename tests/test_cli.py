from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ralph_hardened.cli import _resolve_paths, build_parser, provider_from_name

from tests.helpers import init_repo, write_config, write_prd


class CliTests(unittest.TestCase):
    def test_resume_run_infers_its_state_root(self) -> None:
        arguments = build_parser().parse_args(
            ["--resume-run", "/var/tmp/ralph-state/runs/run-001"]
        )
        self.assertEqual(_resolve_paths(arguments)[3], Path("/var/tmp/ralph-state"))

    def test_state_path_is_not_resolved_before_symlink_validation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            target = root / "target"
            target.mkdir()
            state = root / "state"
            state.symlink_to(target, target_is_directory=True)
            arguments = build_parser().parse_args(
                ["--repo", str(root), "--state-dir", str(state)]
            )
            resolved_state = _resolve_paths(arguments)[3]
            self.assertEqual(resolved_state, state.absolute())
            self.assertTrue(resolved_state.is_symlink())

    def test_legacy_positional_iteration_is_supported(self) -> None:
        parser = build_parser()
        arguments = parser.parse_args(["7"])
        self.assertEqual(arguments.legacy_max_iterations, 7)

    def test_explicit_zero_iteration_is_not_replaced_by_default(self) -> None:
        parser = build_parser()
        arguments = parser.parse_args(["--max-iterations", "0"])
        selected = arguments.max_iterations if arguments.max_iterations is not None else 10
        self.assertEqual(selected, 0)

    def test_verified_provider_commands_have_no_bypass_flags(self) -> None:
        provider = provider_from_name("codex")
        self.assertEqual(provider.name, "codex-container")
        self.assertTrue(provider.argv[0].endswith("scripts/run-codex-provider.sh"))
        self.assertEqual(provider.preflight_argv[-1], "--preflight")
        runner = Path(provider.argv[0]).read_text(encoding="utf-8")
        self.assertNotIn("dangerously-skip-permissions", runner)
        self.assertNotIn("dangerously-allow-all", runner)
        self.assertNotIn("bypass-approvals-and-sandbox", runner)
        self.assertIn("--ignore-user-config", runner)
        self.assertIn("--ignore-rules", runner)
        self.assertIn("--skip-git-repo-check", runner)
        self.assertIn("docker image inspect --format '{{.Id}}'", runner)
        self.assertIn('--name "$container_name"', runner)
        self.assertIn('docker rm --force "$container_name"', runner)
        self.assertIn("allow_login_shell=false", runner)
        self.assertIn("permissions.ralph={", runner)
        self.assertIn("/dev/null:/workspace/.git:ro", runner)
        self.assertIn("/home/node/.codex/auth.json\"=\"deny", runner)
        self.assertNotIn("test -r README.md", runner)
        self.assertIn("--read-only", runner)
        self.assertIn("--cap-drop=ALL", runner)
        self.assertIn("--security-opt=no-new-privileges=true", runner)
        self.assertNotIn("/var/run/docker.sock", runner)
        self.assertNotIn("--privileged", runner)
        with self.assertRaisesRegex(Exception, "filesystem confinement"):
            provider_from_name("claude")

    def test_codex_provider_image_is_pinned(self) -> None:
        dockerfile = (
            Path(__file__).parents[1] / "docker" / "codex-provider" / "Dockerfile"
        ).read_text(encoding="utf-8")
        self.assertIn("node:22-bookworm-slim@sha256:", dockerfile)
        self.assertIn("alpine:3.24.1@sha256:", dockerfile)
        self.assertIn("CODEX_VERSION=0.145.0", dockerfile)
        self.assertIn("ralph-netcheck", dockerfile)
        self.assertIn('ENTRYPOINT ["codex"]', dockerfile)

    def test_unverified_amp_adapter_fails_closed(self) -> None:
        with self.assertRaisesRegex(Exception, "not verified"):
            provider_from_name("amp")

    def test_cli_prints_resolved_paths_and_preflight_exit(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "repo"
            init_repo(repo)
            prd = write_prd(root / "prd.json", requiredChecks=["required"])
            config = write_config(root / "config.json")
            state = root / "state"
            result = subprocess.run(
                (
                    sys.executable,
                    "-m",
                    "ralph_hardened",
                    "--repo",
                    str(repo),
                    "--prd",
                    str(prd),
                    "--config",
                    str(config),
                    "--state-dir",
                    str(state),
                    "--tool",
                    "missing-provider",
                    "--max-iterations",
                    "1",
                ),
                cwd=Path(__file__).parents[1],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(result.returncode, 2)
            output = result.stdout + result.stderr
            self.assertIn(str(repo.resolve()), output)
            self.assertIn(str(prd.resolve()), output)
            self.assertIn(str(config.resolve()), output)
            self.assertIn(str(state.absolute()), output)

    def test_missing_repo_is_contract_preflight_exit(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            result = subprocess.run(
                (
                    sys.executable,
                    "-m",
                    "ralph_hardened",
                    "--repo",
                    str(root / "missing"),
                    "--prd",
                    str(root / "missing-prd.json"),
                    "--config",
                    str(root / "missing-config.json"),
                    "--state-dir",
                    str(root / "state"),
                    "--tool",
                    "mock",
                ),
                cwd=Path(__file__).parents[1],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("PRECHECK_REJECTED", result.stderr)
            self.assertNotIn("Traceback", result.stderr)

    def test_schema_is_valid_json_and_requires_scope_and_checks(self) -> None:
        schema_path = Path(__file__).parents[1] / "schemas" / "prd.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        required = schema["properties"]["userStories"]["items"]["required"]
        self.assertIn("allowedPaths", required)
        self.assertIn("requiredChecks", required)


if __name__ == "__main__":
    unittest.main()
