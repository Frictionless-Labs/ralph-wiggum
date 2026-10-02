from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ralph_hardened.errors import GitPolicyError, PreflightError
from ralph_hardened.gitops import GitWorkspace

from tests.helpers import init_repo, run


class GitWorkspaceTests(unittest.TestCase):
    def test_worktree_creation_does_not_execute_git_smudge_filters(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "source"
            init_repo(repo)
            (repo / ".gitattributes").write_text("*.txt filter=review\n", encoding="utf-8")
            run("git", "add", ".gitattributes", cwd=repo)
            run("git", "commit", "-m", "test: add attributes", cwd=repo)
            marker = root / "smudge-filter-ran"
            helper = root / "filter.py"
            helper.write_text(
                "import pathlib, sys\n"
                "pathlib.Path(sys.argv[1]).write_text('ran')\n"
                "sys.stdout.buffer.write(sys.stdin.buffer.read())\n",
                encoding="utf-8",
            )
            run(
                "git",
                "config",
                "filter.review.smudge",
                f"{sys.executable} {helper} {marker}",
                cwd=repo,
            )
            head = run("git", "rev-parse", "HEAD", cwd=repo).stdout.strip()

            workspace = GitWorkspace.create(repo, root / "state", "run-001", head)

            self.assertFalse(marker.exists())
            self.assertEqual((workspace.path / "app.txt").read_text(), "baseline\n")

    def test_exact_staging_does_not_execute_git_clean_filters(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "source"
            init_repo(repo)
            (repo / ".gitattributes").write_text("*.txt filter=review\n", encoding="utf-8")
            run("git", "add", ".gitattributes", cwd=repo)
            run("git", "commit", "-m", "test: add attributes", cwd=repo)
            head = run("git", "rev-parse", "HEAD", cwd=repo).stdout.strip()
            workspace = GitWorkspace.create(repo, root / "state", "run-001", head)
            marker = root / "clean-filter-ran"
            helper = root / "filter.py"
            helper.write_text(
                "import pathlib, sys\n"
                "pathlib.Path(sys.argv[1]).write_text('ran')\n"
                "sys.stdout.buffer.write(sys.stdin.buffer.read())\n",
                encoding="utf-8",
            )
            run(
                "git",
                "config",
                "filter.review.clean",
                f"{sys.executable} {helper} {marker}",
                cwd=repo,
            )
            baseline = workspace.workspace_inventory()
            (workspace.path / "app.txt").write_text("verified\n", encoding="utf-8")
            manifest = workspace.validate_manifest(
                ["app.txt"], [], baseline_inventory=baseline
            )
            workspace.stage_exact(manifest)
            self.assertFalse(marker.exists())

    def test_worktree_creation_does_not_execute_repository_hooks(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "source"
            head = init_repo(repo)
            marker = root / "hook-ran"
            hook = repo / ".git" / "hooks" / "post-checkout"
            hook.write_text(
                f"#!/bin/sh\ntouch '{marker}'\nprintf 'hooked\\n' > app.txt\n",
                encoding="utf-8",
            )
            hook.chmod(0o700)
            workspace = GitWorkspace.create(repo, root / "state", "run-001", head)
            self.assertFalse(marker.exists())
            self.assertEqual((workspace.path / "app.txt").read_text(), "baseline\n")

    def test_symlinked_worktrees_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "source"
            head = init_repo(repo)
            state = root / "state"
            redirect = root / "redirect"
            state.mkdir()
            redirect.mkdir()
            (state / "worktrees").symlink_to(redirect, target_is_directory=True)
            with self.assertRaisesRegex(PreflightError, "worktrees root must be a real directory"):
                GitWorkspace.create(repo, state, "run-001", head)

    def test_dirty_parent_changes_do_not_enter_worktree(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "source"
            head = init_repo(repo)
            (repo / "app.txt").write_text("uncommitted parent change\n", encoding="utf-8")
            (repo / "untracked.txt").write_text("parent only\n", encoding="utf-8")
            workspace = GitWorkspace.create(repo, root / "state", "run-001", head)
            self.assertEqual((workspace.path / "app.txt").read_text(encoding="utf-8"), "baseline\n")
            self.assertFalse((workspace.path / "untracked.txt").exists())

    def test_state_directory_can_host_multiple_run_worktrees(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "source"
            head = init_repo(repo)
            first = GitWorkspace.create(repo, root / "state", "run-001", head)
            second = GitWorkspace.create(repo, root / "state", "run-002", head)
            self.assertTrue(first.path.is_dir())
            self.assertTrue(second.path.is_dir())

    def test_single_star_does_not_cross_path_segments(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "source"
            head = init_repo(repo)
            workspace = GitWorkspace.create(repo, root / "state", "run-001", head)
            baseline = workspace.workspace_inventory()
            nested = workspace.path / "src" / "nested"
            nested.mkdir(parents=True)
            (nested / "file.py").write_text("nested\n", encoding="utf-8")
            with self.assertRaisesRegex(GitPolicyError, "outside allowed paths"):
                workspace.validate_manifest(
                    ["src/*.py"], [], baseline_inventory=baseline
                )
            self.assertEqual(
                workspace.validate_manifest(
                    ["src/**"], [], baseline_inventory=baseline
                ),
                ("src/nested/file.py",),
            )

    def test_disallowed_and_secret_paths_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "source"
            head = init_repo(repo)
            workspace = GitWorkspace.create(repo, root / "state", "run-001", head)
            baseline = workspace.workspace_inventory()
            (workspace.path / "other.txt").write_text("no\n", encoding="utf-8")
            with self.assertRaisesRegex(GitPolicyError, "outside allowed paths"):
                workspace.validate_manifest(
                    ["app.txt"], [], baseline_inventory=baseline
                )
            (workspace.path / "other.txt").unlink()
            (workspace.path / ".env").write_text("TOKEN=synthetic\n", encoding="utf-8")
            with self.assertRaisesRegex(GitPolicyError, "secret-like"):
                workspace.validate_manifest(["**"], [], baseline_inventory=baseline)

    def test_secret_like_parent_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "source"
            head = init_repo(repo)
            workspace = GitWorkspace.create(repo, root / "state", "run-001", head)
            baseline = workspace.workspace_inventory()
            secret_directory = workspace.path / ".env"
            secret_directory.mkdir()
            (secret_directory / "production.json").write_text("{}\n", encoding="utf-8")

            with self.assertRaisesRegex(GitPolicyError, "secret-like"):
                workspace.validate_manifest(["**"], [], baseline_inventory=baseline)

    def test_symlink_change_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "source"
            head = init_repo(repo)
            workspace = GitWorkspace.create(repo, root / "state", "run-001", head)
            baseline = workspace.workspace_inventory()
            os.symlink("app.txt", workspace.path / "link.txt")
            with self.assertRaisesRegex(GitPolicyError, "symlink"):
                workspace.validate_manifest(
                    ["link.txt"], [], baseline_inventory=baseline
                )

    def test_nested_repository_is_rejected_before_staging(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "source"
            head = init_repo(repo)
            workspace = GitWorkspace.create(repo, root / "state", "run-001", head)
            baseline = workspace.workspace_inventory()
            nested = workspace.path / "vendor" / "dependency"
            init_repo(nested)
            with self.assertRaisesRegex(GitPolicyError, "nested repository"):
                workspace.validate_manifest(
                    ["vendor/**"], [], baseline_inventory=baseline
                )

    def test_nested_git_file_is_rejected_before_staging(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "source"
            head = init_repo(repo)
            workspace = GitWorkspace.create(repo, root / "state", "run-001", head)
            baseline = workspace.workspace_inventory()
            nested = workspace.path / "src"
            nested.mkdir()
            (nested / ".git").write_text("gitdir: ../outside\n", encoding="utf-8")

            with self.assertRaisesRegex(GitPolicyError, "nested repository"):
                workspace.validate_manifest(
                    ["src/**"], [], baseline_inventory=baseline
                )

    def test_tracked_symlink_deletion_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "source"
            init_repo(repo)
            os.symlink("app.txt", repo / "link.txt")
            run("git", "add", "link.txt", cwd=repo)
            run("git", "commit", "-m", "test: add symlink", cwd=repo)
            head = run("git", "rev-parse", "HEAD", cwd=repo).stdout.strip()
            workspace = GitWorkspace.create(repo, root / "state", "run-001", head)
            baseline = workspace.workspace_inventory()
            (workspace.path / "link.txt").unlink()
            with self.assertRaisesRegex(GitPolicyError, "symlink"):
                workspace.validate_manifest(
                    ["link.txt"], [], baseline_inventory=baseline
                )

    def test_tracked_gitlink_deletion_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "source"
            init_repo(repo)
            commit = run("git", "rev-parse", "HEAD", cwd=repo).stdout.strip()
            run(
                "git",
                "update-index",
                "--add",
                "--cacheinfo",
                f"160000,{commit},vendor/submodule",
                cwd=repo,
            )
            run("git", "commit", "-m", "test: add gitlink", cwd=repo)
            head = run("git", "rev-parse", "HEAD", cwd=repo).stdout.strip()
            workspace = GitWorkspace.create(repo, root / "state", "run-001", head)
            baseline = workspace.workspace_inventory()
            (workspace.path / "vendor" / "submodule").rmdir()
            with self.assertRaisesRegex(GitPolicyError, "gitlink"):
                workspace.validate_manifest(
                    ["vendor/submodule"], [], baseline_inventory=baseline
                )

    def test_tracked_gitlink_cannot_be_replaced_through_descendant(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "source"
            init_repo(repo)
            commit = run("git", "rev-parse", "HEAD", cwd=repo).stdout.strip()
            run(
                "git",
                "update-index",
                "--add",
                "--cacheinfo",
                f"160000,{commit},vendor/submodule",
                cwd=repo,
            )
            run("git", "commit", "-m", "test: add gitlink", cwd=repo)
            head = run("git", "rev-parse", "HEAD", cwd=repo).stdout.strip()
            workspace = GitWorkspace.create(repo, root / "state", "run-001", head)
            baseline = workspace.workspace_inventory()
            (workspace.path / "vendor" / "submodule" / "payload.txt").write_text(
                "replacement\n", encoding="utf-8"
            )

            with self.assertRaisesRegex(GitPolicyError, "gitlink ancestor"):
                workspace.validate_manifest(
                    ["vendor/submodule/**"], [], baseline_inventory=baseline
                )

    def test_ignored_provider_file_changes_digest(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "source"
            init_repo(repo)
            (repo / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
            run("git", "add", ".gitignore", cwd=repo)
            run("git", "commit", "-m", "test: ignore fixture", cwd=repo)
            head = run("git", "rev-parse", "HEAD", cwd=repo).stdout.strip()
            workspace = GitWorkspace.create(repo, root / "state", "run-001", head)
            before = workspace.ignored_digest()
            (workspace.path / "ignored.txt").write_text("hidden\n", encoding="utf-8")
            self.assertNotEqual(workspace.ignored_digest(), before)

    def test_workspace_digest_includes_mode_only_changes_and_empty_directories(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "source"
            head = init_repo(repo)
            workspace = GitWorkspace.create(repo, root / "state", "run-001", head)
            baseline = workspace.workspace_digest()
            (workspace.path / "app.txt").chmod(0o600)
            self.assertNotEqual(baseline, workspace.workspace_digest())
            (workspace.path / "app.txt").chmod(0o644)
            self.assertEqual(baseline, workspace.workspace_digest())
            (workspace.path / "empty").mkdir()
            self.assertNotEqual(baseline, workspace.workspace_digest())

    def test_workspace_digest_frames_fields_to_prevent_structural_collisions(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "source"
            head = init_repo(repo)
            workspace = GitWorkspace.create(repo, root / "state", "run-001", head)
            original = workspace.path / "a32768420"
            original.write_text("X", encoding="utf-8")
            first_digest = workspace.workspace_digest()
            original.unlink()
            (workspace.path / "a").write_text("32768420X", encoding="utf-8")
            self.assertNotEqual(first_digest, workspace.workspace_digest())

    def test_manifest_allows_removal_of_empty_parent_for_tracked_deletion(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "source"
            init_repo(repo)
            (repo / "nested").mkdir()
            (repo / "nested" / "only.txt").write_text("tracked\n", encoding="utf-8")
            run("git", "add", "nested/only.txt", cwd=repo)
            run("git", "commit", "-m", "test: add nested fixture", cwd=repo)
            head = run("git", "rev-parse", "HEAD", cwd=repo).stdout.strip()
            workspace = GitWorkspace.create(repo, root / "state", "run-001", head)
            baseline = workspace.workspace_inventory()
            (workspace.path / "nested" / "only.txt").unlink()
            (workspace.path / "nested").rmdir()
            self.assertEqual(
                workspace.validate_manifest(
                    ["nested/only.txt"], [], baseline_inventory=baseline
                ),
                ("nested/only.txt",),
            )

    def test_workspace_identity_includes_root_mode(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "source"
            head = init_repo(repo)
            workspace = GitWorkspace.create(repo, root / "state", "run-001", head)
            baseline_inventory = workspace.workspace_inventory()
            baseline_digest = workspace.workspace_digest()
            original_mode = workspace.path.stat().st_mode & 0o777
            workspace.path.chmod(original_mode | 0o022)
            try:
                self.assertNotEqual(baseline_digest, workspace.workspace_digest())
                (workspace.path / "app.txt").write_text("verified\n", encoding="utf-8")
                with self.assertRaisesRegex(GitPolicyError, "root metadata"):
                    workspace.validate_manifest(
                        ["app.txt"], [], baseline_inventory=baseline_inventory
                    )
            finally:
                workspace.path.chmod(original_mode)

    def test_manifest_rejects_non_git_workspace_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "source"
            head = init_repo(repo)
            workspace = GitWorkspace.create(repo, root / "state", "run-001", head)
            baseline = workspace.workspace_inventory()
            (workspace.path / "app.txt").write_text("verified\n", encoding="utf-8")
            (workspace.path / "outside-empty").mkdir()
            with self.assertRaisesRegex(GitPolicyError, "non-Git workspace artifact"):
                workspace.validate_manifest(["app.txt"], [], baseline_inventory=baseline)

    def test_manifest_allows_new_parent_directories_for_candidate_files(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "source"
            head = init_repo(repo)
            workspace = GitWorkspace.create(repo, root / "state", "run-001", head)
            baseline = workspace.workspace_inventory()
            nested = workspace.path / "src" / "nested"
            nested.mkdir(parents=True)
            (nested / "feature.py").write_text("verified\n", encoding="utf-8")
            self.assertEqual(
                workspace.validate_manifest(
                    ["src/**"], [], baseline_inventory=baseline
                ),
                ("src/nested/feature.py",),
            )

    def test_existing_validator_file_is_immutable(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "source"
            init_repo(repo)
            validator = repo / "tests" / "acceptance.py"
            validator.parent.mkdir()
            validator.write_text("assert True\n", encoding="utf-8")
            run("git", "add", "tests/acceptance.py", cwd=repo)
            run("git", "commit", "-m", "test: add validator", cwd=repo)
            head = run("git", "rev-parse", "HEAD", cwd=repo).stdout.strip()
            workspace = GitWorkspace.create(repo, root / "state", "run-001", head)
            baseline = workspace.workspace_inventory()
            (workspace.path / "tests" / "acceptance.py").write_text("pass\n", encoding="utf-8")
            with self.assertRaisesRegex(GitPolicyError, "immutable validator"):
                workspace.validate_manifest(
                    ["tests/**"],
                    [],
                    ["tests/**"],
                    baseline_inventory=baseline,
                )

    def test_candidate_growth_limit_fails_before_git_manifest_expansion(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "source"
            head = init_repo(repo)
            workspace = GitWorkspace.create(repo, root / "state", "run-001", head)
            baseline = workspace.workspace_inventory()
            (workspace.path / "large.bin").write_bytes(b"x" * 4096)
            with mock.patch("ralph_hardened.limits.MAX_FILE_GROWTH_BYTES", 128):
                with self.assertRaisesRegex(GitPolicyError, "file growth limit exceeded"):
                    workspace.validate_manifest(
                        ["large.bin"], [], baseline_inventory=baseline
                    )

    def test_stage_uses_nul_index_input_for_many_paths(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "source"
            head = init_repo(repo)
            workspace = GitWorkspace.create(repo, root / "state", "run-001", head)
            baseline = workspace.workspace_inventory()
            for index in range(40):
                (workspace.path / f"file-{index:03}.txt").write_text("ok\n", encoding="utf-8")
            manifest = workspace.validate_manifest(
                ["*.txt"], [], baseline_inventory=baseline
            )
            tree = workspace.stage_exact(manifest)
            self.assertEqual(len(manifest), 40)
            self.assertEqual(len(tree), 40)

    def test_provider_filenames_are_always_literal_git_paths(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "source"
            head = init_repo(repo)
            workspace = GitWorkspace.create(repo, root / "state", "run-001", head)
            baseline = workspace.workspace_inventory()
            adversarial = ":(exclude)literal.txt"
            (workspace.path / adversarial).write_text("literal\n", encoding="utf-8")
            manifest = workspace.validate_manifest(
                ["**"], [], baseline_inventory=baseline
            )
            tree = workspace.stage_exact(manifest)
            commit = workspace.commit_verified("test(git): preserve literal path")
            self.assertIn(adversarial, manifest)
            self.assertEqual(workspace.commit_tree(commit), tree)
            self.assertEqual(run("git", "status", "--short", cwd=workspace.path).stdout, "")

    def test_exact_staging_tree_matches_commit_tree(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "source"
            head = init_repo(repo)
            workspace = GitWorkspace.create(repo, root / "state", "run-001", head)
            baseline = workspace.workspace_inventory()
            (workspace.path / "app.txt").write_text("verified\n", encoding="utf-8")
            manifest = workspace.validate_manifest(
                ["app.txt"], [], baseline_inventory=baseline
            )
            evaluated_tree = workspace.stage_exact(manifest)
            commit = workspace.commit_verified("feat(fixture): verify app")
            self.assertEqual(workspace.commit_tree(commit), evaluated_tree)
            self.assertNotEqual(commit, head)
            self.assertEqual(run("git", "status", "--short", cwd=workspace.path).stdout, "")

    def test_verified_commit_does_not_execute_repository_hooks(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "source"
            head = init_repo(repo)
            marker = root / "hook-ran"
            hook = repo / ".git" / "hooks" / "pre-commit"
            hook.write_text(f"#!/bin/sh\ntouch '{marker}'\nexit 1\n", encoding="utf-8")
            hook.chmod(0o700)
            workspace = GitWorkspace.create(repo, root / "state", "run-001", head)
            baseline = workspace.workspace_inventory()
            (workspace.path / "app.txt").write_text("verified\n", encoding="utf-8")
            manifest = workspace.validate_manifest(
                ["app.txt"], [], baseline_inventory=baseline
            )
            workspace.stage_exact(manifest)
            workspace.commit_verified("feat(fixture): verify app")
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
