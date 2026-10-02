from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from ralph_hardened.errors import StateError
from ralph_hardened.state import RunStore, lock_resumable_run

from tests.helpers import write_config, write_prd


class StateTests(unittest.TestCase):
    def test_resume_lock_rejects_a_concurrent_owner(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            store = RunStore.create(
                root / "state", write_prd(root / "prd.json"), "head", ["US-001"]
            )
            with lock_resumable_run(store.run_dir):
                with self.assertRaisesRegex(StateError, "already active"):
                    with lock_resumable_run(store.run_dir):
                        self.fail("concurrent resume lock was acquired")
            self.assertEqual((store.run_dir / ".resume.lock").stat().st_mode & 0o777, 0o600)

    def test_malformed_saved_state_is_rejected_as_state_error(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            run_dir = Path(raw) / "runs" / "bad-run"
            run_dir.mkdir(parents=True)
            (run_dir / "run.json").write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(StateError, "invalid run state"):
                RunStore.load(run_dir)

    def test_invalid_utf8_saved_state_is_rejected_as_state_error(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            store = RunStore.create(
                root / "state", write_prd(root / "prd.json"), "head", ["US-001"]
            )
            store.state_path.write_bytes(b"\xff\xfe\x00")
            with self.assertRaisesRegex(StateError, "invalid run state"):
                RunStore.load(store.run_dir)

    def test_resume_load_rejects_hierarchy_that_became_shared_writable(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            state_root = root / "state"
            store = RunStore.create(
                state_root, write_prd(root / "prd.json"), "head", ["US-001"]
            )
            state_root.chmod(0o770)
            with self.assertRaisesRegex(StateError, "unsafe state hierarchy"):
                RunStore.load(store.run_dir)

    def test_resume_lock_rejects_hierarchy_that_became_shared_writable(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            state_root = root / "state"
            store = RunStore.create(
                state_root, write_prd(root / "prd.json"), "head", ["US-001"]
            )
            state_root.chmod(0o770)
            with self.assertRaisesRegex(StateError, "unsafe state hierarchy"):
                with lock_resumable_run(store.run_dir):
                    self.fail("unsafe hierarchy acquired a resume lock")

    def test_saved_run_id_must_match_its_directory(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            store = RunStore.create(
                root / "state", write_prd(root / "prd.json"), "head", ["US-001"]
            )
            state = json.loads(store.state_path.read_text(encoding="utf-8"))
            state["runId"] = "copied-alias"
            store.state_path.write_text(json.dumps(state), encoding="utf-8")
            with self.assertRaisesRegex(StateError, "invalid run state"):
                RunStore.load(store.run_dir)

    def test_snapshot_is_immutable_and_digest_is_stable(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            prd = write_prd(root / "prd.json")
            store = RunStore.create(root / "state", prd, "head-sha", ["US-001"])
            digest = store.state["prdDigest"]
            snapshot = store.snapshot_path.read_bytes()
            prd.write_text("{}", encoding="utf-8")
            resumed = RunStore.load(store.run_dir)
            self.assertEqual(resumed.state["prdDigest"], digest)
            self.assertEqual(resumed.snapshot_path.read_bytes(), snapshot)

    def test_config_snapshot_is_frozen_when_supplied(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            prd = write_prd(root / "prd.json")
            config = write_config(root / "config.json")
            store = RunStore.create(root / "state", prd, "head", ["US-001"], config_path=config)
            digest = store.state["configDigest"]
            snapshot = store.config_snapshot_path.read_bytes()
            config.write_text("{}", encoding="utf-8")
            resumed = RunStore.load(store.run_dir)
            self.assertEqual(resumed.state["configDigest"], digest)
            self.assertEqual(resumed.config_snapshot_path.read_bytes(), snapshot)

    def test_explicit_input_bytes_are_the_immutable_snapshots(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            prd = write_prd(root / "prd.json")
            config = write_config(root / "config.json")
            prd_bytes = prd.read_bytes()
            config_bytes = config.read_bytes()
            prd.write_text("{}", encoding="utf-8")
            config.write_text("{}", encoding="utf-8")
            store = RunStore.create(
                root / "state",
                prd,
                "head",
                ["US-001"],
                config_path=config,
                prd_bytes=prd_bytes,
                config_bytes=config_bytes,
            )
            self.assertEqual(store.snapshot_path.read_bytes(), prd_bytes)
            self.assertEqual(store.config_snapshot_path.read_bytes(), config_bytes)

    def test_invalid_transition_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            store = RunStore.create(root / "state", write_prd(root / "prd.json"), "head", ["US-001"])
            with self.assertRaisesRegex(StateError, "invalid story transition"):
                store.transition_story("US-001", "PASS")

    def test_events_are_append_only_and_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            store = RunStore.create(root / "state", write_prd(root / "prd.json"), "head", ["US-001"])
            store.event("provider_result", story_id="US-001", attempt=1, detail={"token": "abc", "message": "ok"})
            lines = store.events_path.read_text(encoding="utf-8").splitlines()
            self.assertGreaterEqual(len(lines), 2)
            event = json.loads(lines[-1])
            self.assertEqual(event["runId"], store.run_id)
            self.assertEqual(event["storyId"], "US-001")
            self.assertEqual(event["attempt"], 1)
            self.assertEqual(event["detail"]["token"], "[REDACTED]")

    def test_existing_state_root_permissions_are_not_changed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            state_root = root / "shared-state"
            state_root.mkdir(mode=0o750)
            before = state_root.stat().st_mode & 0o777
            RunStore.create(state_root, write_prd(root / "prd.json"), "head", ["US-001"])
            after = state_root.stat().st_mode & 0o777
            self.assertEqual(after, before)

    def test_state_root_writable_by_another_principal_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            state_root = root / "shared-state"
            state_root.mkdir(mode=0o770)
            state_root.chmod(0o770)
            with self.assertRaisesRegex(StateError, "unsafe state hierarchy"):
                RunStore.create(
                    state_root,
                    write_prd(root / "prd.json"),
                    "head",
                    ["US-001"],
                )

    def test_state_root_below_replaceable_parent_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            replaceable_parent = root / "replaceable"
            replaceable_parent.mkdir(mode=0o777)
            replaceable_parent.chmod(0o777)
            state_root = replaceable_parent / "state"
            state_root.mkdir(mode=0o700)
            with self.assertRaisesRegex(StateError, "unsafe state hierarchy"):
                RunStore.create(
                    state_root,
                    write_prd(root / "prd.json"),
                    "head",
                    ["US-001"],
                )

    def test_state_root_below_sticky_shared_parent_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            sticky_parent = root / "sticky"
            sticky_parent.mkdir(mode=0o1777)
            sticky_parent.chmod(0o1777)
            state_root = sticky_parent / "state"
            store = RunStore.create(
                state_root,
                write_prd(root / "prd.json"),
                "head",
                ["US-001"],
            )
            self.assertEqual(store.run_dir.stat().st_mode & 0o777, 0o700)

    def test_symlinked_state_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            target = root / "target"
            target.mkdir()
            state_root = root / "state-link"
            state_root.symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(StateError, "real directory"):
                RunStore.create(
                    state_root,
                    write_prd(root / "prd.json"),
                    "head",
                    ["US-001"],
                )


if __name__ == "__main__":
    unittest.main()
