from __future__ import annotations

import json
import math
import tempfile
import unittest
from pathlib import Path

from ralph_hardened.config import load_config
from ralph_hardened.errors import PreflightError
from ralph_hardened.prd import load_prd

from tests.helpers import prd_payload, write_config, write_prd


class PreflightTests(unittest.TestCase):
    def test_unknown_check_policy_key_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            path = write_config(root / "config.json")
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["checks"]["required"]["immutablePath"] = ["tests/**"]
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(PreflightError, "unsupported fields.*immutablePath"):
                load_config(path)

    def test_unknown_root_policy_key_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            path = write_config(root / "config.json")
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["protectedPath"] = payload.pop("protectedPaths")
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(PreflightError, "unsupported root fields.*protectedPath"):
                load_config(path)

    def test_unknown_story_control_key_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            config = load_config(write_config(root / "config.json"))
            path = write_prd(root / "prd.json", requiresBrower=True)
            with self.assertRaisesRegex(PreflightError, "unsupported fields.*requiresBrower"):
                load_prd(path, config)

    def test_noncanonical_path_patterns_fail_closed(self) -> None:
        cases = ("./.github/workflows/**", ".github//workflows/**")
        for pattern in cases:
            with self.subTest(pattern=pattern), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                path = write_config(root / "config.json")
                payload = json.loads(path.read_text(encoding="utf-8"))
                payload["protectedPaths"] = [pattern]
                path.write_text(json.dumps(payload), encoding="utf-8")
                with self.assertRaisesRegex(PreflightError, "protectedPaths"):
                    load_config(path)

    def test_nul_in_check_argument_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            path = write_config(root / "config.json", ["python3", "print(1)\x00"])
            with self.assertRaisesRegex(PreflightError, "argv"):
                load_config(path)

    def test_nul_in_check_environment_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            path = write_config(root / "config.json")
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["checks"]["required"]["environment"] = {"SAFE": "x\x00y"}
            path.write_text(json.dumps(payload), encoding="utf-8")

            with self.assertRaisesRegex(PreflightError, "environment"):
                load_config(path)

    def test_control_character_in_story_id_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            config = load_config(write_config(root / "config.json"))
            path = write_prd(root / "prd.json", id="US-\x00")
            with self.assertRaisesRegex(PreflightError, "id"):
                load_prd(path, config)

    def test_malformed_prd_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            config = load_config(write_config(root / "config.json"))
            (root / "prd.json").write_text("{", encoding="utf-8")
            with self.assertRaisesRegex(PreflightError, "invalid JSON"):
                load_prd(root / "prd.json", config)

    def test_duplicate_ids_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            config = load_config(write_config(root / "config.json"))
            payload = prd_payload()
            payload["userStories"].append(dict(payload["userStories"][0]))  # type: ignore[union-attr,index]
            (root / "prd.json").write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(PreflightError, "duplicate story id"):
                load_prd(root / "prd.json", config)

    def test_dependency_cycle_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            config = load_config(write_config(root / "config.json"))
            payload = prd_payload(dependsOn=["US-002"])
            second = dict(payload["userStories"][0])  # type: ignore[index]
            second.update({"id": "US-002", "dependsOn": ["US-001"]})
            payload["userStories"].append(second)  # type: ignore[union-attr]
            (root / "prd.json").write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(PreflightError, "dependency cycle"):
                load_prd(root / "prd.json", config)

    def test_dependencies_are_scheduled_before_higher_priority_dependents(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            config = load_config(write_config(root / "config.json"))
            payload = prd_payload(dependsOn=["US-002"])
            second = dict(payload["userStories"][0])  # type: ignore[index]
            second.update({"id": "US-002", "title": "Dependency", "priority": 2, "dependsOn": []})
            payload["userStories"].append(second)  # type: ignore[union-attr]
            (root / "prd.json").write_text(json.dumps(payload), encoding="utf-8")
            prd = load_prd(root / "prd.json", config)
            self.assertEqual([story.id for story in prd.stories], ["US-002", "US-001"])

    def test_unknown_check_and_path_traversal_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            config = load_config(write_config(root / "config.json"))
            with self.subTest("unknown check"):
                write_prd(root / "prd.json", requiredChecks=["invented"])
                with self.assertRaisesRegex(PreflightError, "unknown required check"):
                    load_prd(root / "prd.json", config)
            with self.subTest("path traversal"):
                write_prd(root / "prd.json", allowedPaths=["../secret"])
                with self.assertRaisesRegex(PreflightError, "unsafe allowed path"):
                    load_prd(root / "prd.json", config)

    def test_legacy_passes_is_inert(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            config = load_config(write_config(root / "config.json"))
            prd = load_prd(write_prd(root / "prd.json", passes=True), config)
            self.assertEqual(prd.stories[0].id, "US-001")
            self.assertFalse(hasattr(prd.stories[0], "passes"))

    def test_unpinned_or_latest_check_image_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            path = write_config(root / "config.json")
            payload = json.loads(path.read_text(encoding="utf-8"))
            for image in ("validator", "validator:latest"):
                with self.subTest(image=image):
                    payload["checks"]["required"]["containerImage"] = image
                    path.write_text(json.dumps(payload), encoding="utf-8")
                    with self.assertRaisesRegex(PreflightError, "pinned image"):
                        load_config(path)

    def test_unsafe_scratch_mount_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            path = write_config(root / "config.json")
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["checks"]["required"]["scratchMounts"] = {"../escape": "rw"}
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(PreflightError, "scratchMounts"):
                load_config(path)

    def test_nul_in_scratch_mount_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            path = write_config(root / "config.json")
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["checks"]["required"]["scratchMounts"] = {"cache\x00escape": "rw"}
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(PreflightError, "scratchMounts"):
                load_config(path)

    def test_unsafe_config_path_patterns_fail_closed(self) -> None:
        cases = (
            ("immutablePaths", ["tests/unsafe\x00path"], "immutablePaths"),
            ("scratchMounts", {".": "rw"}, "scratchMounts"),
            ("scratchMounts", {"cache:escape": "rw"}, "scratchMounts"),
            ("scratchMounts", {".GIT/cache": "rw"}, "scratchMounts"),
            ("scratchMounts", {"cache\nescape": "rw"}, "scratchMounts"),
            ("protectedPaths", ["private/unsafe\x00path"], "protectedPaths"),
        )
        for field, value, message in cases:
            with self.subTest(field=field, value=value), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                path = write_config(root / "config.json")
                payload = json.loads(path.read_text(encoding="utf-8"))
                if field == "protectedPaths":
                    payload[field] = value
                else:
                    payload["checks"]["required"][field] = value
                path.write_text(json.dumps(payload), encoding="utf-8")
                with self.assertRaisesRegex(PreflightError, message):
                    load_config(path)

    def test_check_path_override_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            path = write_config(root / "config.json")
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["checks"]["required"]["environment"] = {"PATH": "/tmp"}
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(PreflightError, "non-secret string values"):
                load_config(path)

    def test_non_finite_check_timeout_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            path = write_config(root / "config.json")
            payload = json.loads(path.read_text(encoding="utf-8"))
            for timeout in (math.nan, math.inf, -math.inf):
                with self.subTest(timeout=timeout):
                    payload["checks"]["required"]["timeoutSeconds"] = timeout
                    path.write_text(json.dumps(payload), encoding="utf-8")
                    with self.assertRaisesRegex(PreflightError, "must be positive"):
                        load_config(path)


if __name__ == "__main__":
    unittest.main()
