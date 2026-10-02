from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[1]


class RepositoryPolicyTests(unittest.TestCase):
    def test_legacy_prompts_do_not_delegate_state_or_git_authority(self) -> None:
        text = "\n".join(
            (ROOT / name).read_text(encoding="utf-8") for name in ("prompt.md", "CLAUDE.md")
        )
        prohibited = (
            "commit ALL changes",
            "set `passes: true`",
            "<promise>COMPLETE</promise>",
            "check it out or create from main",
        )
        for phrase in prohibited:
            self.assertNotIn(phrase, text)

    def test_launcher_has_no_failure_suppression_or_permission_bypass(self) -> None:
        text = (ROOT / "ralph.sh").read_text(encoding="utf-8")
        self.assertNotIn("|| true", text)
        self.assertNotIn("dangerously", text)
        self.assertNotIn("<promise>", text)
        self.assertIn("PATH='/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin'", text)

    def test_provider_rechecks_exact_image_confinement_for_each_invocation(self) -> None:
        text = (ROOT / "scripts" / "run-codex-provider.sh").read_text(encoding="utf-8")
        branch = text.index("if [ \"${1:-}\" = '--preflight' ]")
        guard = text.index("check_sandbox </dev/null", branch)
        execution = text.index("docker_base --strict-config", guard)
        self.assertLess(guard, execution)
        self.assertIn("--ulimit fsize=67108864:67108864", text)
        self.assertIn("stat.S_IRUSR", text)

    def test_ci_and_pages_workflows_are_sha_pinned_and_gated(self) -> None:
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        deploy = (ROOT / ".github" / "workflows" / "deploy.yml").read_text(encoding="utf-8")
        self.assertIn("pull_request:", ci)
        self.assertIn("python3 -m unittest discover -s tests -v", ci)
        self.assertIn("npm run lint", ci)
        self.assertIn("npm run build", ci)
        self.assertIn("workflow_run:", deploy)
        self.assertIn("github.event.workflow_run.conclusion == 'success'", deploy)
        self.assertIn("github.event.workflow_run.event == 'push'", deploy)
        self.assertIn("head_repository.full_name == github.repository", deploy)
        self.assertIn("gh api repos/${GITHUB_REPOSITORY}/git/ref/heads/main", deploy)
        self.assertIn('"$current_sha" = "$EXPECTED_SHA"', deploy)
        self.assertIn("if: steps.current-main.outputs.matches == 'true'", deploy)
        self.assertNotIn("workflow_dispatch:", deploy)
        self.assertIn("node-version: 22", deploy)
        self.assertIn("npm ci --ignore-scripts", deploy)
        for workflow in (ci, deploy):
            uses = re.findall(r"uses:\s*([^\s]+)", workflow)
            self.assertTrue(uses)
            for action in uses:
                self.assertRegex(action, r"@[0-9a-f]{40}$")
        self.assertIn("contents: read", ci)

    def test_vite_base_is_environment_driven(self) -> None:
        text = (ROOT / "flowchart" / "vite.config.ts").read_text(encoding="utf-8")
        self.assertIn("VITE_BASE_PATH", text)
        self.assertNotIn("base: '/ralph/'", text)

    def test_example_prd_uses_scope_and_named_checks(self) -> None:
        payload = json.loads((ROOT / "prd.json.example").read_text(encoding="utf-8"))
        for story in payload["userStories"]:
            self.assertTrue(story["allowedPaths"])
            self.assertTrue(story["requiredChecks"])
            self.assertNotIn("passes", story)

    def test_flowchart_build_uses_production_base(self) -> None:
        config = json.loads((ROOT / "ralph.config.json").read_text(encoding="utf-8"))
        self.assertEqual(
            config["checks"]["flowchart-build"]["environment"]["VITE_BASE_PATH"],
            "/ralph-wiggum/",
        )

    def test_dependency_install_scripts_are_disabled(self) -> None:
        package = json.loads((ROOT / "flowchart" / "package.json").read_text(encoding="utf-8"))
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        config = json.loads((ROOT / "ralph.config.json").read_text(encoding="utf-8"))
        self.assertNotIn("allowScripts", package)
        self.assertIn("npm ci --ignore-scripts", workflow)
        self.assertIn("--ignore-scripts", config["checks"]["flowchart-install"]["argv"])

    def test_production_checks_are_container_confined(self) -> None:
        config = json.loads((ROOT / "ralph.config.json").read_text(encoding="utf-8"))
        for check in config["checks"].values():
            self.assertEqual(check["containerImage"], "ralph-validator:1.0.1")

    def test_runtime_image_revisions_are_synchronized(self) -> None:
        provider = "ralph-codex-provider:0.145.0-r1"
        validator = "ralph-validator:1.0.1"
        documents = (
            ROOT / "AGENTS.md",
            ROOT / "README.md",
            ROOT / "SPEC.md",
            ROOT / "docs" / "RUNBOOK.md",
            ROOT / ".github" / "workflows" / "ci.yml",
            ROOT / "scripts" / "run-codex-provider.sh",
        )
        combined = "\n".join(path.read_text(encoding="utf-8") for path in documents)
        self.assertIn(provider, combined)
        self.assertIn(validator, combined)
        for path in documents:
            text = path.read_text(encoding="utf-8")
            if "ralph-codex-provider:" in text:
                self.assertIn(provider, text, path)
            if "ralph-validator:" in text:
                self.assertIn(validator, text, path)

    def test_validator_image_pins_patched_base_and_replaces_distribution_npm(self) -> None:
        dockerfile = (ROOT / "docker" / "validator" / "Dockerfile").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "cgr.dev/chainguard/wolfi-base@sha256:"
            "824f77df45397eb954dfb963db255907ee8842e3446353ce93d688e5e862f51d",
            dockerfile,
        )
        self.assertNotIn("alpine:", dockerfile)
        self.assertIn("nodejs-22", dockerfile)
        self.assertIn("npm@11.19.1", dockerfile)
        self.assertIn("undici@6.28.1", dockerfile)
        self.assertIn("brace-expansion@5.0.12", dockerfile)
        self.assertIn("ip-address@10.7.1", dockerfile)
        self.assertIn("apk del npm", dockerfile)
        self.assertIn("PATH=/opt/npm/bin:", dockerfile)

    def test_operator_documents_match_authority_and_failure_contracts(self) -> None:
        spec = (ROOT / "SPEC.md").read_text(encoding="utf-8")
        runbook = (ROOT / "docs" / "RUNBOOK.md").read_text(encoding="utf-8")
        agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        for requirement in ("REQ-001", "REQ-007", "REQ-014", "REQ-015", "REQ-021"):
            self.assertIn(requirement, spec)
        for term in ("BLOCKED_VERIFIER", "PROVIDER_NONZERO", "BLOCKED_BUDGET"):
            self.assertIn(term, runbook)
        self.assertIn("Only the orchestrator", agents)
        self.assertIn("BLOCKED_NO_PROGRESS", agents)
        self.assertIn("outer scheduler", spec.lower())
        self.assertIn("independent label source", spec)
        self.assertIn("--state-dir", readme)
        self.assertNotIn("outputs `<promise>COMPLETE</promise>`", readme)


if __name__ == "__main__":
    unittest.main()
