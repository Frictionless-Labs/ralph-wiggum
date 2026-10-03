---
name: ralph
description: Convert an existing PRD into the validated prd.json format used by the hardened Ralph orchestrator, including bounded file scope, named checks, dependencies, and browser-verification declarations.
---

# Hardened Ralph PRD Converter

Convert a PRD into `prd.json` without granting the implementation worker state, Git, validation, or completion authority.

## Inputs to inspect

Read the source PRD and the exact operator-reviewed `ralph.config.json` that will be passed to Ralph. Do not invent check IDs or assume paths. If repository structure is available, inspect it before deriving file scopes.

## Output contract

Each story must be small enough for one fresh provider context and include:

````json
{
  "id": "US-001",
  "title": "Focused story title",
  "description": "As a user, I want a bounded outcome so that the benefit is explicit.",
  "acceptanceCriteria": [
    "Specific observable behavior",
    "Named checks pass"
  ],
  "priority": 1,
  "allowedPaths": [
    "src/feature/**",
    "tests/feature/**"
  ],
  "requiredChecks": [
    "unit",
    "lint"
  ],
  "dependsOn": [],
  "references": ["docs/reviewed-context.md"],
  "requiresBrowser": false
}
````

The root object requires non-empty `project`, `description`, and `userStories`.

## Rules that change execution safety

- Use unique IDs and positive integer priorities. Put dependencies before consumers and declare them with existing IDs.
- Make every `allowedPaths` entry repository-relative. Never use absolute paths or `..` traversal. Prefer the narrowest paths that can satisfy the story.
- Select `requiredChecks` only from the provided configuration's named check registry. PRD shell commands are prohibited.
- Set `requiresBrowser` to true when acceptance depends on rendered UI or interaction. Include a required check configured with `kind: browser` when synchronous verification exists; otherwise exact-tree external evidence is required.
- Add `references` only for explicitly selected tracked text blobs needed by this story. Paths must be unique and repository-relative; use at most eight and never select secrets, symlinks, generated progress history, or protected files.
- Do not add or use `passes`, completion tokens, branch mutation instructions, commit instructions, or progress-file authority. Canonical status belongs to the orchestrator.
- Do not broaden scope merely to avoid dependency ordering; split the story instead.

## Conversion workflow

Map every verifiable requirement to one or more stories, order the dependency graph, assign narrow file scopes, attach the minimum sufficient named checks, and validate the resulting JSON against `schemas/prd.schema.json` plus repository semantic rules.

Before returning, confirm that every check ID exists, dependencies are acyclic, scopes do not overlap protected/secret paths, UI stories have a browser-verification route, and no acceptance criterion relies solely on provider prose.
