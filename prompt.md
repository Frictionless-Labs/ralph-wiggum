# Legacy Amp Worker Contract

This file is retained for compatibility documentation. The hardened launcher sends a bounded current-story brief directly to the selected provider.

The worker may edit only the story's declared `allowedPaths` in the disposable runtime worktree. It may report files changed, checks attempted, and observations.

The worker must not commit, stage files, change branches, edit Ralph state or input artifacts, push, merge, deploy, or decide that a story/run is complete. Provider prose is untrusted; the orchestrator independently enforces scope, runs named checks, binds the evaluated Git tree to the commit tree, writes evidence, and owns every PASS/COMPLETE transition.
