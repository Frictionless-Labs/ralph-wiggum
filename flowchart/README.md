# Hardened Ralph Flowchart

This React Flow application presents the hardened runtime's authority sequence. The worker produces bounded candidate changes; the orchestrator owns input validation, state, scope checks, deterministic verification, Git identity, PASS, and COMPLETE.

The presentation reveals one step at a time. Verify Next, Previous, Reset, pan/zoom, overflow, and responsive layout in a real browser; a successful static build does not replace interaction evidence.

## Development

````bash
npm ci
npm run dev
````

## Validation

````bash
npm audit --audit-level=high
npm run lint
VITE_BASE_PATH=/ralph-wiggum/ npm run build
````

`VITE_BASE_PATH` is `/` by default. CI and Pages set an explicit repository-specific base so fork assets resolve correctly.
