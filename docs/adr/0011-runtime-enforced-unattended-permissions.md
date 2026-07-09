# ADR-0011: Runtime-enforced unattended permissions

- Status: Accepted
- Decision date: 2026-07-09

## Context

Bounded orchestration and transactional experiments define goals and evaluation, but repeated or scheduled execution introduces another trust boundary. Prompt-only restrictions cannot reliably prevent excessive tools, paths, network access, connectors, secrets, deletion, deployment, or repeated retries.

## Decision

Require every unattended run to use an immutable, time-limited permission manifest approved by a distinct human actor and bound to its SHA-256.

Enforce permissions in runtime adapters rather than relying on natural-language instructions. Use a shell-free fixed command registry. Isolate an item after two materially identical failures. Halt the full workflow when a blocker affects security invariants, authorization, scope, data integrity, the evaluator, or required verifiers.

Use the scheduling decision matrix:

- supervised goal loops for substantial interactive work;
- session loops for temporary repetition;
- local scheduled tasks for private repository work;
- CI workflows for deterministic checks;
- remote routines only for narrowly scoped work with minimal access.

## Consequences

Benefits:

- permissions are machine-enforced and auditable;
- revocation and expiry stop future actions;
- repeated failures do not become infinite retry loops;
- remote execution receives stricter defaults;
- completion depends on real verifier evidence.

Costs:

- manifest creation and independent approval add operational steps;
- every future connector or network executor must integrate with the enforcer;
- OS-level isolation and authenticated identities remain separate requirements.
