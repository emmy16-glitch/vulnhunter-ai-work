# ADR-0009: Immutable evaluator and transactional experiments

- Status: Accepted
- Decision date: 2026-07-09

## Context

An automated experiment can appear to improve when it edits tests, labels, holdouts, safety policies, or evaluation code instead of improving the candidate. Failed experiments can also leave random code in the primary repository.

## Decision

Run each research hypothesis in an isolated Git branch/worktree from a clean recorded baseline. Classify resources as editable, read-only, or inaccessible. Hash protected baseline resources outside the candidate worktree. Accept only one clean candidate commit that passes fixed verifiers, objective improvement, regression limits, safety checks, resource boundaries, and provenance checks.

Rejected and inconclusive worktrees are removed while their evidence and patch remain archived. Accepted candidates require a separate human-confirmed promotion step.

## Consequences

Benefits:

- candidates cannot receive credit for changing evaluator resources;
- failed experiments do not contaminate the primary tree;
- every decision is reproducible and auditable;
- a candidate cannot trade a security regression for a better score.

Costs:

- experiment setup and evidence storage are more complex;
- each hypothesis is limited to one candidate commit;
- local actor identities remain pseudonymous until signed identities exist.
