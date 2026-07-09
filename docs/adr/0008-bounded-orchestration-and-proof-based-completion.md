# ADR-0008: Bounded orchestration and proof-based completion

- Status: Accepted
- Decision date: 2026-07-09

## Context

Open-ended coding-agent loops can claim success without objective evidence, repeat the same failing action, exceed resource budgets, modify unrelated files, or blur builder, verifier, reviewer, and approver responsibilities.

## Decision

VulnHunter engineering automation must use a bounded orchestration contract with:

- a strict task specification;
- explicit context and path boundaries;
- fixed deterministic verifier commands;
- separate builder, test-runner, security-verifier, reviewer, and human roles;
- maximum iteration, time, token, cost, diff, and changed-file ceilings;
- repeated-error and no-progress detection;
- hash-chained audit events;
- explicit human approval;
- documentation and a learning record before completion.

The harness records and verifies repository evidence but does not autonomously edit source code or execute arbitrary specification commands.

## Consequences

Benefits:

- unsupported completion claims are rejected;
- failures and repeated attempts remain auditable;
- role separation is mechanically enforced;
- rollback is bounded and cannot rewrite commits;
- future AI coding work can be evaluated consistently.

Costs:

- every substantial change requires a specification and role identities;
- the fixed verifier registry must be maintained as the project evolves;
- local pseudonymous identities are not authenticated accounts;
- the policy sentinel does not replace expert security review.
