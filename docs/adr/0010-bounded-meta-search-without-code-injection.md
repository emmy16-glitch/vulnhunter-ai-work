# ADR-0010: Bounded meta-search without code injection

- Status: Accepted
- Decision date: 2026-07-09

## Context

A higher-level loop can improve search diversity by identifying repeated hypotheses and overused strategies. Allowing that outer loop to inject arbitrary Python or edit evaluator policy would recreate the same evaluator-gaming risk at a higher level.

## Decision

The outer loop may analyze experiment metadata and propose non-executable search-policy weights. It cannot modify evaluator boundaries, safety invariants, tests, holdouts, labels, authorization rules, or source code. A human must approve every proposed policy generation before it becomes active.

## Consequences

Benefits:

- search can escape repetitive patterns without granting self-modifying authority;
- evaluator integrity remains independent from both inner and outer loops;
- policy changes remain inspectable and reversible.

Costs:

- the outer loop is less autonomous than systems that inject code;
- a human remains in control of policy promotion.
