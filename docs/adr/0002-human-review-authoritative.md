# ADR-0002: Human review remains authoritative

- Status: Accepted
- Decision date: 2026-07-09

## Context

Passive signals are contextual. Missing headers or disclosed technologies do not automatically establish a vulnerability.

## Decision

Human reviewers own labels and conclusions. Models may prioritise and predict but cannot mutate labels, resolve conflicts, or approve findings.

## Consequences

Benefits:

- prevents automation from overstating evidence;
- creates auditable training labels;
- supports honest uncertainty.

Costs:

- dataset creation is slower;
- reviewer quality and consistency become important.
