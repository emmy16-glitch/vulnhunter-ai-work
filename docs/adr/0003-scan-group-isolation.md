# ADR-0003: Split datasets by scan group

- Status: Accepted
- Decision date: 2026-07-09

## Context

Observations from one scan share target, page, headers, templates, and deployment context. Random row splitting can leak near-identical information into training and holdout sets.

## Decision

Keep every observation from one scan in exactly one dataset partition. Perform model selection using training scan groups only.

## Consequences

Benefits:

- more honest generalisation estimates;
- reproducible split provenance;
- reduced duplicate/template leakage.

Costs:

- requires more independent scans;
- small datasets may fail readiness gates rather than train.
