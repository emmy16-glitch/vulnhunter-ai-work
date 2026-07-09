# ADR-0004: Synthetic benchmarks are pipeline evidence only

- Status: Accepted
- Decision date: 2026-07-09

## Context

Controlled local scenarios are useful for deterministic testing but do not represent unknown real applications.

## Decision

Use synthetic benchmarks to validate workflow, reproducibility, provenance, and diagnostics. Never present their metrics as real-world vulnerability-detection performance.

## Consequences

Benefits:

- deterministic end-to-end verification;
- honest interpretation;
- safe local experimentation.

Costs:

- real performance claims remain deferred until diverse authorised data exists.
