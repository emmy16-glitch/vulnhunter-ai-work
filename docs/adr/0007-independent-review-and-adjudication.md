# ADR-0007: Independent review and adjudication

- Status: Accepted
- Decision date: 2026-07-09

## Context

A single reviewer can introduce mistakes or consistent label bias. Those labels become training evidence, so unresolved disagreement must not silently become ground truth.

## Decision

New manual observations use two immutable primary decisions by distinct pseudonymous reviewer IDs.

- Matching decisions establish consensus.
- Conflicting decisions leave the effective label as `needs_review`.
- A third person, distinct from both primary reviewers, may adjudicate the disagreement.
- Pending and disputed cases remain ineligible for training.
- Historical and controlled-benchmark labels remain supported for reproducibility but are identified as legacy review state.

## Consequences

Benefits:

- stronger label reliability;
- explicit disagreement handling;
- auditable decision provenance;
- automatic exclusion of unresolved cases from training.

Costs:

- real dataset creation requires more human effort;
- reviewer identity is currently pseudonymous rather than authenticated;
- historical labels do not automatically gain two-review provenance.
