# Core Product Workflows

## Authorization and bounded scan

An operator selects or creates an explicit authorization, enters a target already
covered by that record, reviews inherited limits, and confirms the scan. Progress
presents request budget, elapsed budget, resolved approved addresses, current page,
collected observations, failures, and cancellation state.

## Independent review

A reviewer sees only assigned findings and redacted evidence. The workspace records
one explicit decision, rationale, confidence, and limitations. It never reveals the
second reviewer's decision before submission.

## Adjudication

Disagreements enter a separate queue. The adjudicator sees both completed decisions,
evidence, and conflict checks, but cannot act when they participated as a reviewer.

## Governed release

Release assessment lists hard blockers separately from warnings. Publishing is
unavailable until the backend reports readiness, and there is no UI bypass path.

## Dataset and model evidence

Dataset readiness presents provenance, duplicates, class balance, application-family
coverage, reviewer agreement, disputes, leakage risk, and manifest fingerprints.
Model pages remain evidence-only until a later milestone authorizes training.
