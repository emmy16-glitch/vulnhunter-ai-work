# Controlled Human Pilot Runbook

## Boundary

This runbook is for explicitly authorized local or laboratory applications.
Public, external, and third-party targets are prohibited. Plan validation,
pilot execution, dataset release, and model-training approval are separate
human decisions.

## Workflow

1. Create time-limited human authorization using the existing authorization subsystem.
2. Inventory every local/lab application and its application family.
3. Validate the plan and resolve every hard blocker.
4. Create separate governed campaigns for authorized applications.
5. Confirm operator, two independent reviewers, separate adjudicator, Dataset
   Quality Auditor, Test and Verification Specialist, human release authority,
   and emergency-stop owner.
6. Execute only the existing bounded local scan path.
7. Persist only governed redacted evidence.
8. Require two independent review decisions.
9. Preserve disagreement and use only the assigned human adjudicator.
10. Complete only campaigns that satisfy existing release gates.
11. Create and verify the immutable release manifest.
12. Run the governed pilot-readiness assessment.
13. Have the Dataset Quality Auditor evaluate sample size, class balance,
    application-family diversity, scan diversity, duplicates, leakage,
    agreement, and adjudication evidence.
14. Require a separate human decision before any model training.

## Emergency stop

Stop when authorization is revoked, scope changes, sensitive data cannot be
redacted, unexpected network behavior occurs, evidence integrity fails, or a
human raises a safety concern. Preserve audit evidence and never mark stopped
work successful.

## Explicit prohibitions

During collection, do not activate connectors, scan public systems, expand
scope automatically, approve vulnerabilities automatically, adjudicate
automatically, release automatically, or train a model.
