# Independent Review and Adjudication

## Purpose

Passive observations require context. A single reviewer can make an honest mistake or apply a consistent personal bias, so new manual findings use a two-person primary-review workflow with a third-person adjudication path for disagreements.

## Reviewer identities

Reviewers use stable pseudonymous IDs such as:

```text
analyst-a
analyst-b
lead-c
```

Reviewer IDs are not email addresses, credentials, or legal identities. They are normalised to lowercase and restricted to safe characters so they can be compared deterministically without storing unnecessary personal information.

## State machine

```text
unreviewed
    -> first primary decision
pending_second_review
    -> matching second decision
consensus

pending_second_review
    -> conflicting second decision
disputed
    -> independent third-person resolution
adjudicated
```

The effective observation label behaves as follows:

- after one decision: `needs_review`;
- after disagreement: `needs_review`;
- after consensus: `confirmed` or `false_positive`;
- after adjudication: `confirmed` or `false_positive`.

Only final binary labels enter the existing reviewed-data pipeline.

## Independence rules

- A reviewer may submit only one immutable primary decision per observation.
- The second primary reviewer must use a different reviewer ID.
- An adjudicator must be different from both primary reviewers.
- Matching decisions cannot be adjudicated because consensus already exists.
- A resolved case cannot receive another primary decision or adjudication.
- Legacy direct labels cannot overwrite a case that has entered independent review.

## Auditability

Primary decisions and adjudications are stored in append-only rows. The observation's existing `review_label` remains the effective compatibility field used by dataset preparation.

The review case exposes:

- reviewer IDs;
- decisions;
- redacted notes;
- timestamps;
- adjudicator ID;
- redacted rationale;
- current state;
- effective label.

## Backward compatibility

Historical labels and controlled synthetic benchmark labels remain readable as `legacy_final`. This preserves existing experiment reproducibility.

The public manual CLI no longer permits direct single-review labelling. New real observations must use:

```bash
vulnhunter findings review
vulnhunter findings second-review-queue
vulnhunter findings disputes
vulnhunter findings adjudicate
vulnhunter findings review-status
```

Internal legacy labelling remains available only for controlled benchmark compatibility and existing historical tests. It is blocked from overwriting governed review cases.

## Limitations

This milestone verifies reviewer separation through stable local identifiers, not authenticated user accounts. Identity authentication, role management, and cryptographic decision signing remain future work.
