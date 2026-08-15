# Governed Web Verification Lifecycle

This batch completes the web-verification authority path above passive browser perception and adaptive hunters without turning models or workers into security authorities.

```text
signed external evidence
  -> live authorization revalidation
  -> transactional evidence ledger
  -> durable cross-restart replay prevention
  -> strategy-specific deterministic adjudication
  -> authenticated human review
  -> final validated / rejected / inconclusive decision
  -> Assessment/task projection
```

## Authority boundaries

- AI/hunters propose hypotheses only.
- External collectors submit signed, hash-only evidence receipts.
- The lifecycle revalidates the current authorization record, exact authorization snapshot, exact target reference, and evidence collection time before persistence.
- SQLite receipt IDs are globally unique, so replay is rejected across processes and restarts.
- Deterministic strategy policy produces a candidate verdict and a ceiling on verdicts humans may choose.
- A validated candidate requires validation-grade offline artifact evidence. Read-only HTTP/browser metadata alone cannot produce a validated candidate.
- Two distinct authenticated governance identities with the `reviewer` role are required for a final decision. Disagreement requires one distinct authenticated `adjudicator`.
- Reviewers cannot be the evidence collector, target authorization owner, or target authorization approver for the same case.
- Final decisions assign no severity, publication, exploitation, or automatic-remediation authority.

## Strategy policy

The current policy is deliberately conservative:

- object authorization: offline artifact evidence;
- request integrity: offline artifact or read-only HTTP metadata;
- file upload: offline artifact or read-only browser metadata;
- authentication: offline artifact or read-only browser metadata;
- API access: offline artifact or read-only HTTP metadata.

Only `OFFLINE_ARTIFACT_REVIEW` support is validation-grade. A relevant refuting receipt can produce a rejected candidate. Conflicting support/refutation remains inconclusive.

## Broader verification workers

The worker registry broadens evidence collection through capability manifests and immutable plans, not arbitrary execution:

- `offline-artifact-verifier-v1`;
- `read-only-browser-verifier-v1`;
- `read-only-http-verifier-v1`.

Every capability and plan hard-denies mutation, credential use, authorization bypass, shell execution, and payload execution. Network-capable manifests are limited to GET/HEAD. Plans contain no command or raw scanner-argument field.

Actual worker execution remains subject to the existing OpenSandbox/release/authorization architecture. This lifecycle layer does not create a new unrestricted worker runtime.

## Persistent lifecycle

The SQLite ledger stores integrity-linked cases, admissions, signed submissions, verified receipts, adjudications, human reviews, final decisions, and append-only events. Case transitions use compare-and-swap revisions to reject stale concurrent writers.

The pre-persistence `ExternalEvidenceAdmissionBatch` continues to truthfully state `durable_replay_protection_established = false`; only the separately persisted ledger admission states durable replay protection is established after an atomic commit.

## Assessment/task projection

A verification case may bind an Assessment run/workspace. Evidence and adjudication advance the existing Active Validation graph to verification/review. A final human decision completes the review/report projection while the authoritative final verdict remains in the verification ledger.

## Still forbidden

This completion does not authorize public arbitrary scanning, brute force, credential guessing, cross-user authorization bypass, destructive form/file submission, injection payload execution, shell access, public OAST, exploit publication, automatic severity assignment, or automatic remediation/merge.
