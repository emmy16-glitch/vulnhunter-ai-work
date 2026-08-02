# Dataset Integrity, Review and ML Release Quality

**Status:** Implemented reviewed-observation controls plus binding production release standard  
**Architecture:** [`intelligence/ML_AND_HUGGING_FACE_PRODUCTION_ARCHITECTURE.md`](intelligence/ML_AND_HUGGING_FACE_PRODUCTION_ARCHITECTURE.md)  
**Governance:** [`intelligence/ML_GOVERNANCE.md`](intelligence/ML_GOVERNANCE.md)

## 1. Purpose

VulnHunter treats verified evidence and authorised human review as the source of truth.

Model predictions, advisory answers, reviewer clicks, ranking position and embedding similarity never change stored review labels automatically.

This document owns:

- observation eligibility;
- review integrity;
- duplicate and conflict handling;
- application and collection metadata;
- governed dataset release construction;
- training-package derivation;
- quality reports;
- correction, withdrawal and retention requirements.

## 2. Current review workflow

The implemented CLI supports inspection and terminal binary labels:

```bash
vulnhunter findings queue --database vulnhunter.db
vulnhunter findings show OBSERVATION_ID --database vulnhunter.db
vulnhunter findings label OBSERVATION_ID confirmed --database vulnhunter.db
vulnhunter findings label OBSERVATION_ID false_positive --database vulnhunter.db
```

The wider governed architecture additionally supports independent reviewer assignment, two-reviewer consensus and adjudication.

Production training eligibility follows the governed release, not merely the presence of a terminal-looking database field.

## 3. Authoritative review states

The data model and release policy must distinguish, where supported:

- `unreviewed`;
- assigned to first reviewer;
- first review completed;
- awaiting independent second review;
- consensus confirmed;
- consensus false positive;
- reviewer disagreement;
- awaiting adjudication;
- adjudicated confirmed;
- adjudicated false positive;
- corrected;
- withdrawn.

Only the terminal states allowed by the release policy become training labels.

## 4. Review independence

A production release must verify:

- reviewer identities are authenticated;
- required reviewers are distinct;
- reviewer assignment is recorded;
- reviewers are not prohibited by campaign conflict rules;
- adjudicator is distinct where required;
- attestations bind exact observation/evidence digests;
- review timestamps and policy versions are preserved;
- corrected evidence invalidates stale attestations.

A model operator or automated agent cannot impersonate a reviewer or generate terminal review attestations.

## 5. Model output and reviewer feedback separation

Store separately:

- authoritative review label;
- active model recommendation;
- shadow model recommendation;
- LLM advisory output;
- reviewer interaction with the recommendation;
- final consensus/adjudication outcome.

Opening, accepting, dismissing or ignoring a model suggestion is behavioural feedback, not an authoritative label.

Feedback becomes training-eligible only after the normal governed review and release process.

## 6. Current training-readiness command

```bash
vulnhunter ml readiness --database vulnhunter.db
```

The current software baseline requires:

- at least 20 unique reviewed observations;
- at least five examples for each binary class;
- at least four independent scans;
- each class in at least two scans;
- no fingerprint with conflicting labels;
- a feasible complete-scan grouped split.

These thresholds prove pipeline viability only. They are not sufficient evidence for production classification.

## 7. Production data sufficiency

Production-candidate policy must declare and enforce stronger thresholds for:

- unique reviewed observations;
- both terminal classes;
- distinct application families;
- distinct application instances;
- distinct deployment environments;
- independent scans;
- category coverage;
- detector/template coverage;
- severity coverage;
- calibration groups;
- OOD examples;
- untouched external families;
- independent reviewer participation.

There is no universal numeric threshold. The declared threshold must match the task and be justified before model evaluation.

The correct outcome for insufficient diversity is `insufficient_data`, not relaxed grouping or exaggerated claims.

## 8. Duplicate handling

The implemented preparation groups observations by fingerprint.

Repeated observations with the same fingerprint and terminal label are reduced to one canonical training example. This prevents repeated scans from inflating sample counts.

The quality report records:

- source samples;
- canonical unique samples;
- duplicates excluded;
- conflicting fingerprints;
- scans and class counts.

Production quality should additionally report duplicates by:

- application family;
- instance;
- environment;
- detector/template;
- campaign/release;
- repository revision or artifact digest.

## 9. Duplicate context is not automatic equivalence

A repeated fingerprint is review context, not proof that current evidence has the same meaning.

Reviewers must consider:

- changed application revision;
- changed deployment environment;
- changed scanner/template version;
- changed response content;
- changed authorisation;
- changed exploitability or impact context.

The canonical training record must preserve sufficient lineage to explain why examples were considered duplicates.

## 10. Conflicting labels

A fingerprint with terminal labels in both classes blocks training until resolved.

The conflict report should include safe metadata:

- fingerprint;
- observation IDs;
- application families/instances;
- assessment/scan IDs;
- review attestation IDs;
- label states;
- evidence digests;
- detector/template versions;
- correction status.

Do not resolve conflicts by majority vote without the governed adjudication process.

## 11. Application identity

Every production-eligible observation should resolve:

- `application_family_id`;
- `application_instance_id`;
- `deployment_environment_id`;
- repository ID and exact revision where applicable;
- artifact digest where applicable;
- authorisation ID;
- campaign ID;
- assessment ID;
- scan ID;
- observation ID.

### 11.1 Application family

Groups applications or benchmark variants that are substantially related and must not cross external-holdout boundaries.

### 11.2 Application instance

Identifies one concrete application/deployment lineage.

### 11.3 Deployment environment

Records meaningful configuration differences without pretending the same application is an unrelated external family.

Missing family metadata prevents production external-validation claims.

## 12. Collection metadata

Retain:

- collection timestamp;
- scanner and worker version;
- template/feed identity and digest;
- target authorisation snapshot;
- request and response policy;
- redaction policy;
- application family/instance/environment;
- repository/artifact identity;
- campaign limits;
- evidence schema;
- collection success/partial/failure state.

A partial or failed assessment may still contain useful evidence, but release eligibility must state which records are valid and why.

## 13. Evidence integrity

An eligible label binds to exact evidence.

Required checks include:

- observation fingerprint;
- evidence digest;
- assessment identity;
- source/tool receipt;
- redaction state;
- evidence schema version;
- review attestation binding;
- no mutation after review without correction workflow.

A model prediction or LLM explanation cannot substitute for missing evidence.

## 14. Privacy and prohibited fields

Training and embedding packages must exclude or safely transform:

- passwords;
- API keys and bearer tokens;
- session cookies;
- private keys;
- authentication headers;
- secret values;
- unrestricted raw response bodies;
- personal/customer data not permitted by the release;
- local file paths or ownership evidence not approved for model use.

Privacy policy is field- and task-specific. Data permitted for local review is not automatically permitted for remote Hugging Face or Groq processing.

## 15. Governed dataset release

Production training consumes an immutable governed release.

The release manifest records:

- release ID and schema version;
- campaign IDs and digests;
- authorisation snapshot digests;
- included assessments/observations;
- label ontology;
- review and adjudication attestations;
- application grouping metadata;
- collection and scanner provenance;
- duplicate/conflict report;
- redaction policy;
- exclusions and reasons;
- permitted tasks and providers;
- retention policy;
- creation and approval identities;
- manifest digest;
- correction/supersedes relationship;
- current active/withdrawn/revoked state.

## 16. Release eligibility gates

A release fails closed when:

- any included observation lacks terminal governed review;
- required reviewer independence is missing;
- evidence or attestation digest mismatches;
- unresolved conflicts remain;
- required application metadata is missing;
- prohibited fields are present;
- campaign/authorisation integrity fails;
- retention or permitted-use policy is absent;
- release manifest is not deterministic;
- included data changed after manifest construction.

## 17. Dataset release quality report

A release quality report should include:

- total included/excluded observations;
- class counts;
- application-family, instance and environment counts;
- scans per class and family;
- categories and severities;
- detector/template distribution;
- reviewer/adjudicator distribution;
- duplicate rate;
- conflict count;
- missing metadata;
- partial-assessment contribution;
- redaction/prohibited-data scan;
- grouping and split feasibility;
- known biases and gaps.

Every percentage includes raw counts.

## 18. Training dataset package

A training package is a content-addressed derivative of one or more compatible releases.

It includes:

- canonical redacted examples;
- exact release references;
- schema and dictionaries;
- grouping keys;
- excluded records and reasons;
- privacy classification;
- package generator version;
- source commit;
- deterministic digest.

The package is immutable. Regeneration with different content creates a new digest and package identity.

## 19. Export format

The current JSONL export is deterministic and owner-private.

Production packages may use JSONL, Parquet or another reviewed format, but must retain:

- explicit schema;
- bounded and validated types;
- deterministic ordering or manifest;
- no executable deserialisation;
- content hashes;
- owner/role-appropriate permissions;
- atomic writes;
- safe handling of malformed rows.

## 20. Partition eligibility

Before model selection, the package must support the required grouping.

Current baseline:

- complete scan isolation.

Production target:

- complete scan isolation;
- application-instance isolation where required;
- complete application-family isolation for external holdout;
- stable partition programme across releases.

When no feasible partition exists, quality status is blocked and explains which classes/groups are missing.

## 21. External datasets

External or Hugging Face datasets are never silently merged into governed real data.

Create a distinct source record containing:

- repository/dataset ID;
- revision or snapshot;
- official/unofficial status;
- license;
- synthetic versus human-labelled status;
- task definition;
- languages;
- grouping keys;
- duplicate/leakage analysis;
- transformations;
- approved research use.

Public datasets may support pipeline tests, representation learning or comparison benchmarks. They do not become VulnHunter's external product holdout without independent qualification.

## 22. Synthetic data

Synthetic data must remain clearly labelled.

It may support:

- schema and parser tests;
- rare error-path tests;
- benchmark harnesses;
- controlled feature experiments;
- red-team prompt or OOD tests.

It must not:

- inflate real-data sample counts;
- satisfy application-diversity gates;
- replace external family validation;
- be presented as real reviewer evidence;
- silently train production candidates without declared policy.

## 23. Temporal and revision leakage

When data volume supports it, audit:

- same repository revisions across partitions;
- near-identical commits;
- benchmark duplicates;
- scanner/template versions that encode labels;
- future information in generated titles/descriptions;
- corrections made after model evaluation;
- temporal ordering of releases.

For source-code datasets, group by repository and related commits, not only functions.

## 24. Bias and coverage

Quality reports should identify under-representation across:

- application families;
- frameworks/languages;
- deployment types;
- categories;
- severities;
- detector/template sources;
- reviewer identities;
- positive and negative classes;
- easy versus ambiguous cases.

A model may be restricted to a narrower supported domain rather than claiming universal coverage.

## 25. Corrections

A corrected review or evidence record does not mutate an existing immutable release.

Correction flow:

1. create correction record;
2. bind old/new evidence and review digests;
3. produce a superseding release;
4. identify dependent packages/models;
5. assess prediction impact;
6. retrain, degrade, rollback or revoke as required;
7. preserve historical provenance.

## 26. Withdrawal and deletion

Withdrawal policy must address:

- dataset release state;
- training package state;
- embedding index deletion;
- model impact;
- retained audit evidence;
- remote provider retention constraints;
- user/tenant deletion requirements.

A withdrawn release must not remain eligible for new production training.

## 27. Active-learning suggestions

The model may suggest high-uncertainty or coverage-gap observations for review.

Active-learning queues remain governed:

- assignments preserve reviewer separation;
- model reason is visible;
- selection cannot change labels;
- tenant boundaries remain enforced;
- one application/detector cannot dominate without policy;
- reviewed results enter training only through a later release.

## 28. Reviewer experience

Reviewers should see:

- exact observation and evidence;
- application/assessment context;
- duplicate/conflict context;
- model recommendation clearly separated;
- model/revision and reason codes when relevant;
- an easy way to disagree without accepting model framing;
- no preselected terminal label;
- no hidden pressure to match the model.

## 29. Quality commands and evidence

Current commands remain the exact implemented interface.

Future release commands should emit machine-readable reports and deterministic manifests. Documentation must not claim they exist until implemented.

Required retained evidence includes:

- release manifest;
- quality report;
- prohibited-data scan result;
- partition-feasibility report;
- reviewer/adjudication attestation summary;
- package digest;
- repository audit result.

## 30. Testing

Test:

- eligible terminal review;
- pending second review;
- disagreement/adjudication;
- duplicate same-label records;
- conflicting labels;
- evidence mutation after review;
- application metadata missing;
- family/instance grouping;
- prohibited data;
- deterministic release/package digests;
- correction and superseding release;
- withdrawal/revocation;
- external/synthetic source separation;
- reviewer-feedback not becoming labels;
- active-learning assignment controls;
- safe export permissions and atomicity.

## 31. Current-versus-target classification

```text
HUMAN REVIEW AS LABEL AUTHORITY                 IMPLEMENTED
DUPLICATE REDUCTION                             IMPLEMENTED
CONFLICTING-FINGERPRINT BLOCK                   IMPLEMENTED
SCAN AND CLASS READINESS GATES                  IMPLEMENTED
DETERMINISTIC PRIVATE JSONL EXPORT              IMPLEMENTED
INDEPENDENT REVIEW/ADJUDICATION FOUNDATIONS     IMPLEMENTED
IMMUTABLE GOVERNED RELEASE MANIFESTS            IMPLEMENTED FOUNDATION
RELEASE-BOUND ML TRAINING                       NOT COMPLETE
APPLICATION-FAMILY ML METADATA                  PARTIAL/NOT ENFORCED IN ML
PRODUCTION RELEASE QUALITY REPORT               PARTIAL
CORRECTION-TO-MODEL IMPACT GRAPH                NOT COMPLETE
EXTERNAL DATASET REGISTRY                       NOT COMPLETE
ACTIVE-LEARNING GOVERNANCE                      NOT COMPLETE
```

## 32. Definition of done

Dataset quality is production-complete for ML only when:

- every production example originates from a verified governed release;
- review independence and evidence binding are enforced;
- application family/instance/environment metadata is complete;
- duplicate/conflict reports are group-aware;
- prohibited data is excluded;
- release quality and bias/coverage reports exist;
- training packages are immutable and reproducible;
- family-isolated partitioning is feasible;
- external and synthetic data remain separately governed;
- corrections/withdrawals propagate to dependent models and indexes;
- reviewer behaviour never silently becomes a label;
- all quality, privacy and repository gates pass.