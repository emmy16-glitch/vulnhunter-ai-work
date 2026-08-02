# VulnHunter Machine-Learning and Hugging Face Production Architecture

**Status:** Binding future implementation programme; documentation does not imply implementation  
**Owner:** VulnHunter architecture and ML governance maintainers  
**Repository:** `emmy16-glitch/vulnhunter-ai-work`  
**Created:** 2026-08-02  
**Applies to:** governed dataset releases, feature extraction, model training, model selection, calibration, abstention, out-of-distribution detection, evaluation, model registry, shadow deployment, monitoring, Hugging Face models, advisory inference, embeddings, retrieval, Source Hunt model assistance, supply-chain controls, privacy and product presentation

---

## 0. Authority, ownership and non-duplication

This document defines the target cross-layer architecture that connects VulnHunter's governed evidence and human-review system to its classical machine-learning pipeline and optional Hugging Face capabilities.

It exists because the repository already has strong individual components but does not yet have one complete production contract covering the path from an immutable governed dataset release through training, evaluation, promotion, deployment, monitoring, rollback and evidence-grounded advisory use.

This document does **not** replace the existing owners:

- `docs/intelligence/ML_GOVERNANCE.md` owns authority separation, training eligibility, promotion, revocation, accountability and governance policy;
- `docs/DATA_QUALITY.md` owns review integrity, deduplication, label conflict handling, application metadata and dataset-release quality gates;
- `docs/ML_PIPELINE.md` owns the implemented local baseline mechanics and the pluggable training/prediction contracts;
- `docs/MODEL_SELECTION.md` owns development partitions, candidate comparison, calibration selection, locked external evaluation and diagnostic reporting;
- `docs/product/AI_ROUTING.md` owns deterministic-first routing, privacy classification, provider permissions and remote-data boundaries;
- `docs/product/LLM_RUNTIME_READINESS.md` owns provider configuration, capability verification, model/revision readiness and deployed inference checks;
- `docs/intelligence/CURRENT_STATE.md` owns truthful implemented-versus-planned status;
- `docs/intelligence/ROADMAP.md` owns dependency ordering;
- this document owns the complete ML/Hugging Face system architecture and the bounded implementation programme that joins those existing contracts.

Agents must not create another document that claims to own the same end-to-end ML lifecycle, model registry, Hugging Face production policy or deployment programme. New cross-layer requirements belong here. Narrow requirements must be updated in their existing owner document at the same time.

The permanent rule is:

> A model may assist prioritisation, retrieval, explanation or hypothesis generation, but deterministic services, verified evidence and authorised human decisions remain the only sources of operational truth and authority.

No model output may authorise a target, expand scope, start a worker, change evidence, confirm a vulnerability, determine final severity, approve a finding, release a dataset, activate another model, merge code, deploy software or publish a report.

---

# 1. Verified current baseline

The repository already provides a responsible research baseline:

- human-reviewed `confirmed` and `false_positive` observations;
- duplicate reduction and conflicting-label rejection;
- complete-scan isolation between development and holdout data;
- training-only grouped cross-validation;
- Multinomial and Bernoulli Naive Bayes candidates;
- explicit decision thresholds;
- deterministic privacy-conscious feature engineering;
- JSON model artifacts rather than executable pickle artifacts;
- bounded artifact loading and strict dimension validation;
- dataset hashes, application version, feature schema and split provenance;
- controlled benchmark provenance;
- holdout diagnostics by category and scan;
- optional Groq and Hugging Face advisory providers that remain untrusted;
- exact input/output hashes and provider provenance;
- bounded remote inference, explicit model allowlists and safe abstention on failure.

These foundations must be preserved. A later transformer, embedding model, hosted endpoint or larger language model must not weaken them.

The current classifier is deliberately narrow. It estimates whether an already-produced, already-redacted, human-reviewable observation resembles the existing binary classes. It is not the autonomous intelligence layer for the complete product.

The current Hugging Face provider is also deliberately narrow. It is an optional remote advisory path. It is not the classifier, scanner, reviewer, lifecycle owner or publication authority.

---

# 2. Target system decomposition

VulnHunter must treat the following as separate systems with separate identities, artifacts, permissions, health and acceptance gates:

1. **Deterministic security platform**
   - authorisation;
   - target containment;
   - scanner execution;
   - evidence capture;
   - integrity validation;
   - lifecycle state;
   - human review and adjudication;
   - report and publication gates.

2. **Governed dataset system**
   - campaign definition;
   - application and deployment metadata;
   - review attestations;
   - conflict resolution;
   - immutable release manifests;
   - privacy classification;
   - dataset lineage.

3. **Classical ML decision-support system**
   - feature extraction;
   - candidate training;
   - calibration;
   - abstention and OOD handling;
   - locked evaluation;
   - model registry;
   - shadow and active inference;
   - drift monitoring.

4. **Hugging Face model system**
   - revision-pinned model inventory;
   - capability profiles;
   - local or remote inference backends;
   - embeddings and retrieval;
   - optional code-model experiments;
   - tokenizer and context-budget management;
   - model supply-chain verification.

5. **Conversational advisory system**
   - assessment-scoped context construction;
   - redaction and permission filtering;
   - provider-neutral invocation;
   - structured advisory output;
   - evidence citations;
   - safe abstention;
   - no lifecycle authority.

6. **Product presentation system**
   - truthful model status;
   - recommendation explanations;
   - confidence and uncertainty language;
   - reviewer feedback;
   - model provenance and limitations;
   - no fabricated or authoritative framing.

One component must never silently impersonate another. Provider health is not model quality. Model confidence is not vulnerability confidence. A prediction is not a review decision. A retrieved document is not evidence. An advisory answer is not a finding.

---

# 3. Mandatory implementation order

This programme begins only after the mandatory AI-first assessment workspace and premium interaction programmes are fully implemented, merged, tested and documented.

The product must first possess:

- one authoritative assessment identity;
- one canonical lifecycle;
- typed failure and retry;
- assessment-scoped evidence, findings and reports;
- correct phone and desktop behaviour;
- one frontend state owner backed by persisted server state;
- truthful provider, worker and assessment health.

Do not place sophisticated model outputs into contradictory product state.

After those programmes are complete, implement this programme through bounded pull requests in this order:

1. documentation and current-state reconciliation;
2. governed release-to-training boundary;
3. hierarchical application identity and group isolation;
4. richer label and task contracts;
5. pluggable feature-extractor interface;
6. expanded leakage and ablation evaluation;
7. calibration, abstention and OOD handling;
8. complete evaluation and uncertainty reporting;
9. model registry, signing, activation and rollback;
10. shadow inference and reviewer-feedback linkage;
11. monitoring, drift and incident response;
12. revision-pinned Hugging Face capability registry;
13. local embedding and retrieval experiments;
14. Source Hunt code-model experiments;
15. evidence-grounded conversational retrieval;
16. full cross-workflow production acceptance and cleanup.

Do not begin with fine-tuning a large model. Build the data, evaluation, registry and rollback foundations first.

---

# 4. Governed release-to-training contract

## 4.1 The current gap

Training from an arbitrary current database view is not sufficient for production governance, even when individual observations are reviewed.

A database can change after training. Review decisions can be corrected. Campaign membership can drift. Application metadata can be incomplete. A later query can silently produce a different set while retaining the same command.

Production training must therefore originate from an immutable governed dataset release.

## 4.2 Required lineage

The required lineage is:

```text
owned or explicitly authorised application
    -> narrow authorisation snapshot
    -> governed collection campaign
    -> bounded completed assessments
    -> two independent reviews
    -> adjudication where required
    -> immutable dataset release manifest
    -> verified ML dataset package
    -> development partitions
    -> candidate training and calibration
    -> locked external evaluation
    -> registered model artifact
```

## 4.3 Required training-release fields

Every training request must identify exactly one verified release or a declared ordered set of compatible releases.

The release input must include or resolve:

- `dataset_release_id`;
- release schema version;
- release manifest digest;
- campaign IDs;
- campaign manifest digests;
- authorisation snapshot digests;
- collection-policy version;
- exact included assessment IDs;
- exact included observation IDs or stable observation digests;
- review-attestation digests;
- adjudication-attestation digests where applicable;
- application-family metadata;
- application-instance metadata;
- deployment-environment metadata;
- source repository and revision when applicable;
- scanner, template, feed and worker identities;
- redaction policy version;
- label ontology version;
- release creation and approval identities;
- release timestamp;
- retention and permitted-use policy;
- withdrawal or revocation state.

Training must fail closed when the release cannot be reproduced, has been revoked, contains unresolved conflicts, lacks required application grouping or does not satisfy its declared usage policy.

## 4.4 Dataset package

The ML dataset package should be an immutable, content-addressed derivative of the governed release.

It must include:

- canonical redacted examples;
- a machine-readable schema;
- release and source digests;
- grouping keys;
- label and category dictionaries;
- excluded-record counts and reasons;
- conflict and duplicate reports;
- feature-eligibility metadata;
- privacy classification;
- package generator version;
- source code commit;
- deterministic package digest.

The package must not include raw secrets, credentials, cookies, private keys, unrestricted response bodies or data prohibited by the release policy.

## 4.5 Corrections and withdrawal

A corrected review must not silently mutate a released dataset.

Corrections require:

1. a new release version;
2. an explicit supersedes relationship;
3. a signed or integrity-protected correction record;
4. affected model discovery;
5. impact assessment;
6. retraining or revocation decision;
7. preserved historical provenance.

A model trained from a withdrawn release must enter `degraded`, `revoked` or `retired` status according to the impact policy. It must not continue as an unexplained active model.

---

# 5. Hierarchical application identity and leakage prevention

## 5.1 Scan isolation is necessary but insufficient

Complete-scan isolation prevents observations from one scan appearing in both development and holdout partitions. It does not prevent separate scans of the same application from crossing partitions.

The model may then memorise:

- application-specific wording;
- routes;
- deployment fingerprints;
- scanner-template behaviour;
- repeated evidence structures;
- framework-specific configuration;
- synthetic benchmark patterns.

## 5.2 Required grouping hierarchy

Every eligible example must carry stable grouping metadata where applicable:

```text
application_family_id
application_instance_id
deployment_environment_id
repository_id
repository_revision
artifact_digest
authorisation_id
campaign_id
assessment_id
scan_id
observation_id
```

Definitions:

- `application_family_id` identifies substantially related applications or benchmark variants that must not cross external evaluation boundaries;
- `application_instance_id` identifies one concrete application or deployment lineage;
- `deployment_environment_id` separates meaningful environment variants without pretending they are independent families;
- `repository_revision` or `artifact_digest` records exact source or binary identity;
- `scan_id` remains the smallest group that must never split.

## 5.3 Partition hierarchy

Use three logical partitions:

1. **Development training groups**
   - used for fitting candidate parameters.

2. **Development validation/calibration groups**
   - used for algorithm selection, threshold selection, feature selection, calibration and abstention policy.

3. **Locked external holdout groups**
   - entire application families unseen during development;
   - frozen before final design decisions;
   - evaluated once at the declared checkpoint;
   - never used to revise the same candidate programme.

When data is too small for all three, the system must say that external validation is unavailable. It must not rename an ordinary split as external validation.

## 5.4 Repeated releases

The same application family must remain assigned consistently across releases unless a documented partition reset creates a new evaluation programme.

A partition registry should record:

- programme ID;
- grouping-policy version;
- application-family assignment;
- partition assignment;
- assignment reason;
- timestamp;
- approving identity;
- superseded programme if any.

---

# 6. Label ontology and task separation

## 6.1 Preserve authoritative review labels

The authoritative human-review labels remain separate from model outputs.

At minimum, persisted review state must distinguish:

- unreviewed;
- awaiting second review;
- review disagreement;
- awaiting adjudication;
- confirmed;
- false positive;
- withdrawn or corrected where supported.

The binary model may train only on eligible terminal labels under the release policy.

## 6.2 Do not overload one classifier

The following are different tasks and must use separate contracts, datasets and metrics:

- confirmed-versus-false-positive prioritisation;
- vulnerability category classification;
- severity assistance;
- duplicate or related-finding retrieval;
- evidence-quality scoring;
- remediation retrieval;
- source-code vulnerability candidate retrieval;
- natural-language summarisation;
- report drafting.

A single output called `confidence` must not represent all of them.

## 6.3 Recommended prediction contract

The decision-support prediction should eventually expose:

```json
{
  "model_id": "...",
  "model_version": "...",
  "task": "review_priority",
  "positive_probability_raw": 0.0,
  "positive_probability_calibrated": 0.0,
  "uncertainty": 0.0,
  "out_of_distribution_score": 0.0,
  "decision": "prioritise_review | normal_review | abstain",
  "reason_codes": [],
  "feature_coverage": 0.0,
  "input_schema_version": "...",
  "created_at": "..."
}
```

This object is advisory. It must never overwrite `review_label`.

## 6.4 Reviewer-facing language

Prefer:

- `Suggested review priority`;
- `Model estimate`;
- `The model abstained`;
- `Unfamiliar application or evidence pattern`;
- `Requires human review`.

Do not use:

- `AI verified`;
- `Definitely vulnerable`;
- `Safe`;
- `Automatically confirmed`;
- `Model-approved`;
- `No vulnerability` when the model only predicted a false-positive-like pattern.

---

# 7. Feature architecture and leakage control

## 7.1 Existing feature baseline

The current privacy-conscious features are an appropriate baseline:

- severity and category indicators;
- bounded redacted title/description vocabulary;
- structural URL features;
- bounded evidence counts;
- response status families;
- selected missing-header and debug indicators;
- selected directory-index context.

## 7.2 Feature-source registry

Every feature must have registered metadata:

- feature name;
- schema version;
- source field;
- deterministic transformation;
- privacy classification;
- allowed tasks;
- missing-value behaviour;
- expected range;
- leakage risk;
- stability expectation;
- deprecation state.

Unknown feature names must fail closed when loading a model artifact.

## 7.3 Detector leakage

Category, severity, title and generated description may encode the scanner's own conclusion. The model could learn detector identity rather than evidence quality.

Required ablations include:

1. structural evidence only;
2. no category;
3. no severity;
4. no title or description tokens;
5. no detector-generated text;
6. leave-one-category-out;
7. leave-one-detector-out;
8. leave-one-template-family-out;
9. leave-one-application-family-out;
10. time-based or release-based evaluation where enough data exists.

A feature family that improves random or scan-group validation but harms application-family generalisation should not be promoted.

## 7.4 Feature stability

The model must detect and report:

- unknown category;
- unknown detector;
- unknown template revision;
- evidence schema mismatch;
- token coverage below threshold;
- missing expected fields;
- values outside training range;
- unseen application family;
- unsupported feature schema.

These signals feed OOD and abstention policy.

## 7.5 Transformer and embedding features

A future Hugging Face encoder must be wrapped behind a feature-extractor interface.

The interface must expose:

- extractor ID and version;
- model repository ID;
- exact revision or commit;
- tokenizer repository and revision;
- license and usage approval;
- input schema and redaction policy;
- maximum bytes and tokens;
- pooling or output method;
- embedding dimension;
- normalisation policy;
- deterministic settings;
- device and numerical precision;
- artifact and dependency digests;
- offline/cache behaviour.

A transformer encoder must not become a hidden replacement for the baseline. It is a candidate feature source evaluated under the same governance.

---

# 8. Calibration, abstention and uncertainty

## 8.1 Raw posterior is not calibrated confidence

The current Naive Bayes posterior is useful for ranking and thresholding, but it must not be presented as a real-world probability without calibration evidence.

## 8.2 Calibration requirements

Candidate evaluation must report:

- Brier score;
- log loss where numerically safe;
- expected calibration error;
- maximum calibration error;
- reliability buckets;
- calibration slope and intercept where applicable;
- calibration by category;
- calibration by application family;
- calibration by severity;
- calibration confidence intervals when sample size supports them.

Calibration methods may include Platt scaling, isotonic regression or another justified bounded method. Method selection must use development data only.

The calibration artifact must be versioned separately and bound to the exact base model artifact.

## 8.3 Explicit abstention

The production decision contract must support `abstain`.

Abstention may be triggered by:

- calibrated probability near the uncertainty region;
- high OOD score;
- unknown category or detector;
- low token or feature coverage;
- evidence schema mismatch;
- missing required context;
- model artifact degradation;
- revoked training release;
- unsupported application family;
- disagreement between approved candidate models where ensemble policy exists;
- runtime numerical or dependency failure.

An abstention routes to normal or elevated human review. It is not an error and must not be converted to `false_positive`.

## 8.4 Coverage-risk policy

Evaluate the trade-off between:

- percentage of observations receiving a model recommendation;
- error rate among those recommendations;
- false-negative rate;
- reviewer workload;
- category and family coverage.

Promotion policy must specify the acceptable coverage-risk point rather than maximising coverage at any cost.

## 8.5 Reason codes

Reason codes must be deterministic and safe to expose, for example:

- `LOW_CALIBRATED_MARGIN`;
- `UNSEEN_APPLICATION_FAMILY`;
- `UNKNOWN_CATEGORY`;
- `UNKNOWN_DETECTOR_REVISION`;
- `LOW_FEATURE_COVERAGE`;
- `EVIDENCE_SCHEMA_MISMATCH`;
- `MODEL_DEGRADED`;
- `TRAINING_RELEASE_REVOKED`;
- `CALIBRATOR_UNAVAILABLE`.

Do not invent natural-language explanations from hidden model reasoning and present them as causal truth.

---

# 9. Out-of-distribution detection

## 9.1 Purpose

OOD handling identifies inputs that differ materially from the model's validated domain. It does not prove that an input is vulnerable or safe.

## 9.2 Baseline OOD signals

Start with deterministic signals before complex learned detectors:

- unseen application family;
- unseen category;
- unseen detector or template family;
- feature missingness;
- feature value range violations;
- token coverage;
- embedding distance to development groups;
- evidence-schema version mismatch;
- source language or artifact type outside the approved set.

## 9.3 OOD artifact

The OOD policy must be versioned and bound to:

- model ID and version;
- feature extractor;
- training release;
- threshold-selection dataset;
- thresholds;
- metrics;
- supported domain declaration.

## 9.4 OOD acceptance

Test OOD behaviour with intentionally excluded:

- application families;
- scanner categories;
- template revisions;
- source languages;
- evidence schemas;
- synthetic malformed inputs.

The expected result is safe abstention, not an arbitrary negative classification.

---

# 10. Evaluation framework

## 10.1 Core classification metrics

Report at least:

- true positive;
- false positive;
- true negative;
- false negative;
- accuracy;
- precision;
- recall;
- F1;
- specificity;
- balanced accuracy;
- Matthews correlation coefficient when supported;
- PR-AUC;
- ROC-AUC only with appropriate caveats.

## 10.2 Review-prioritisation metrics

Because the product assists review ordering, report:

- precision at K;
- recall at K;
- recall under fixed review budgets;
- average precision;
- number needed to review for one confirmed finding;
- false negatives by severity and category;
- reviewer time saved only when measured from real tasks;
- workload reduction at declared abstention coverage.

## 10.3 Generalisation slices

Report by:

- application family;
- application instance;
- deployment environment;
- category;
- severity;
- detector;
- template family and revision;
- scanner/worker version;
- campaign and dataset release;
- source language for code tasks;
- artifact type;
- known versus unseen domain.

Do not report a slice metric without its sample count.

## 10.4 Repetition and uncertainty

Evaluate:

- multiple random seeds;
- repeated grouped partitions during development where allowed;
- bootstrap intervals over appropriate groups;
- sensitivity to threshold and calibration choices;
- model stability across releases;
- confidence intervals grouped by application family, not only observations.

## 10.5 Locked external holdout

The external holdout is evaluated only after:

- features are frozen;
- candidate family is frozen;
- hyperparameters are frozen;
- calibration is frozen;
- OOD policy is frozen;
- abstention thresholds are frozen;
- intended-use and acceptance criteria are signed off.

After evaluation, any material design change creates a new programme and requires a new untouched external holdout or an honestly declared exploratory cycle.

## 10.6 Error analysis

Every candidate report must include:

- individual redacted false negatives;
- individual redacted false positives;
- dominant error clusters;
- category and family failures;
- detector leakage findings;
- OOD failures;
- calibration failures;
- known limitations;
- recommended collection targets;
- explicit reasons not to promote when gates fail.

---

# 11. Model registry and lifecycle

## 11.1 Registry states

Use explicit immutable transitions:

```text
research
    -> candidate
    -> validated
    -> approved
    -> shadow
    -> active
    -> degraded
    -> retired
    -> revoked
```

Not every transition is linear. A candidate may be rejected. An active model may become degraded or revoked. A retired model remains inspectable.

## 11.2 Required registry fields

Each registry entry must record:

- model ID;
- semantic or monotonic version;
- task;
- model artifact digest;
- calibration artifact digest;
- OOD policy digest;
- feature schema digest;
- feature-extractor ID and digest;
- training dataset release IDs and digests;
- application-family partition programme;
- training code commit;
- application version;
- dependency lock digest;
- container or environment digest where used;
- random seeds;
- candidate selection report;
- locked evaluation report;
- intended use;
- prohibited use;
- limitations;
- approval identities and attestations;
- activation timestamp;
- rollback target;
- monitoring policy;
- current lifecycle state;
- retirement or revocation reason.

## 11.3 Authority separation

Separate roles should exist for:

- dataset release approval;
- model training operator;
- model evaluation reviewer;
- model promotion approver;
- deployment operator;
- incident/revocation authority.

One unattended agent must not collect data, assign labels, train, evaluate, approve and activate the same model without independent human controls.

## 11.4 Activation

Activation must be an explicit command or service operation that:

1. verifies registry state;
2. verifies all artifact digests;
3. verifies signatures or attestations where configured;
4. verifies deployment compatibility;
5. confirms the rollback target;
6. records the active revision atomically;
7. emits an audit event.

Copying a model file into a directory must not silently activate it.

## 11.5 Rollback

Rollback must be tested before activation and must restore:

- previous model artifact;
- previous calibration artifact;
- previous OOD policy;
- previous feature schema and extractor;
- previous routing configuration;
- monitoring references.

Rollback must not rewrite historical prediction provenance.

---

# 12. Artifact authenticity and supply-chain controls

## 12.1 Model artifacts

Keep non-executable model formats where feasible. For transformer ecosystems:

- prefer `safetensors` over pickle-based weights;
- disable unreviewed remote custom code;
- pin repository and exact revision;
- verify expected file digests;
- record license and model card;
- scan dependencies and model files;
- retain a manifest of downloaded artifacts;
- use an approved cache with controlled permissions;
- operate offline after controlled acquisition where possible.

## 12.2 Tokenizers and custom code

Tokenizer code and configuration are part of the model supply chain.

Record and verify:

- tokenizer repo and revision;
- tokenizer files and digests;
- special-token configuration;
- maximum sequence length;
- normalisation behaviour;
- whether remote code is required;
- approved library versions.

`trust_remote_code=True` must be prohibited by default. An exception requires code review, sandboxing, exact revision pinning and explicit approval.

## 12.3 Software bill of materials

Each deployable model package should include an SBOM or equivalent manifest covering:

- Python packages;
- native libraries;
- model files;
- tokenizer files;
- runtime image;
- hardware/runtime assumptions;
- licenses.

## 12.4 Signing and attestation

The architecture should support signatures or attestations for:

- dataset releases;
- training runs;
- evaluation reports;
- model packages;
- activation events;
- rollback events.

Unsigned operation may remain acceptable in local research mode, but production status must expose that trust limitation clearly.

---

# 13. Experiment tracking and reproducibility

## 13.1 Experiment record

Every experiment must have a stable ID and record:

- hypothesis;
- candidate description;
- source commit;
- dataset release;
- partition programme;
- feature extractor;
- candidate configuration;
- calibration method;
- OOD policy;
- seeds;
- environment;
- start/end timestamps;
- metrics;
- artifacts;
- logs;
- failure reason;
- keep/reject decision;
- reviewer.

## 13.2 Tracking implementation

The first implementation may remain repository-local and deterministic. Hugging Face Trackio or another experiment tracker may be evaluated later, but it must not become the sole provenance store.

The durable registry and immutable artifacts remain authoritative. A dashboard is a view, not the source of truth.

## 13.3 Reproducibility command

Provide a command that can:

1. verify the release package;
2. reconstruct the environment;
3. rerun feature extraction;
4. rerun training with declared seeds;
5. reproduce development metrics;
6. verify artifact digests;
7. avoid touching the locked external holdout unless explicitly authorised.

---

# 14. Shadow deployment, canary and rollback

## 14.1 Shadow-first rule

A newly approved model enters shadow mode before it affects reviewer ordering or product recommendations.

For each eligible observation:

```text
authoritative observation
    -> active model prediction
    -> shadow candidate prediction
    -> no user-visible candidate action
    -> later human review label
    -> comparative evaluation
```

## 14.2 Shadow requirements

Shadow inference must:

- use the same redacted input contract;
- preserve active and shadow provenance separately;
- never change product state;
- avoid doubling remote sensitive-data exposure;
- respect rate and compute budgets;
- fail independently;
- record disagreement and abstention;
- join later to authoritative review outcomes.

## 14.3 Canary

A canary recommendation phase may follow shadow validation.

Canary activation requires:

- declared reviewer cohort;
- bounded traffic percentage or task scope;
- easy disable switch;
- rollback target;
- monitored acceptance metrics;
- no automatic expansion.

## 14.4 Promotion gates

Promotion from shadow/canary to active requires:

- no unresolved integrity failure;
- acceptable external holdout performance;
- acceptable calibration;
- acceptable OOD and abstention behaviour;
- no critical family/category regression;
- acceptable latency and resource use;
- privacy and supply-chain approval;
- documented reviewer impact;
- human approval.

---

# 15. Monitoring and drift

## 15.1 Distinguish system health dimensions

Monitor separately:

- inference service health;
- model artifact health;
- feature-extractor health;
- input data quality;
- prediction distribution;
- calibration and outcome quality;
- Hugging Face provider health;
- assessment lifecycle health.

A reachable endpoint does not mean the model is good. A healthy model does not mean the worker is available.

## 15.2 Operational metrics

Record bounded metrics such as:

- prediction count;
- latency distribution;
- failure count and type;
- abstention rate;
- OOD rate;
- unknown-category rate;
- unknown-detector rate;
- feature missingness;
- token/feature coverage;
- score distribution;
- active-versus-shadow disagreement;
- reviewer override/disagreement rate;
- label delay;
- model and feature revisions;
- provider rate-limit and timeout rates.

Do not log secret-bearing raw evidence.

## 15.3 Drift

Evaluate drift by appropriate groups:

- application family mix;
- category mix;
- severity mix;
- detector/template mix;
- feature distributions;
- embedding distributions;
- calibrated probability distribution;
- abstention reasons;
- reviewer outcomes.

Drift alerts are diagnostic. They do not automatically retrain or activate a model.

## 15.4 Delayed labels

Human outcomes arrive after predictions. Monitoring must support delayed joins and distinguish:

- predictions awaiting review;
- predictions with first review only;
- predictions with consensus;
- predictions after adjudication;
- corrected or withdrawn labels.

## 15.5 Incident response

Define incidents for:

- corrupted model artifact;
- revoked dataset release;
- supply-chain compromise;
- unexpected data exposure;
- severe calibration failure;
- critical false-negative cluster;
- model/provider identity mismatch;
- cross-tenant retrieval;
- repeated unsafe advisory output.

Response may include disabling recommendations, falling back to baseline, revoking a model, disabling a provider and preserving forensic artifacts.

---

# 16. Reviewer feedback loop

## 16.1 Feedback is not an immediate training label

A reviewer interaction becomes training-eligible only through the existing governed review and release process.

Button clicks, dismissal, acceptance or ordering behaviour must not silently become ground truth.

## 16.2 Feedback records

The product may capture:

- prediction shown;
- model/revision;
- reason codes;
- reviewer identity and role;
- first review;
- second review;
- adjudication;
- time to decision;
- whether the recommendation affected ordering;
- optional structured disagreement reason.

## 16.3 Active learning

Active-learning suggestions may propose observations for review based on uncertainty, disagreement or coverage gaps.

They must not:

- change labels;
- bypass assignment separation;
- repeatedly over-sample one user or application without policy;
- expose private data across tenants;
- become an autonomous collection loop.

---

# 17. Hugging Face model and capability registry

## 17.1 Why model-name allowlists are insufficient

A model repository ID alone is mutable. Runtime behaviour can change through model revision, tokenizer files, provider backend or dependency changes.

Every approved Hugging Face configuration must identify:

- repository ID;
- exact revision or commit SHA;
- model task;
- model architecture/class;
- tokenizer repository and revision;
- approved files and digests where locally downloaded;
- license and usage approval;
- inference backend/provider;
- context limit;
- maximum approved input and output;
- structured-output capability;
- streaming capability;
- tool/function capability, normally disabled;
- reasoning-parameter support;
- quantisation and precision;
- data residency/endpoint classification;
- model card review timestamp;
- capability verification timestamp;
- approved use cases;
- prohibited use cases;
- retirement/revocation state.

## 17.2 Provider health model

Use separate states:

- configured;
- credential file valid;
- model approved;
- capability profile valid;
- endpoint reachable;
- harmless end-to-end invocation verified;
- last successful invocation;
- last failure type;
- degraded;
- disabled.

Do not report `reachable=true` merely because configuration exists.

## 17.3 Capability testing

Before activation, verify the exact model/revision/backend combination for:

- authentication;
- model identity;
- structured JSON output;
- maximum context handling;
- cancellation;
- timeout;
- rate limiting;
- malformed output;
- provider error redaction;
- deterministic fallback;
- response-size limits;
- supported request parameters.

Unsupported parameters must be omitted based on the capability profile, not sent optimistically to every model.

## 17.4 Candidate inventory

The following are research starting points only, not pre-approved production choices:

### Code representation

- `microsoft/codebert-base`;
- `microsoft/graphcodebert-base`;
- `microsoft/unixcoder-base`;
- `jinaai/jina-embeddings-v2-base-code`.

### General or multilingual retrieval

- `sentence-transformers/all-MiniLM-L6-v2`;
- `ibm-granite/granite-embedding-107m-multilingual`;
- `Qwen/Qwen3-Embedding-0.6B`.

Every experiment must pin an exact revision and review current license, model card, dependencies, memory, latency and supported languages. Popularity or download count is not an approval criterion.

---

# 18. Tokenisation, context and inference budgets

## 18.1 Separate security limits

Maintain both:

- byte limits for transport and memory safety;
- model-specific token limits for inference correctness and cost.

Do not replace byte limits with token limits.

## 18.2 Token accounting

Prefer, in order:

1. revision-pinned local tokenizer matching the approved model;
2. provider-reported token accounting validated against limits;
3. a documented conservative approximation when neither is available.

The chosen method must be part of the capability profile.

## 18.3 Truncation

Truncation must be explicit and structure-aware.

For assessment evidence:

- preserve assessment identity;
- preserve user question;
- preserve selected evidence citations;
- preserve constraints and authority boundaries;
- prefer removing low-priority history over silently cutting evidence mid-record.

The response provenance must indicate when input was truncated or summarised.

## 18.4 Resource budgets

Define per task:

- maximum input bytes;
- maximum input tokens;
- maximum output bytes;
- maximum output tokens;
- timeout;
- concurrency;
- retry count;
- total model calls;
- embedding batch size;
- cache size;
- CPU/GPU memory ceiling.

---

# 19. Streaming advisory responses

## 19.1 Streaming is optional

The non-streaming bounded provider remains valid. Streaming should be introduced only when it improves the conversation experience and the exact model/backend supports it.

## 19.2 Required streaming controls

A streaming adapter must support:

- exact invocation identity;
- bounded cumulative bytes and tokens;
- cancellation;
- connection and read timeouts;
- incremental UTF-8 safety;
- no redirect following;
- safe provider errors;
- partial-output marking;
- final structured-output validation;
- final output digest;
- no action execution from partial text;
- recovery when the stream ends unexpectedly.

## 19.3 Product presentation

Partial text may be displayed as advisory prose, but it must not expose an unvalidated finding, approval, lifecycle state or report status.

When final structured validation fails, the persisted result becomes `ABSTAIN` or a typed degraded response. The UI must not retain partial text as a successful authoritative answer.

---

# 20. Embeddings and retrieval architecture

## 20.1 Valid uses

Embeddings may assist:

- duplicate and related-finding retrieval;
- similar evidence retrieval;
- remediation retrieval;
- internal documentation retrieval;
- code-search candidates;
- clustering for reviewer triage;
- assessment-scoped conversational grounding.

Embeddings do not establish vulnerability truth.

## 20.2 Index boundaries

Every vector record must include enforceable metadata:

- tenant/workspace identity;
- assessment identity;
- evidence or finding identity;
- source digest;
- redaction policy;
- visibility and role policy;
- embedding model ID/revision;
- embedding timestamp;
- deletion/retention state.

Retrieval must apply permission and assessment filters before results are returned. Post-filtering a global unrestricted result set is not sufficient when it can leak similarity information.

## 20.3 Local-first policy

Assessment evidence and private source embeddings should remain local by default.

Remote embedding requires:

- explicit approved provider/model;
- privacy classification;
- source-processing approval where required;
- retention and terms review;
- redaction;
- bounded input;
- exact provenance.

## 20.4 Index consistency

The index must detect:

- source deletion;
- source correction;
- model revision change;
- embedding dimension change;
- permission change;
- assessment reassignment;
- stale vectors.

A stale index must not silently serve results as current.

## 20.5 Retrieval evaluation

Evaluate:

- recall at K;
- precision at K;
- mean reciprocal rank;
- duplicate retrieval accuracy;
- cross-family generalisation;
- permission filtering;
- stale-record removal;
- malicious prompt/evidence injection;
- latency and memory.

---

# 21. Evidence-grounded conversational advisory

## 21.1 Context construction

The conversation provider should receive a bounded context package containing only authorised, relevant and redacted records.

A context record must expose:

- assessment ID;
- evidence/finding/report object ID;
- source type;
- stable digest;
- safe excerpt;
- visibility;
- citation label;
- lifecycle status;
- verification/review status.

## 21.2 Citations

Advisory answers that make assessment-specific factual statements should cite the supplied context record IDs.

The application must verify that cited IDs:

- were included in the prompt;
- belong to the selected assessment;
- remain visible to the user;
- retain the same digest;
- are not invented.

Unsupported citations are rejected or clearly marked unsupported.

## 21.3 Prompt injection defence

Retrieved evidence, source comments and documents are untrusted data.

The context broker must:

- separate instructions from evidence;
- label untrusted content;
- avoid concatenating unrestricted files;
- enforce maximum records and bytes;
- prevent retrieved text from altering authority rules;
- test common injection patterns;
- preserve deterministic action routing outside the model.

## 21.4 No hidden action bridge

The advisory provider receives no scanner, shell, browser, GitHub, connector or publication tools through this path.

A user-visible action proposed in prose must still pass through deterministic intent routing, current state validation and explicit approval.

---

# 22. Source Hunt and code-model experiments

## 22.1 Separate task

Source Hunt code analysis is not the same task as observation triage.

Code models may assist:

- code and symbol retrieval;
- attack-surface ranking;
- related-code search;
- candidate vulnerability classification;
- remediation example retrieval;
- natural-language explanation.

Each requires its own dataset and evaluation.

## 22.2 Exact source identity

Every code-model input must remain bound to:

- repository ID;
- exact revision;
- snapshot digest;
- permitted paths;
- exact source-file digest;
- line range;
- source-processing approval;
- model/revision;
- prompt/context digest.

Returned file paths and line ranges must be verified against the supplied snapshot.

## 22.3 Code embedding experiments

Candidate encoders may be evaluated for retrieval, but must be compared against deterministic lexical and graph baselines.

Report:

- retrieval recall at K;
- exact-file and symbol retrieval;
- vulnerable-function retrieval;
- cross-repository generalisation;
- language coverage;
- latency and memory;
- impact of truncation;
- false-neighbour analysis.

## 22.4 Vulnerability datasets

Public datasets such as BigVul mirrors, CodeXGLUE defect detection and synthetic secure/insecure code pairs may be used only for pipeline tests, pretraining experiments or comparison benchmarks under their licenses and quality limitations.

They do not prove performance on VulnHunter's governed real applications.

Required dataset review includes:

- official versus unofficial source;
- license;
- synthetic versus human-labelled status;
- duplicate and repository leakage;
- vulnerability-label quality;
- temporal leakage;
- commit and function grouping;
- language distribution;
- intended task mismatch.

---

# 23. Privacy, tenant isolation and retention

## 23.1 Data classes

Classify model inputs as:

- public product documentation;
- internal non-sensitive metadata;
- redacted assessment evidence;
- customer/private target evidence;
- source code;
- credentials/secrets/prohibited data.

Each class has explicit local/remote routing policy.

## 23.2 Tenant isolation

Model features, caches, indexes, prompts, logs and monitoring records must preserve tenant/workspace boundaries.

Tests must prove:

- one tenant cannot retrieve another tenant's vectors;
- one assessment cannot cite another without authorised global-index behaviour;
- cache keys include required identity and revision fields;
- redacted errors do not expose inputs;
- model monitoring cannot reconstruct private evidence.

## 23.3 Retention

Define retention separately for:

- dataset releases;
- training packages;
- model artifacts;
- prompts;
- provider responses;
- embeddings;
- prediction records;
- monitoring aggregates;
- debug logs.

Deletion or legal withdrawal must propagate to indexes and affect model governance where required, while preserving permitted audit evidence.

---

# 24. ML and LLM threat model

## 24.1 Data poisoning

Defences include:

- governed releases;
- independent review;
- conflict detection;
- reviewer separation;
- application diversity checks;
- outlier and duplicate reporting;
- release approval;
- dataset lineage;
- correction and revocation.

## 24.2 Label leakage and benchmark contamination

Defences include:

- application-family grouping;
- release partition registry;
- fold-local feature learning;
- external holdout lock;
- benchmark source tracking;
- no repeated tuning against external holdout.

## 24.3 Model supply-chain compromise

Defences include:

- revision pinning;
- safe artifact formats;
- digest verification;
- remote-code prohibition;
- dependency locking;
- SBOM;
- sandboxed acquisition and testing;
- model registry approval;
- rollback and revocation.

## 24.4 Prompt injection

Defences include:

- instruction/evidence separation;
- bounded context;
- no model tools;
- deterministic action routing;
- citation validation;
- output schema validation;
- adversarial tests.

## 24.5 Model extraction and sensitive logging

Use bounded outputs, authentication, rate limits, no raw secret logs, safe errors and appropriate cache controls. Do not expose full model artifacts or private training examples through product diagnostics.

## 24.6 Denial of service

Enforce byte/token limits, concurrency, timeouts, batch limits, queue budgets, cache ceilings, cancellation and worker isolation.

---

# 25. Service and API contracts

## 25.1 Feature extraction

A feature-extraction request should identify:

- task;
- input schema;
- redacted input digest;
- extractor ID/version;
- model/tokenizer revision where applicable;
- limits;
- cancellation token;
- output schema.

The response should include:

- feature/embedding digest;
- feature coverage;
- unknown/missing indicators;
- duration;
- extractor provenance;
- typed failure.

## 25.2 Prediction

A prediction request must identify:

- model registry ID/version;
- task;
- input digest;
- assessment/observation identity;
- feature schema;
- request timestamp;
- caller purpose.

The response includes raw score, calibrated score, OOD score, decision, reason codes and full model provenance.

## 25.3 Registry commands

Required operations include:

- register candidate;
- verify artifacts;
- request evaluation;
- approve/reject;
- enter shadow;
- compare shadow;
- activate;
- degrade;
- rollback;
- retire;
- revoke;
- inspect lineage.

All mutating operations require authorisation and audit records.

## 25.4 Provider invocation

The provider-neutral contract must identify:

- provider;
- approved model profile;
- exact model revision when available;
- task;
- prompt template version;
- redaction policy;
- input/output limits;
- structured output schema;
- cancellation and timeout;
- data classification;
- approval reference for source processing.

---

# 26. Product experience requirements

## 26.1 Model information hierarchy

Show ordinary task language first:

- `Suggested review priority`;
- `Why this was prioritised`;
- `The model abstained`;
- `Human review required`.

Technical detail may include:

- model ID/version;
- training-release digest;
- calibrated probability;
- OOD reason;
- feature coverage;
- prediction timestamp;
- limitations.

## 26.2 Separate health

The UI must distinguish:

- provider configured/reachable;
- model active/degraded;
- feature extractor available;
- assessment worker state;
- prediction available;
- human review state.

## 26.3 No fake explanation

Reason codes and visible feature contributions may be shown when they are derived deterministically. Free-form LLM explanations must be labelled advisory and cited to supplied evidence.

## 26.4 Failure and recovery

Typed states include:

- model unavailable;
- model degraded;
- incompatible feature schema;
- calibrator unavailable;
- OOD abstention;
- provider timeout;
- capability mismatch;
- privacy routing denied;
- source approval required;
- retrieval unavailable;
- stale index;
- registry integrity failure.

Every state explains whether the user can continue without AI. Deterministic and human workflows must continue wherever safe.

---

# 27. Testing and acceptance matrix

## 27.1 Dataset and release

Test:

- valid governed release;
- missing review attestation;
- unresolved conflict;
- revoked release;
- corrected release;
- duplicate examples;
- incompatible label ontology;
- missing application-family metadata;
- deterministic package digest;
- prohibited data exclusion.

## 27.2 Splitting

Test:

- no scan crosses partitions;
- no application instance crosses prohibited partitions;
- no application family crosses external holdout boundary;
- infeasible split fails honestly;
- stable partition assignment;
- release updates preserve grouping;
- synthetic benchmark family isolation.

## 27.3 Features

Test:

- train-only vocabulary;
- unknown category;
- missing evidence fields;
- range violations;
- schema mismatch;
- deterministic output;
- redaction;
- tokenizer revision mismatch;
- remote-code disabled;
- embedding dimension mismatch.

## 27.4 Models

Test:

- baseline reproducibility;
- candidate comparison;
- calibration artifact binding;
- abstention;
- OOD;
- no label mutation;
- malformed artifact;
- oversized artifact;
- revoked release impact;
- multiple seeds;
- family/category diagnostics.

## 27.5 Registry

Test:

- invalid transition;
- missing approval;
- digest mismatch;
- activation atomicity;
- rollback;
- concurrent activation;
- degraded and revoked state;
- historical provenance preservation;
- active model reconstruction after restart.

## 27.6 Shadow and monitoring

Test:

- active and shadow isolation;
- no shadow UI effect;
- delayed label join;
- disagreement metrics;
- drift signals;
- no raw private evidence in metrics;
- disable and incident paths.

## 27.7 Hugging Face provider

Test exact approved profiles for:

- configuration without reachability;
- credential permissions;
- revision/model mismatch;
- unsupported parameters;
- structured output;
- malformed response;
- timeout;
- cancellation;
- rate limit;
- response-size limit;
- safe error redaction;
- streaming interruption where enabled;
- token budget;
- deterministic fallback;
- provider/model provenance.

## 27.8 Retrieval

Test:

- assessment-scoped retrieval;
- tenant isolation;
- permission changes;
- stale source deletion;
- model revision reindex;
- malicious text injection;
- citation validation;
- invented citations;
- retrieval quality metrics;
- local/remote privacy routing.

## 27.9 Full product acceptance

Run:

```text
governed campaign
    -> reviewed release
    -> training package
    -> baseline and candidate training
    -> calibration/OOD
    -> locked evaluation
    -> registry
    -> shadow
    -> human approval
    -> active prediction
    -> reviewer decision
    -> monitoring
    -> rollback
```

Also run:

```text
authorised assessment
    -> evidence
    -> scoped retrieval
    -> Hugging Face advisory answer
    -> verified citations
    -> no lifecycle authority
    -> provider failure fallback
```

---

# 28. Detailed implementation slices

## Slice 1 — Documentation and current-state reconciliation

- reconcile Groq-only language with the existing optional Hugging Face provider;
- index this architecture;
- clarify owner documents;
- classify every described capability as implemented, partial, planned or research-only;
- add repository-audit checks for required ML documents and contradictions.

## Slice 2 — Governed release-to-training input

- define release package schema;
- require verified release identity for production-mode training;
- retain explicit research-mode dataset input with truthful lab-only status;
- add release revocation and correction handling;
- add provenance fields to model artifacts.

## Slice 3 — Application-family identity and partitions

- add application family/instance/environment keys;
- create partition programme registry;
- implement family-isolated development and external holdout;
- migrate compatible historical benchmark metadata;
- fail closed when grouping is absent for production claims.

## Slice 4 — Task and label contracts

- separate review-priority prediction from review label;
- introduce advisory decision and reason-code schema;
- preserve binary baseline compatibility;
- add explicit abstention state;
- update CLI/API/UI language.

## Slice 5 — Pluggable feature extractors

- wrap current deterministic features as one extractor;
- define extractor manifest;
- bind feature artifacts to inputs and schemas;
- add candidate local embedding extractor behind an optional dependency;
- preserve offline baseline operation.

## Slice 6 — Leakage and ablation suite

- add no-category/no-severity/no-text baselines;
- leave-one-detector/template/family-out diagnostics;
- feature coverage and unknown indicators;
- report sample counts and confidence intervals;
- reject candidates dependent on obvious leakage.

## Slice 7 — Calibration, abstention and OOD

- add calibration partition policy;
- implement calibration metrics and artifacts;
- implement deterministic baseline OOD signals;
- add coverage-risk report;
- integrate abstention into prediction contract.

## Slice 8 — Expanded evaluation

- PR-AUC, precision/recall at K and review-budget metrics;
- family/category/detector slices;
- severity-weighted false-negative analysis;
- grouped confidence intervals;
- multiple seeds;
- locked external evaluation command and report.

## Slice 9 — Model registry and artifact verification

- immutable registry entries and states;
- activation approvals;
- artifact/calibrator/OOD digests;
- activation atomicity;
- rollback and revocation;
- inspectable lineage UI/CLI.

## Slice 10 — Shadow inference and feedback linkage

- active/shadow prediction records;
- no shadow product effect;
- delayed join to consensus/adjudicated labels;
- disagreement and reviewer-impact reporting;
- bounded canary support.

## Slice 11 — Monitoring and incident response

- operational metrics;
- prediction and OOD distributions;
- delayed outcome quality;
- drift reports;
- incident classification;
- model disable/degrade/revoke procedures;
- privacy-safe monitoring storage.

## Slice 12 — Hugging Face capability registry

- revision-pinned profiles;
- tokenizer and parameter capability metadata;
- configured versus reachable state;
- exact harmless capability verification;
- model/provider mismatch handling;
- license and supply-chain fields.

## Slice 13 — Embedding retrieval experiment

- select one small approved local candidate and deterministic baseline;
- assessment-scoped vector schema;
- tenant and permission filters;
- duplicate/evidence retrieval benchmark;
- stale-index and revision handling;
- no remote private embedding by default.

## Slice 14 — Source Hunt code-model experiment

- exact repository snapshot binding;
- code retrieval benchmark;
- candidate encoder comparison;
- lexical/graph baseline;
- cross-repository evaluation;
- no automatic verification or patching.

## Slice 15 — Evidence-grounded conversational retrieval

- context broker;
- bounded assessment-scoped retrieval;
- citation labels and validation;
- prompt-injection tests;
- provider-neutral advisory invocation;
- safe fallback and abstention;
- product presentation.

## Slice 16 — Production acceptance and cleanup

- complete end-to-end acceptance;
- remove obsolete provider contradictions and ad hoc model configuration;
- reconcile all owner documents;
- capture machine-readable reports and artifacts;
- classify remaining limitations honestly;
- verify deterministic operation with all ML/Hugging Face features disabled.

---

# 29. Permanent invariants

1. Human-reviewed evidence remains the source of label truth.
2. Production training consumes verified immutable governed releases.
3. Complete scans never split; external holdout isolates complete application families.
4. The external holdout is not used for iterative tuning.
5. Predictions never mutate review labels.
6. Low-confidence or unfamiliar inputs may and should abstain.
7. Raw model posterior is not presented as calibrated probability without evidence.
8. OOD detection cannot be converted silently to a negative label.
9. Every active model is registry-backed and rollback-capable.
10. Model activation requires explicit authority and verified artifacts.
11. Shadow models cannot affect user-visible decisions.
12. Drift does not trigger autonomous retraining or activation.
13. Hugging Face repositories, models and tokenizers are revision-pinned for approved use.
14. Unreviewed remote custom code is prohibited.
15. Remote providers remain optional and untrusted.
16. Provider reachability, model quality, worker health and assessment lifecycle are separate.
17. Embedding retrieval is permission- and assessment-scoped.
18. Retrieved content is untrusted and cannot override system authority.
19. Advisory citations are validated against supplied records.
20. No model receives operational tools through the advisory path.
21. Public or synthetic datasets do not establish real-product performance.
22. Monitoring does not store prohibited raw evidence.
23. Every model output retains exact task, model, revision and input provenance.
24. All deterministic and human workflows remain usable when ML and remote providers are disabled.
25. Documentation does not count as implementation.

---

# 30. Definition of done

The ML and Hugging Face production programme is complete only when:

- production training requires a verified governed dataset release;
- release corrections and revocations propagate to model governance;
- application-family and instance metadata exist and are enforced in partitions;
- a genuinely untouched family-isolated external holdout exists;
- current deterministic features remain a reproducible baseline;
- feature-extractor contracts support safely evaluated local encoders;
- leakage and ablation reports exist;
- predictions include calibrated uncertainty, OOD and abstention;
- ranking, calibration, generalisation and error metrics are reported with sample counts;
- a model registry controls candidate, shadow, active, degraded, retired and revoked states;
- activation and rollback are atomic, authorised and tested;
- shadow deployment and delayed human-outcome comparison work;
- privacy-safe monitoring and drift reports work;
- incident disable, rollback and revocation work;
- Hugging Face models and tokenizers are exact-revision capability profiles;
- configured, reachable and end-to-end verified provider states are distinct;
- local assessment-scoped embedding retrieval passes isolation and quality tests;
- Source Hunt code-model experiments beat or honestly fail against deterministic baselines;
- conversational advisory answers use bounded authorised context and validated citations;
- prompt injection cannot grant authority or cross data boundaries;
- every relevant CLI, API and UI surface uses truthful language;
- all required repository, security, ML, browser and phone gates pass;
- the complete system remains useful with ML and all remote providers disabled;
- current-state documentation agrees with actual implementation;
- no production claim relies only on synthetic benchmarks, documentation or model popularity.

Until all of these conditions are met, VulnHunter must continue to describe its ML and Hugging Face capabilities as governed research and advisory decision support rather than production vulnerability intelligence.