# Machine-Learning Governance

**Status:** Binding governance policy  
**Scope:** dataset eligibility, authority separation, experiment approval, promotion, activation, monitoring, correction, rollback, retirement and revocation  
**Cross-layer architecture:** [`ML_AND_HUGGING_FACE_PRODUCTION_ARCHITECTURE.md`](ML_AND_HUGGING_FACE_PRODUCTION_ARCHITECTURE.md)

## 1. Purpose

VulnHunter models provide decision support. They may prioritise review, retrieve related evidence, cluster observations, rank source-code candidates or draft bounded advisory explanations.

They do not determine vulnerability truth and do not receive authority to:

- authorise or expand a target;
- approve a plan;
- run a scanner or worker;
- mutate evidence;
- confirm or reject a finding;
- determine final severity;
- assign or impersonate a human review;
- adjudicate disagreement;
- release a dataset;
- activate another model;
- merge code, deploy software or publish reports.

The governing rule is:

> Deterministic services enforce policy, verified evidence records what happened, authorised humans decide governed outcomes, and models remain advisory.

This policy applies to the implemented Naive Bayes baseline, future local encoders, embedding models, remote Hugging Face models, Groq advisory models, calibration artifacts, OOD policies and any later candidate model.

## 2. Document ownership

This document owns governance and authority.

Related documents own narrower mechanics:

- `docs/DATA_QUALITY.md` owns review and dataset-release integrity;
- `docs/ML_PIPELINE.md` owns training and prediction mechanics;
- `docs/MODEL_SELECTION.md` owns selection, calibration and evaluation protocol;
- `docs/product/AI_ROUTING.md` owns privacy and provider routing;
- `docs/product/LLM_RUNTIME_READINESS.md` owns deployed provider/model readiness;
- `ML_AND_HUGGING_FACE_PRODUCTION_ARCHITECTURE.md` owns the joined production architecture and implementation sequence.

Do not create a second model-promotion or governance policy. Update this document when authority or lifecycle rules change.

## 3. Governance objects

The production architecture should treat the following as separate immutable or append-only governance objects:

- governed dataset release;
- training dataset package;
- partition programme;
- experiment record;
- candidate model package;
- calibration artifact;
- OOD policy artifact;
- evaluation report;
- model registry entry;
- promotion decision;
- activation event;
- rollback event;
- degradation incident;
- retirement or revocation event.

Each object has its own identity, schema version, digest, timestamps and responsible identities.

## 4. Training eligibility

### 4.1 Research mode

Local research-mode training may use an explicitly exported reviewed dataset for pipeline development, provided the resulting artifact is labelled `research` and cannot be activated as a production model.

Research-mode metrics must state:

- the data source;
- whether a governed release was used;
- whether application-family grouping was available;
- whether evaluation is synthetic, internal or external;
- that the artifact is not approved for product recommendations.

### 4.2 Production-candidate mode

A production candidate must train only from one or more verified immutable governed dataset releases.

Training fails safely when any required condition is unmet:

- release manifest integrity cannot be verified;
- release is withdrawn or revoked;
- minimum reviewed samples are not met;
- minimum samples per class are not met;
- minimum application families, instances, scans or environments are not met;
- either class lacks required family and scan coverage;
- unresolved label conflicts exist;
- pending second reviews remain;
- unresolved adjudication cases remain;
- application-family metadata is absent;
- the required grouped development/calibration split is infeasible;
- the locked external holdout cannot be kept isolated;
- prohibited or unredacted data is present;
- label ontology, feature schema or permitted-use policy is incompatible.

A configuration option must not allow an unattended process to bypass production eligibility while still labelling the output production-ready.

## 5. Governing data lineage

The required production lineage is:

```text
explicitly authorised application
    -> governed campaign
    -> completed bounded assessments
    -> independent review
    -> adjudication where needed
    -> immutable dataset release
    -> verified training package
    -> candidate experiment
    -> locked evaluation
    -> model registry
    -> shadow/canary
    -> human-approved activation
```

Every production model must resolve back to:

- exact release IDs and digests;
- campaign and authorisation digests;
- included assessment and observation identities;
- review and adjudication attestations;
- application-family and deployment metadata;
- code, scanner, template and worker versions where relevant;
- redaction and label-policy versions.

## 6. Authority and role separation

### 6.1 Required logical roles

Separate responsibilities should exist for:

- **data-release authority:** approves the governed dataset release;
- **training operator:** executes an approved experiment specification;
- **evaluation reviewer:** verifies methodology, metrics and limitations;
- **model promotion authority:** approves or rejects registry progression;
- **deployment operator:** activates or rolls back an already-approved package;
- **incident authority:** degrades, disables or revokes unsafe models;
- **reviewers/adjudicators:** produce authoritative labels independently of model operators.

One identity may hold more than one role in a small laboratory only when the conflict is documented and an independent human approves promotion. Production policy should prefer separate identities.

### 6.2 Forbidden self-approval

An automated agent or single unreviewed workflow must not:

1. select data;
2. generate labels;
3. train a model;
4. evaluate it;
5. declare it successful;
6. activate it;
7. close the governing work item.

The existing bounded orchestration system may prepare evidence and execute approved deterministic steps. It does not inherit model-promotion authority.

## 7. Partition and holdout governance

All observations from one scan remain in one partition.

Production evaluation additionally isolates entire application families from the external holdout.

The partition programme records:

- programme ID and version;
- grouping-policy version;
- application family and instance identities;
- development-training assignment;
- development-validation/calibration assignment;
- external-holdout assignment;
- assignment timestamp and authority;
- superseded programme where applicable.

The external holdout is locked before final model-family, feature, calibration, OOD and threshold decisions.

After it is evaluated, a material design change starts a new evaluation programme. Agents must not repeatedly tune against the same external holdout and continue calling it untouched.

## 8. Label governance

Human review remains authoritative.

Model outputs must be stored separately from review labels and include:

- task;
- model/revision;
- raw and calibrated score where applicable;
- OOD score;
- abstention decision;
- deterministic reason codes;
- timestamp;
- input and feature provenance.

A reviewer accepting, dismissing or opening a recommendation is not automatically a training label.

Training eligibility requires the terminal governed review state declared by the release policy, normally independent consensus or adjudication.

Corrections produce new review/release lineage. Historical labels and predictions remain inspectable rather than being silently rewritten.

## 9. Model task governance

The following are governed as separate tasks:

- review-priority assistance;
- confirmed-versus-false-positive research classification;
- vulnerability-category assistance;
- severity assistance;
- related-finding retrieval;
- evidence-quality assistance;
- remediation retrieval;
- source-code retrieval;
- source vulnerability candidate generation;
- conversational summarisation and explanation.

Approval for one task does not authorise another.

A model approved for duplicate retrieval cannot be presented as a vulnerability classifier. A conversational model approved to explain evidence cannot confirm findings.

## 10. Experiment governance

Every experiment specification records:

- stable experiment ID;
- hypothesis;
- task and intended use;
- dataset release and partition programme;
- candidate family;
- feature extractor;
- calibration and OOD plan;
- declared metrics and acceptance criteria;
- compute and provider budget;
- source commit and environment;
- expected artifacts;
- prohibited operations;
- reviewer.

Experiments are immutable after execution begins except through an explicit superseding record.

Failed and rejected experiments remain in the ledger. Do not delete failures to make the programme appear more successful.

## 11. Model registry lifecycle

Use explicit lifecycle states:

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

Additional terminal states such as `rejected` may be used for candidates.

### 11.1 Research

- pipeline or exploratory artifact;
- may use controlled benchmark or non-release data;
- cannot affect product recommendations.

### 11.2 Candidate

- complete package submitted for evaluation;
- all lineage and artifact digests present;
- no activation authority.

### 11.3 Validated

- automated integrity and declared evaluation gates passed;
- still requires human promotion approval.

### 11.4 Approved

- human authority approved intended use and limitations;
- not necessarily deployed.

### 11.5 Shadow

- runs beside the active model;
- cannot affect reviewer ordering or user-visible recommendations;
- captures comparative outcomes.

### 11.6 Active

- explicitly activated for a bounded task and scope;
- rollback target exists;
- monitoring is enabled.

### 11.7 Degraded

- may remain available with restricted or no recommendations;
- product surfaces clearly expose the degraded state;
- deterministic workflow continues.

### 11.8 Retired

- intentionally removed from active use;
- lineage and historical predictions remain inspectable.

### 11.9 Revoked

- prohibited from use because of integrity, privacy, supply-chain, dataset or safety failure;
- activation must fail closed.

## 12. Promotion standard

A candidate must not advance beyond research without:

- diverse intentionally selected authorised applications;
- governed consensus/adjudicated labels from independent reviewers;
- application-family and instance metadata;
- group-isolated development partitions;
- a genuinely locked external application-family holdout;
- leakage and ablation analysis;
- category, family, detector and severity error analysis;
- calibration analysis;
- OOD and abstention analysis;
- repeatability across seeds and appropriate groups;
- privacy and supply-chain review;
- performance and resource measurements;
- documented intended use, prohibited use and limitations.

Promotion to active additionally requires:

- successful shadow evaluation;
- no critical regression;
- tested rollback;
- operational monitoring;
- activation approval;
- exact artifact verification.

## 13. Metric interpretation

Report at least:

- sample and group counts;
- confusion matrix;
- accuracy;
- precision;
- recall;
- F1;
- balanced accuracy;
- PR-AUC;
- precision and recall at review-budget cutoffs;
- Brier score and calibration error;
- abstention coverage and error;
- OOD performance;
- family/category/detector slices;
- uncertainty or confidence intervals where valid.

Accuracy alone is insufficient.

A high precision with low recall can hide critical missed findings. A high F1 on repeated variants can hide application memorisation. A perfect synthetic benchmark can indicate an easy or contaminated benchmark rather than production capability.

Every metric is accompanied by:

- dataset/release identity;
- partition type;
- sample count;
- application-family count;
- model/revision;
- whether the result is development, internal holdout or external holdout.

## 14. Calibration and abstention governance

Raw posterior probabilities must not be labelled calibrated confidence unless calibration was evaluated and recorded.

A production recommendation contract supports `abstain`.

Abstention is required when policy detects conditions such as:

- insufficient calibrated margin;
- OOD input;
- unknown application family, category or detector;
- feature-schema mismatch;
- low feature coverage;
- revoked training release;
- degraded model or calibrator;
- numerical failure.

Abstention sends work to human review. It does not become `false_positive`.

Calibration, OOD and abstention artifacts are governed and versioned alongside the base model.

## 15. Hugging Face governance

A Hugging Face repository name is not sufficient approval.

Approved use requires:

- exact repository and revision;
- model and tokenizer identity;
- license review;
- model-card and intended-use review;
- approved inference backend;
- safe artifact format where downloaded;
- file/dependency manifests;
- remote custom code disabled unless separately reviewed;
- capability profile;
- privacy classification;
- compute and data-retention policy;
- verified rollback or disable path.

Popularity, likes, download count, leaderboard position or provider availability are not promotion criteria.

Public vulnerability datasets and synthetic preference datasets remain research inputs unless they independently satisfy VulnHunter's release and validation requirements. They do not prove real-product performance.

## 16. Model and data supply-chain governance

Production status should require integrity controls for:

- dataset releases;
- training packages;
- source commit;
- dependency lock;
- runtime/container;
- model weights;
- tokenizer files;
- calibration artifact;
- OOD policy;
- evaluation report;
- registry entry.

Prefer non-executable model formats and `safetensors` for transformer weights. Prohibit arbitrary pickle loading and unreviewed `trust_remote_code`.

A software or model bill of materials should be attached to approved deployable packages.

## 17. Activation and rollback governance

Activation is a distinct authorised operation. It verifies:

1. approved registry state;
2. exact artifact digests;
3. compatible application and feature schemas;
4. calibration and OOD artifacts;
5. deployment environment;
6. monitoring configuration;
7. rollback target;
8. current non-revoked releases and licenses.

Activation records an immutable audit event.

Rollback is tested before activation. It restores the complete previous package, including feature extractor, calibrator, OOD policy and routing configuration.

Historical prediction provenance is never rewritten by rollback.

## 18. Shadow and canary governance

A newly approved model enters shadow mode first.

Shadow predictions:

- cannot change reviewer ordering;
- cannot alter product state;
- are stored separately from active predictions;
- join later to governed human outcomes;
- respect the same privacy, budget and retention controls.

Canary use requires an explicit bounded cohort or traffic scope, monitoring and immediate disable/rollback.

No unattended process automatically expands canary scope.

## 19. Monitoring and drift governance

Monitoring distinguishes:

- inference service health;
- model artifact health;
- input quality;
- score/calibration drift;
- OOD and abstention rates;
- reviewer outcome quality;
- provider health;
- worker and assessment health.

Drift detection does not automatically retrain or promote a model.

Drift or incident records may trigger:

- investigation;
- degraded mode;
- recommendation disablement;
- rollback;
- model revocation;
- collection plan changes;
- a new governed training programme.

Monitoring must not store prohibited raw evidence or enable cross-tenant reconstruction.

## 20. Corrections, withdrawal and revocation

A corrected label or withdrawn dataset release requires impact analysis for every dependent model.

The dependency graph must answer:

- which models used the release;
- which active or shadow deployments use those models;
- which predictions were generated;
- whether retraining, degradation, rollback or revocation is required.

Revocation reasons include:

- corrupted artifact;
- revoked or invalid training release;
- privacy violation;
- model supply-chain compromise;
- critical leakage;
- severe external-holdout failure discovered after activation;
- incompatible license or terms;
- cross-tenant retrieval;
- unsafe advisory behaviour that cannot be bounded.

## 21. Benchmark policy

Controlled benchmark data is useful for:

- pipeline correctness;
- regression testing;
- reproducibility;
- provenance tests;
- error-diagnostic development;
- candidate engineering.

It is not evidence of performance on unknown real applications.

Every benchmark result must identify:

- dataset source and official/unofficial status;
- synthetic or real status;
- license;
- known duplicate/leakage risks;
- task mismatch;
- partition method;
- whether any benchmark content influenced feature or model design.

## 22. Product-language governance

Product surfaces use language that preserves human authority:

- `Suggested review priority`;
- `Advisory estimate`;
- `Model abstained`;
- `Human review required`;
- `Provider unavailable; deterministic workflow continues`.

Prohibited claims include:

- `AI verified`;
- `Model approved`;
- `Definitely vulnerable`;
- `Safe`;
- `No vulnerability` based only on a negative model recommendation;
- `Production-ready` based only on synthetic benchmark metrics.

## 23. Required evidence for governance changes

A pull request changing training, evaluation, registry, provider or activation behaviour must include:

- threat and authority analysis;
- schema migration impact;
- tests for authorised and unauthorised paths;
- failure and rollback tests;
- provenance examples;
- updated current-state classification;
- relevant owner-document updates;
- repository audit results.

Changes must not weaken deterministic operation when models or providers are disabled.

## 24. Definition of governance completion

Machine-learning governance is production-complete only when:

- production training is release-bound;
- role and authority separation is enforced;
- family-isolated external evaluation exists;
- labels and predictions remain separate;
- calibration, OOD and abstention are governed;
- registry states and transitions are implemented;
- activation, degradation, rollback, retirement and revocation work;
- shadow comparison joins to governed outcomes;
- monitoring and incident controls work;
- Hugging Face model/revision/license/capability approval works;
- dataset and model supply-chain provenance is verifiable;
- public product language remains truthful;
- all required automated and human acceptance gates pass.

Until then, model capabilities remain governed research or advisory decision support.