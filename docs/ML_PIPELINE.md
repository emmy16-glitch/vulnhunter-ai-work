# VulnHunter Machine-Learning Pipeline

**Status:** Implemented deterministic baseline plus binding evolution contract  
**Architecture:** [`intelligence/ML_AND_HUGGING_FACE_PRODUCTION_ARCHITECTURE.md`](intelligence/ML_AND_HUGGING_FACE_PRODUCTION_ARCHITECTURE.md)  
**Governance:** [`intelligence/ML_GOVERNANCE.md`](intelligence/ML_GOVERNANCE.md)

## 1. Purpose

The current local model is a decision-support baseline trained only from eligible human-reviewed passive observations. It estimates whether an observation resembles the existing `confirmed` or `false_positive` classes.

It does not:

- scan or contact targets;
- create evidence;
- change review labels;
- approve findings;
- determine final severity;
- publish results;
- replace independent review;
- grant lifecycle or operational authority.

The baseline must remain available as the deterministic, inspectable comparison point for every later model family.

A transformer, embedding model or hosted Hugging Face endpoint must beat or complement this baseline under the same group-isolated evaluation. It must not replace the baseline merely because it is newer or larger.

## 2. Current implementation

The implemented pipeline contains:

- `vulnhunter/ml/dataset.py` for reviewed-example construction, deterministic hashing and JSONL export;
- `vulnhunter/ml/quality.py` for deduplication, conflict detection and readiness gates;
- `vulnhunter/ml/splitting.py` for complete-scan grouped splits;
- `vulnhunter/ml/features.py` for deterministic privacy-conscious features;
- `vulnhunter/ml/estimators.py` for Multinomial and Bernoulli Naive Bayes;
- `vulnhunter/ml/tuning.py` for training-only grouped candidate selection;
- `vulnhunter/ml/training.py` for fitting, evaluation, model persistence and prediction;
- `vulnhunter/ml/diagnostics.py` for locked-holdout diagnostics;
- versioned Pydantic model and artifact schemas;
- CLI commands for readiness, export, training, prediction and controlled benchmark diagnostics.

## 3. Implemented data boundary

Eligible model labels are:

- `confirmed`;
- `false_positive`.

Ineligible or excluded records include:

- unreviewed observations;
- observations awaiting second review;
- unresolved reviewer disagreement;
- unresolved adjudication;
- review notes as free-form model features;
- raw response bodies;
- credentials, cookies, tokens, private keys and detected secrets;
- data outside the release or training policy.

The current dataset conversion uses already-redacted observation fields. Structural URL features are preferred over arbitrary hostname, query-value or path-token memorisation.

Production-mode evolution must require an immutable governed dataset release rather than an arbitrary mutable database view. Research mode may continue to support local reviewed exports, but artifacts must remain classified as research.

## 4. Dataset identity and provenance

Every canonical dataset has a deterministic SHA-256 over its ordered JSON representation.

The target production package additionally records:

- dataset release ID and digest;
- campaign and authorisation provenance;
- review/adjudication attestation digests;
- application-family and instance IDs;
- deployment environment;
- assessment and scan IDs;
- label ontology version;
- redaction policy version;
- package generator version;
- source commit;
- excluded records and reasons.

A corrected release produces a new package and digest. Training must never silently consume a mutated dataset under an old identity.

## 5. Quality preparation

The preparation stage currently:

1. groups examples by fingerprint;
2. removes repeated examples with the same terminal label;
3. blocks fingerprints with conflicting labels;
4. counts unique samples and scans;
5. checks both classes;
6. checks scans per class;
7. verifies a grouped split can be formed.

Production preparation must also verify:

- governed release integrity;
- no pending review/adjudication state;
- application-family metadata;
- minimum application families and instances;
- family coverage for both labels where required;
- external-holdout isolation;
- privacy and permitted-use policy;
- detector/template and environment diversity;
- compatible feature and label schemas.

## 6. Current feature engineering

The current feature schema is learned from the training partition only.

Features include:

- severity one-hot indicators;
- observed category indicators;
- bounded redacted title/description token vocabulary;
- HTTPS and query indicators;
- path depth;
- predeclared sensitive/public path-context indicators;
- bounded evidence key/string/number counts;
- missing-header count and selected header identities;
- response status families;
- selected debug-indicator identities;
- selected directory-index context.

The pipeline does not add arbitrary raw response bodies, secret values or unrestricted URL values.

## 7. Feature-extractor interface

The pipeline must evolve from one hardcoded feature function to a versioned extractor interface while keeping the current extractor as the default baseline.

Each extractor manifest must record:

- extractor ID;
- extractor version;
- task;
- input schema version;
- output schema and dimension;
- deterministic transformation configuration;
- source fields;
- privacy classification;
- missing-value policy;
- model/tokenizer repository and exact revision where applicable;
- dependency and artifact digests;
- numerical precision and device;
- maximum bytes/tokens;
- license and approval state;
- offline/cache requirements.

Recommended logical interface:

```text
prepare(input, policy)
    -> validated redacted model input

fit_schema(training_inputs)
    -> immutable extractor schema

transform(input, schema)
    -> feature vector or embedding
    -> coverage and unknown indicators
    -> provenance
```

Feature extraction must be deterministic under the declared environment or must record any unavoidable numerical nondeterminism.

## 8. Unknown and missing features

The extractor should report, rather than silently ignore:

- unknown category;
- unknown detector/template family;
- evidence-schema mismatch;
- missing expected evidence fields;
- out-of-range numeric features;
- low token coverage;
- unsupported source language;
- unsupported artifact type;
- embedding dimension mismatch.

These indicators feed OOD and abstention policy.

## 9. Leakage controls

The pipeline must preserve:

- training-only vocabulary construction;
- fold-local vocabulary during cross-validation;
- complete-scan grouping;
- application-family isolation for external evaluation;
- no feature selection using locked external errors;
- no model selection using external holdout metrics.

Mandatory ablation variants include:

- all baseline features;
- structural evidence only;
- no category;
- no severity;
- no title/description tokens;
- no scanner-generated text;
- leave-one-detector-out;
- leave-one-template-family-out;
- leave-one-application-family-out.

This identifies models that memorise detector wording or application fingerprints instead of generalising from evidence.

## 10. Current model family

The implemented candidate family contains:

- Multinomial Naive Bayes;
- Bernoulli Naive Bayes;
- smoothing candidates;
- explicit positive thresholds.

The implementation is dependency-light, deterministic, inspectable and appropriate for a private laboratory VM.

## 11. Future candidate families

Future candidates may include:

- regularised linear models over deterministic features;
- calibrated tree or boosting models when dependency and explainability policy permits;
- frozen text embeddings plus a small calibrated classifier;
- frozen code embeddings for Source Hunt retrieval;
- hybrid deterministic and embedding features.

A large generative model is not the default classification architecture.

Any new candidate must:

- implement the versioned model interface;
- preserve the release and grouping boundaries;
- support safe artifact loading;
- record dependencies and exact revisions;
- support calibration, OOD and abstention;
- pass resource, privacy and rollback gates;
- be compared against the baseline.

## 12. Hugging Face encoder integration

A Hugging Face encoder may be used only behind the feature-extractor interface.

Required controls include:

- exact repository and revision pinning;
- exact tokenizer revision;
- reviewed license and model card;
- safe weight formats, preferably `safetensors`;
- no unreviewed remote custom code;
- bounded local cache;
- declared input length and truncation;
- deterministic pooling and normalisation;
- fixed output dimension;
- dependency lock;
- local-first processing for private evidence and source code;
- benchmark against non-neural baselines.

Research candidates may include CodeBERT, GraphCodeBERT, UniXcoder, code-oriented Jina embeddings or smaller text embedding models, but none is approved solely by being listed in documentation.

## 13. Training flow

The target production flow is:

```text
verify dataset release
    -> build immutable ML package
    -> validate labels and groups
    -> assign development/calibration/external groups
    -> fit fold-local feature schemas
    -> train candidate models
    -> choose candidate on development data
    -> fit calibrator and OOD policy on development groups
    -> freeze complete package
    -> evaluate locked external holdout once
    -> emit candidate package and reports
    -> register as candidate
```

Research flow may omit external evaluation but must state that limitation.

## 14. Prediction flow

The production prediction path should be:

```text
persisted authoritative observation
    -> eligibility and privacy check
    -> exact active registry package
    -> feature extraction
    -> raw model score
    -> calibration
    -> OOD policy
    -> abstention/priority decision
    -> immutable prediction record
    -> optional product presentation
```

Prediction cannot alter the observation or review record.

## 15. Prediction contract

The evolved prediction artifact should contain:

```json
{
  "prediction_id": "...",
  "observation_id": 1,
  "assessment_id": "...",
  "task": "review_priority",
  "model_id": "...",
  "model_version": "...",
  "feature_extractor_id": "...",
  "input_sha256": "...",
  "feature_sha256": "...",
  "raw_positive_probability": 0.0,
  "calibrated_positive_probability": 0.0,
  "uncertainty": 0.0,
  "ood_score": 0.0,
  "decision": "prioritise_review | normal_review | abstain",
  "reason_codes": [],
  "feature_coverage": 0.0,
  "created_at": "..."
}
```

The legacy binary `Prediction` remains supported for current artifacts until a versioned migration is implemented.

## 16. Calibration

Raw Naive Bayes posterior values are not automatically calibrated probabilities.

The pipeline must support a separate versioned calibrator bound to the exact model, extractor and development partition.

Candidate calibration methods may include:

- Platt scaling;
- isotonic regression;
- another bounded method justified by data volume and diagnostics.

Calibration selection uses development groups only.

The pipeline records:

- calibrator type and parameters;
- training groups;
- calibration groups;
- Brier score;
- expected calibration error;
- reliability buckets;
- calibration limitations.

## 17. Abstention and OOD

The prediction pipeline must support `abstain`.

Baseline deterministic OOD signals include:

- unknown family/category/detector;
- feature-schema mismatch;
- missingness;
- low token or feature coverage;
- values outside validated ranges;
- embedding distance where embeddings are used;
- model or release degradation.

Abstention is an ordinary safe outcome, not an exception and not a synonym for `false_positive`.

## 18. Evaluation

The pipeline produces separate reports for:

- development selection;
- calibration;
- OOD and coverage-risk;
- internal grouped holdout where used;
- locked external application-family holdout;
- category/family/detector diagnostics;
- latency and resource use.

Required metrics are defined in `MODEL_SELECTION.md` and `ML_GOVERNANCE.md`.

## 19. Artifact format and safety

The current models are JSON rather than pickle. Preserve this safe design.

Current protections include:

- maximum artifact size;
- Pydantic validation;
- feature-dimension checks;
- class and label validation;
- dataset digest;
- grouped split provenance;
- atomic owner-private writes.

Future packages must additionally include:

- model registry identity;
- release and partition digests;
- calibrator and OOD artifacts;
- feature-extractor manifest;
- dependency/environment digest;
- intended/prohibited use;
- signatures or attestations where configured;
- rollback compatibility.

Transformer weights should prefer `safetensors`. Pickle and unreviewed remote code remain prohibited.

## 20. Model loading

Loading a model must verify:

- lifecycle state permits use;
- package digest;
- artifact schema;
- feature schema;
- calibrator/OOD binding;
- dataset release not revoked;
- application compatibility;
- dependency/runtime compatibility;
- output dimensions;
- size and numerical validity.

An incompatible or degraded model fails to safe baseline or no-recommendation mode according to policy.

## 21. Registry integration

Training does not activate a model.

The pipeline emits a candidate package that is registered separately.

Registry progression, shadow deployment, activation, degradation, rollback and revocation are governed by `ML_GOVERNANCE.md`.

The runtime resolves the active package atomically from the registry. Copying a file or setting an arbitrary path does not silently activate it.

## 22. Shadow inference

The prediction service should support active and shadow models over the same eligible input.

Shadow output:

- is stored separately;
- never changes UI ordering or decisions;
- includes full provenance;
- joins later to governed review labels;
- respects privacy and compute budgets;
- can fail without affecting the active path.

## 23. Monitoring hooks

Prediction records should support monitoring without storing prohibited raw evidence.

Capture:

- model/extractor versions;
- latency;
- failure type;
- score, OOD and abstention distributions;
- reason codes;
- feature coverage;
- active-shadow disagreement;
- delayed reviewed outcome.

Do not automatically retrain from monitoring data.

## 24. CLI and service evolution

The current CLI remains the exact source for implemented commands.

Future additions should include bounded commands such as:

```text
vulnhunter ml package-release
vulnhunter ml train-candidate
vulnhunter ml calibrate
vulnhunter ml evaluate-external
vulnhunter ml registry inspect
vulnhunter ml registry shadow
vulnhunter ml registry activate
vulnhunter ml registry rollback
vulnhunter ml registry revoke
vulnhunter ml monitor report
```

Do not document a command as operational before it exists and is tested.

## 25. Minimum data rules

The current default minimum of 20 unique reviewed observations and five per class is a software-pipeline threshold, not a production sufficiency claim.

Production promotion requires much stronger declared thresholds covering:

- application families;
- instances;
- scans;
- both classes per relevant grouping;
- category and detector coverage;
- calibration data;
- untouched external families;
- reviewer diversity.

When the dataset is too small, the correct pipeline result is `insufficient_data` with exact reasons.

## 26. Testing

Pipeline tests must cover:

- release integrity and revocation;
- duplicate/conflict handling;
- family and scan isolation;
- deterministic features;
- fold-local vocabularies;
- ablations;
- unknown/missing features;
- baseline fitting and prediction;
- calibration binding;
- OOD and abstention;
- malformed/oversized artifacts;
- registry compatibility;
- shadow isolation;
- delayed review joins;
- Hugging Face extractor revision and dimension mismatch;
- offline operation with optional dependencies absent.

## 27. Current-versus-target classification

```text
DETERMINISTIC REVIEWED-DATA BASELINE          IMPLEMENTED
SCAN-GROUP SPLITTING                           IMPLEMENTED
TRAINING-ONLY MODEL SELECTION                  IMPLEMENTED
SAFE JSON ARTIFACTS                            IMPLEMENTED
GOVERNED RELEASE-BOUND PRODUCTION TRAINING     NOT COMPLETE
APPLICATION-FAMILY EXTERNAL HOLDOUT            NOT COMPLETE
CALIBRATION ARTIFACT                           NOT COMPLETE
OOD AND EXPLICIT ABSTENTION                     NOT COMPLETE
MODEL REGISTRY AND ACTIVATION                   NOT COMPLETE
SHADOW DEPLOYMENT                               NOT COMPLETE
DRIFT MONITORING                                NOT COMPLETE
HUGGING FACE FEATURE EXTRACTOR                  RESEARCH-ONLY/NOT IMPLEMENTED
EVIDENCE RETRIEVAL                              NOT COMPLETE
PRODUCTION VULNERABILITY CLASSIFIER             NOT ESTABLISHED
```

## 28. Definition of done

The ML pipeline is production-complete only when:

- production candidates are release-bound;
- hierarchical grouping prevents family leakage;
- feature extractors are versioned and reproducible;
- baseline and candidate ablations exist;
- calibration, OOD and abstention work;
- external evaluation is genuinely locked;
- complete candidate packages are registry-compatible;
- activation and rollback are separate and tested;
- shadow and monitoring hooks work;
- Hugging Face encoder use is revision-pinned and optional;
- private workflows remain local-first;
- all model outputs remain advisory;
- the system operates correctly with every optional ML/Hugging Face feature disabled.