# Model Selection, Calibration and Locked Evaluation

**Status:** Implemented baseline selection protocol plus binding production evaluation standard  
**Architecture:** [`intelligence/ML_AND_HUGGING_FACE_PRODUCTION_ARCHITECTURE.md`](intelligence/ML_AND_HUGGING_FACE_PRODUCTION_ARCHITECTURE.md)  
**Governance:** [`intelligence/ML_GOVERNANCE.md`](intelligence/ML_GOVERNANCE.md)

## 1. Purpose

Model selection chooses among candidate algorithms, features, thresholds, calibration methods and abstention/OOD policies using development data only.

Final evaluation measures the frozen package on a genuinely untouched external holdout. It is not another tuning stage.

The current implementation correctly separates training-only grouped candidate selection from one locked scan-group holdout evaluation. The production target strengthens the grouping boundary from scans to application families and separates calibration/OOD selection from final external evaluation.

## 2. Document ownership

This document owns:

- development, validation/calibration and external-holdout protocol;
- candidate ranking;
- leakage-safe feature learning;
- calibration selection;
- OOD and abstention selection;
- metric definitions;
- diagnostic slices;
- acceptance and rejection decisions based on measured performance.

It does not own model activation or authority. Those belong to `ML_GOVERNANCE.md` and the future registry.

## 3. Implemented baseline protocol

The current controlled benchmark process is:

1. deduplicate reviewed examples;
2. group all observations from one scan;
3. lock a scan-group holdout before comparing candidates;
4. use only training scans for two-fold grouped cross-validation;
5. rebuild feature vocabularies from each fold's training partition;
6. compare Multinomial and Bernoulli Naive Bayes;
7. compare declared smoothing and positive-threshold candidates;
8. rank candidates using training-only F1, recall, precision and accuracy;
9. fit the selected configuration on all training scans;
10. evaluate the untouched scan holdout once;
11. store metrics, configuration and split provenance in the model artifact.

No observation from a holdout scan is used to choose algorithm, smoothing, threshold, category vocabulary or text vocabulary.

This protocol remains the baseline regression standard.

## 4. Production grouping hierarchy

Scan grouping is necessary but not sufficient for external validation.

Production partitions must use the strongest applicable grouping hierarchy:

```text
application_family_id
    -> application_instance_id
        -> deployment_environment_id
            -> repository revision or artifact digest
                -> assessment/scan
                    -> observation
```

At minimum:

- a scan cannot cross any partition;
- an application instance cannot cross the external holdout boundary;
- an application family cannot appear in both development and external holdout;
- benchmark variants derived from one source family remain grouped;
- near-identical revisions do not masquerade as independent external applications.

## 5. Three-way production partition

### 5.1 Development training

Used for:

- fitting candidate parameters;
- learning feature vocabularies;
- fitting fold-local encoders where allowed.

### 5.2 Development validation and calibration

Used for:

- algorithm selection;
- feature-family selection;
- threshold selection;
- calibration-method selection;
- OOD threshold selection;
- abstention policy;
- ranking and resource trade-offs.

This partition remains application-group isolated from the examples used to fit each candidate within each fold.

### 5.3 Locked external holdout

Used once after the complete candidate package is frozen.

It contains application families unseen during all development decisions.

It is not used to:

- add features;
- change vocabulary;
- change model family;
- tune thresholds;
- select calibrator;
- select OOD policy;
- select abstention coverage;
- rewrite acceptance criteria.

A material post-evaluation change starts a new programme with a new untouched external holdout or an explicitly exploratory status.

## 6. When data is insufficient

If data cannot support a three-way group-isolated design, report the strongest honest status:

- `pipeline_only`;
- `development_cross_validation_only`;
- `internal_group_holdout_only`;
- `external_family_holdout_available`.

Do not call a scan holdout external validation when the same application family appears in development.

Do not use synthetic benchmark variants as independent real applications.

## 7. Candidate specification

Each candidate specification is immutable and records:

- candidate ID;
- task;
- dataset release IDs and digests;
- partition programme;
- feature extractor and schema;
- algorithm family;
- hyperparameters;
- threshold grid;
- calibration candidates;
- OOD candidates;
- abstention candidates;
- random seeds;
- training code commit;
- environment/dependency digest;
- resource budget;
- declared ranking metric and tie-breakers.

An experiment that changes any of these creates a new candidate identity.

## 8. Candidate families

### 8.1 Implemented baseline

- Multinomial Naive Bayes;
- Bernoulli Naive Bayes;
- four smoothing values;
- five positive-class thresholds;
- deterministic fold-local feature schemas.

### 8.2 Future classical candidates

Examples may include:

- regularised logistic regression;
- linear SVM with separately calibrated scores;
- bounded tree/boosting candidates;
- hybrid models over deterministic features.

### 8.3 Future Hugging Face feature candidates

Candidates may use frozen revision-pinned encoders to produce features, followed by a small calibrated classifier.

The encoder is not automatically the classifier and is not promoted by model popularity.

Research candidates may include CodeBERT, GraphCodeBERT, UniXcoder, code-oriented Jina embeddings or small sentence-embedding models. Each experiment records exact revision, tokenizer, pooling, dimension, license, memory and latency.

### 8.4 Generative models

Generative LLMs are not the default binary classifier candidate.

They may be evaluated for retrieval, summarisation or bounded hypothesis generation under separate task metrics. Free-form answers cannot be ranked as classifier candidates without a structured, reproducible and independently validated task contract.

## 9. Fold construction

Development cross-validation must preserve group isolation.

Requirements:

- every validation fold contains complete groups;
- complementary training folds contain both required labels;
- validation folds contain both labels when the metric requires them;
- feature schemas are fitted only on the fold's training groups;
- calibration does not see the validation labels used for final candidate comparison unless nested or otherwise separated;
- fold assignment is deterministic from a declared seed and grouping programme.

For small datasets, two-fold grouped CV may remain appropriate. Larger datasets should evaluate more folds or repeated group splits, provided application families remain isolated.

## 10. Feature selection and ablation

Feature selection is part of model selection and must remain inside development data.

Mandatory comparison includes:

- current full baseline;
- structural evidence only;
- no category;
- no severity;
- no title/description tokens;
- no detector-generated text;
- leave-one-detector-out;
- leave-one-template-family-out;
- leave-one-application-family-out;
- encoder versus non-encoder features where applicable.

A candidate that performs well only when detector or application identity leaks into features should be rejected or limited to an honestly narrower domain.

## 11. Ranking objective

The current implementation ranks by:

1. F1;
2. recall;
3. precision;
4. accuracy;
5. threshold closeness to 0.5;
6. deterministic candidate order.

This remains valid for the current controlled baseline.

Production selection should declare a task-specific objective, for example:

```text
primary: recall at fixed reviewer budget
safety floor: high-severity false-negative rate
secondary: precision at K
calibration floor: Brier/ECE threshold
coverage floor: minimum recommendation coverage after abstention
tie-breaker: lower latency/resource use
```

The ranking rule must be declared before comparing candidates.

Do not alter ranking weights after viewing the external holdout.

## 12. Classification metrics

Report:

- sample and group counts;
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
- ROC-AUC with class-balance caveats.

Every metric includes its exact positive class and threshold.

## 13. Review-prioritisation metrics

Because VulnHunter helps reviewers decide what to inspect first, report:

- precision at K;
- recall at K;
- average precision;
- recall under fixed review budgets;
- number needed to review per confirmed finding;
- false-negative count by severity;
- workload coverage after abstention;
- model-versus-baseline reviewer-ordering comparison.

A model may be useful as a ranking aid even when its hard binary threshold is not suitable for classification. Keep those claims separate.

## 14. Calibration metrics

Report:

- Brier score;
- log loss where numerically safe;
- expected calibration error;
- maximum calibration error;
- reliability table/diagram data;
- calibration slope/intercept where applicable;
- calibration by category;
- calibration by application family;
- calibration by severity;
- sample counts per bin/slice.

Raw Naive Bayes posterior values must be called raw scores or raw posterior probabilities, not calibrated confidence.

## 15. Calibration selection

Calibration candidates may include:

- no calibration baseline;
- Platt scaling;
- isotonic regression;
- another justified bounded method.

Calibration is selected using development groups only.

The calibration artifact records:

- base model identity/digest;
- feature extractor/schema;
- calibration groups;
- method and parameters;
- metrics before and after calibration;
- limitations;
- artifact digest.

A calibrator cannot be reused with a different base model merely because dimensions match.

## 16. OOD and abstention evaluation

Evaluate deterministic and learned OOD signals against intentionally excluded groups.

Report:

- OOD true-positive and false-positive rates;
- AUROC/AUPRC where meaningful;
- abstention rate;
- error rate among non-abstained predictions;
- coverage-risk curve;
- category/family coverage;
- reason-code distribution;
- severe false negatives remaining after abstention.

Test excluded:

- application families;
- categories;
- detector/template families;
- evidence schemas;
- source languages;
- artifact types;
- malformed inputs.

The safe expected outcome for unsupported inputs is abstention, not a negative prediction.

## 17. Category, family and detector diagnostics

The diagnostic report groups metrics by:

- category;
- application family;
- application instance;
- environment;
- detector;
- template family/revision;
- severity;
- campaign/release;
- source language or artifact type where relevant;
- known versus unseen domain.

A slice with too few samples is marked insufficient rather than displayed as a reliable percentage.

## 18. Confidence intervals and repeated runs

Where data supports them, report uncertainty across appropriate groups rather than pretending observations are independent.

Use:

- repeated declared seeds;
- group bootstrap by application family or instance;
- confidence intervals for key metrics;
- candidate-rank stability;
- threshold sensitivity;
- calibration stability;
- resource-use variability.

Do not average away a catastrophic family or severity failure.

## 19. Error analysis

Every candidate evaluation includes:

- redacted false negatives;
- redacted false positives;
- highest-confidence errors;
- low-margin cases;
- OOD failures;
- calibration failures;
- detector leakage evidence;
- family/category clusters;
- potential label conflicts requiring governance review;
- recommended additional data collection;
- limitations and rejection reasons.

Error analysis must not expose prohibited raw evidence.

## 20. External dataset and benchmark use

Public Hugging Face or external datasets may support research and pipeline tests.

Before use, record:

- dataset ID/source;
- official or unofficial status;
- license;
- synthetic/human-labelled status;
- task definition;
- duplicate and repository leakage risk;
- temporal leakage risk;
- languages;
- grouping keys;
- relation to VulnHunter's intended domain.

Examples such as unofficial BigVul mirrors, CodeXGLUE defect detection or synthetic security DPO pairs cannot serve as VulnHunter's real external product holdout.

They may validate code paths or representation-learning hypotheses only.

## 21. Resource and operational metrics

Compare candidates on:

- training duration;
- inference p50/p95/p99 latency;
- memory usage;
- package size;
- cold-start time;
- throughput;
- CPU/GPU requirements;
- dependency footprint;
- offline capability;
- provider cost where remote;
- failure and timeout behaviour.

A marginal metric gain may not justify a large, remote or fragile candidate.

## 22. Candidate acceptance report

A complete report contains:

- experiment and candidate IDs;
- exact data releases;
- partition programme;
- group counts;
- candidate grid;
- selected feature/model/calibration/OOD configuration;
- development metrics;
- external metrics if available;
- all required slices;
- uncertainty;
- errors;
- latency/resources;
- privacy/supply-chain summary;
- acceptance gates;
- pass/fail decision;
- reviewer identity;
- explicit recommendation: reject, continue research, validate, approve for shadow.

## 23. No automatic promotion

A passing metric report does not activate a model.

It may support a governance decision to register the candidate as validated or approved. Shadow, canary and active transitions remain separate authorised actions.

## 24. Current commands

The current implemented diagnostic command recomputes predictions only for the artifact's locked scan holdout and verifies dataset/benchmark provenance.

Future commands may add external family evaluation and calibration reports, but documentation must not imply they exist before implementation.

## 25. Testing requirements

Tests cover:

- deterministic group assignment;
- no scan/family leakage;
- fold-local feature schema;
- candidate-grid determinism;
- ranking tie-breakers;
- insufficient groups;
- calibration-data isolation;
- calibrator/model binding;
- OOD and abstention metrics;
- external-holdout lock;
- no post-holdout tuning;
- slice counts;
- PR-AUC and ranking metrics;
- confidence intervals where implemented;
- malformed or incompatible candidate reports;
- external dataset metadata and license requirements.

## 26. Current-versus-target classification

```text
SCAN-GROUP HOLDOUT                              IMPLEMENTED
TWO-FOLD GROUPED MODEL SELECTION                 IMPLEMENTED
FOLD-LOCAL FEATURE VOCABULARY                    IMPLEMENTED
NAIVE BAYES/ALPHA/THRESHOLD GRID                 IMPLEMENTED
CATEGORY AND SCAN DIAGNOSTICS                    IMPLEMENTED
APPLICATION-FAMILY GROUPING                      NOT COMPLETE
SEPARATE CALIBRATION PARTITION                   NOT COMPLETE
CALIBRATION ARTIFACT AND METRICS                 NOT COMPLETE
OOD AND COVERAGE-RISK EVALUATION                 NOT COMPLETE
REVIEW-BUDGET RANKING METRICS                    NOT COMPLETE
LOCKED EXTERNAL FAMILY HOLDOUT                   NOT COMPLETE
GROUPED CONFIDENCE INTERVALS                     NOT COMPLETE
TRANSFORMER/EMBEDDING CANDIDATE COMPARISON       RESEARCH-ONLY/NOT IMPLEMENTED
```

## 27. Definition of done

Model selection and evaluation are production-complete only when:

- application-family grouping is enforced;
- development, calibration and external groups are separated;
- candidate objectives are declared before evaluation;
- leakage ablations pass;
- classification, ranking, calibration and OOD metrics exist;
- abstention coverage-risk is measured;
- external family holdout is truly untouched;
- errors and limitations are documented;
- resource and privacy trade-offs are measured;
- candidate reports are immutable and registry-ready;
- no metric automatically grants activation authority.