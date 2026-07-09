# Experiment Log

Record every meaningful model experiment here. Do not overwrite history.

## Required experiment fields

- date/time in UTC;
- Git commit;
- dataset SHA-256;
- training context;
- sample and scan counts;
- class distribution;
- duplicate/conflict status;
- split strategy and scan IDs;
- feature schema;
- model candidates;
- selected model and threshold;
- training-selection metrics;
- locked-holdout metrics;
- error summary;
- conclusion;
- artifact path.

## Recorded milestones

### Baseline controlled benchmark

Purpose: verify the complete reviewed-data training pipeline and honest provenance.

Observed result:

- accuracy: `0.500`;
- precision: `1.000`;
- recall: `0.143`;
- F1: `0.250`.

Conclusion: plumbing and provenance worked, but the model missed most confirmed observations. The artifact must remain a weak baseline rather than being presented as successful detection.

### Training-only model-selection experiment

Purpose: compare candidate estimators and thresholds using training scans only, then evaluate the locked holdout once.

Record the actual output produced by the local run below before making claims:

```text
Git commit:
Artifact:
Selected model:
Selected alpha:
Selected threshold:
Training-only validation:
Holdout confusion matrix:
Holdout precision:
Holdout recall:
Holdout F1:
Category errors:
Scan errors:
Conclusion:
```

## Experiment rule

Never delete an unfavourable result. Negative results are part of the project evidence.
