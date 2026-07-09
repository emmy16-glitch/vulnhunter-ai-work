# Machine-Learning Governance

## Purpose

The model prioritises or classifies reviewed passive observations for decision support. It does not determine vulnerability truth.

## Training eligibility

Training must fail safely when any configured requirement is unmet:

- minimum total reviewed samples;
- minimum samples per class;
- minimum independent scans;
- minimum scans per class;
- no unresolved label conflicts;
- viable scan-group split.

## Leakage prevention

All observations from one scan belong to one partition only.

Model-selection flow:

```text
reviewed unique data
    -> grouped training/holdout split
    -> model selection using training scans only
    -> lock configuration
    -> one holdout evaluation
```

Do not repeatedly tune against holdout errors.

## Provenance requirements

Every model artifact should record:

- artifact schema version;
- application version;
- creation time;
- training context;
- model type and configuration;
- feature schema;
- dataset SHA-256;
- source and deduplicated sample counts;
- repeated samples excluded;
- split strategy;
- training and holdout scan IDs;
- random seed;
- training-selection metrics;
- holdout metrics;
- benchmark identifiers when applicable.

## Metric interpretation

Report at least:

- accuracy;
- precision;
- recall;
- F1;
- confusion-matrix counts.

Accuracy alone is insufficient.

A high precision with low recall may mean the model rarely predicts the positive class. A perfect synthetic score may mean the benchmark is easy rather than the model is production-ready.

## Benchmark policy

Controlled benchmark data is useful for:

- verifying pipeline correctness;
- reproducing experiments;
- testing provenance;
- exercising error diagnostics.

It is not evidence of performance on unknown real applications.

## Promotion standard

A model should not be promoted beyond research status without:

- diverse authorised applications;
- independent reviewers or adjudication;
- external holdout data;
- category-level error analysis;
- calibration analysis;
- repeatability across seeds and application groups;
- documented limitations and intended use.
