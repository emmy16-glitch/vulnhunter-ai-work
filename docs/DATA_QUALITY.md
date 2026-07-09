# Dataset integrity and review workflow

VulnHunter treats human review as the source of truth. Model predictions never
change stored review labels.

## Review workflow

Use the queue to work through the highest-severity findings first:

```bash
vulnhunter findings queue --database vulnhunter.db
vulnhunter findings show OBSERVATION_ID --database vulnhunter.db
vulnhunter findings label OBSERVATION_ID confirmed --database vulnhunter.db
vulnhunter findings label OBSERVATION_ID false_positive --database vulnhunter.db
```

Repeated fingerprints are displayed as review context. Reviewers must still
inspect the current observation because repeated evidence can occur in a changed
environment.

## Training readiness

```bash
vulnhunter ml readiness --database vulnhunter.db
```

The default gates require:

- at least 20 unique reviewed observations;
- at least 5 examples for each binary class;
- at least 4 independent scans;
- each class appearing in at least 2 scans;
- no fingerprint carrying conflicting human labels;
- a feasible holdout split that keeps entire scans isolated.

Repeated observations with the same fingerprint and label are reduced to one
canonical example. Conflicting labels for the same fingerprint block training
until a reviewer resolves the disagreement.

## Leakage-resistant evaluation

Training and holdout data are divided by complete scan IDs rather than by
individual observations. An observation from one scan can never be in training
while another observation from that same scan is in holdout evaluation.

The version 2 model artifact records:

- source and deduplicated sample counts;
- number of repeated samples excluded;
- split strategy;
- training scan IDs;
- holdout scan IDs;
- dataset SHA-256 and evaluation metrics.

This provides traceable evaluation and prevents inflated metrics caused by
near-identical findings from the same scan appearing on both sides of the split.
