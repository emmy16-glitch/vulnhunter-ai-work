# Model Selection and Locked-Holdout Diagnostics

Milestone 9 keeps the controlled benchmark honest by separating model selection
from final evaluation.

## Data boundaries

1. The reviewed dataset is deduplicated and split by complete scan IDs.
2. Holdout scan IDs are locked before any candidate is compared.
3. Only training scans enter two-fold grouped cross-validation.
4. Feature vocabularies are rebuilt from each fold's training partition.
5. Algorithm, smoothing, and threshold are selected by training-only F1 score.
6. The selected configuration is fitted on all training scans.
7. The untouched holdout scans are evaluated once and stored in the artifact.

No observation from a holdout scan is used to choose an algorithm, alpha value,
decision threshold, category vocabulary, or text vocabulary.

## Candidate family

The fixed candidate grid compares Multinomial and Bernoulli Naive Bayes, four
smoothing values, and five positive-class thresholds. The grid is intentionally
small, deterministic, and recorded in the model artifact.

## Context features

The feature schema adds predeclared, privacy-safe indicators for sensitive and
public URL-path context, missing-header identities, debug-indicator identities,
disclosed header names, response status families, and directory-index context.
Arbitrary raw paths, response bodies, credentials, and disclosed header values
are not added as features.

## Diagnostics

`vulnhunter benchmark diagnose` recomputes predictions only for the artifact's
locked holdout scans. It verifies dataset and benchmark provenance before
showing the confusion matrix, category metrics, scan metrics, false negatives,
and false positives. It does not retrain the model or alter human labels.

Synthetic benchmark metrics validate pipeline behaviour only. They are not an
estimate of performance on real applications.
