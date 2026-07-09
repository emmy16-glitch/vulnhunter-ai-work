# VulnHunter baseline machine-learning pipeline

## Purpose

The baseline model is a local decision-support component trained only from human-reviewed passive observations. It predicts whether an observation resembles a `confirmed` finding or a `false_positive`. It never scans targets, changes labels, approves findings, or replaces human review.

## Data boundary

Eligible labels:

- `confirmed`
- `false_positive`

Excluded from training:

- `unreviewed`
- `needs_review`
- review notes
- raw response bodies
- authentication data, cookies, and secrets

The exported JSONL dataset contains already-redacted observation fields. The model uses structural URL features rather than hostname or path tokens.

## Feature engineering

The schema is learned from the training split only to avoid holdout leakage. Features include:

- severity one-hot values;
- observed category one-hot values;
- bounded title and description token vocabulary;
- URL scheme, query presence, and path depth;
- bounded evidence counts and HTTP status buckets.

## Model and evaluation

The first model is a lightweight Multinomial Naive Bayes classifier implemented with the Python standard library. It is intentionally small, deterministic, inspectable, and suitable for the laboratory VM.

Training uses a deterministic stratified holdout split. The artifact records accuracy, precision, recall, F1, confusion-matrix counts, application version, random seed, feature schema, and a SHA-256 digest of the reviewed dataset.

## Artifact safety

Models are JSON rather than pickle, so loading a model does not execute arbitrary Python code. Reads are capped at 10 MiB, internal dimensions are validated, and writes are atomic with owner-only permissions.

## Minimum data rule

The default training command requires at least 20 binary-reviewed observations and at least 5 examples from each class. More diverse reviewed data is needed before treating metrics as representative.
