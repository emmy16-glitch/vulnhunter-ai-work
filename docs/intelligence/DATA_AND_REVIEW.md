# Data and Human Review

## Observation model

An observation represents passive evidence about a page or response. It is not itself a confirmed vulnerability.

Expected fields include:

- scan and page identity;
- category and severity;
- redacted title and evidence;
- source URL;
- timestamps;
- human label and note when reviewed.

## Review states

The system uses explicit review labels such as:

- `confirmed`;
- `false_positive`;
- `needs_review`.

Unreviewed observations must not enter the training dataset.

## Governed review workflow

1. Display prioritised redacted evidence.
2. Record one immutable decision from the first pseudonymous reviewer.
3. Keep the effective label as `needs_review`.
4. Present the case only to a distinct second reviewer.
5. Matching decisions establish consensus.
6. Conflicting decisions create a dispute and remain `needs_review`.
7. A third person, distinct from both primary reviewers, records an adjudication and rationale.
8. Preserve every decision, timestamp, note, and final resolution.
9. Block unresolved cases from training.

Historical and controlled-benchmark labels remain available as legacy review state for reproducibility. New manual labels must use the governed workflow.

## Duplicate policy

Repeated equivalent observations may occur across pages or scans. Dataset preparation must distinguish:

- exact/repeated samples that should be excluded;
- independent scan evidence that provides useful diversity;
- conflicting human labels that require resolution.

## Privacy policy

Training data must use structured, sanitised fields. Do not include:

- raw response bodies;
- complete cookies;
- tokens;
- credentials;
- personal information;
- unrestricted free-form target data.

## Dataset quality questions

Before training:

- Are both classes represented?
- Are enough independent scans represented?
- Does each class span multiple scans?
- Are duplicate samples excluded?
- Are all new manual labels supported by consensus or adjudication?
- Are review disputes resolved?
- Is the split scan-group isolated?
- Is the dataset hash recorded?

For governed pilot releases, run the campaign readiness assessment before any
model experiment. The assessment records release-manifest integrity,
authorization and scan provenance, final-review completeness, duplicate
fingerprint and evidence indicators, reviewer status, application-family
diversity, class balance, leakage warnings, and deterministic dataset/report
fingerprints. It does not train, tune, select, or promote a model.
