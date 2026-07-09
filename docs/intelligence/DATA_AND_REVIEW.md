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

## Review workflow

1. Display prioritised redacted evidence.
2. Let the reviewer inspect one observation.
3. Record an explicit decision.
4. Preserve the decision and note.
5. Detect repeated fingerprints and conflicting labels.
6. Block training when unresolved conflicts remain.

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
- Are conflicts resolved?
- Is the split scan-group isolated?
- Is the dataset hash recorded?
