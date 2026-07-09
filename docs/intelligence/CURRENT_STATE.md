# Current State

## Implemented capabilities

VulnHunter currently includes:

- strict laboratory target validation;
- loopback/private-address enforcement;
- immutable `ApprovedTarget` and `ScopedUrl` trust-boundary models;
- derived-link and redirect containment;
- central sensitive-data redaction;
- GET/HEAD-only HTTP policy;
- cancellation, request budgets, rate limiting, timeout controls, and body-size limits;
- manual redirect validation;
- passive HTML mapping;
- passive security observations;
- SQLite scan, page, observation, and review persistence;
- human review queue and explicit labels;
- duplicate and conflicting-label quality gates;
- reviewed dataset export;
- scan-group-isolated training and holdout evaluation;
- model artifact provenance and integrity metadata;
- controlled synthetic benchmark workflow;
- training-only model selection and holdout diagnostics.

## Current interpretation

The platform is a secure research pipeline and decision-support prototype. It is not an autonomous vulnerability scanner, exploit framework, or production-grade vulnerability classifier.

## Current model status

Controlled benchmark results validate software plumbing and reproducibility only. They do not establish performance on real applications.

Before any real-world performance claim, the project still requires:

- diverse authorised applications;
- independently reviewed observations;
- broader category coverage;
- external validation;
- calibration analysis;
- repeated experiments across application families;
- documented error analysis.

## Current operational commands

Use the CLI help as the exact current interface:

```bash
vulnhunter --help
vulnhunter scope --help
vulnhunter scan --help
vulnhunter findings --help
vulnhunter ml --help
vulnhunter benchmark --help
```

## Repository health

The repository should remain:

- testable offline;
- free of tracked secrets;
- free of tracked local databases and generated model artifacts;
- organised into focused commits;
- documented alongside architectural changes.
