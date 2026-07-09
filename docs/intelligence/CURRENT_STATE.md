# Current State

## Implemented capabilities

VulnHunter currently includes:

- strict laboratory target validation;
- explicit time-limited target authorization with revocation and audit events;
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
- first-review and reviewer-specific second-review queues;
- immutable two-reviewer consensus and independent adjudication;
- duplicate and conflicting-label quality gates;
- reviewed dataset export;
- scan-group-isolated training and holdout evaluation;
- model artifact provenance and integrity metadata;
- controlled synthetic benchmark workflow;
- training-only model selection and holdout diagnostics;
- bounded engineering orchestration with deterministic proof, role separation, hard stops, human approval, and learning records.
- immutable evaluator resource classes and protected baseline snapshots;
- isolated one-commit transactional experiments with deterministic keep-or-revert decisions;
- human-confirmed promotion of accepted candidates;
- bounded outer-loop search-diversity analysis with no executable code injection;
- GitHub Actions quality gates for supported Python versions.
- runtime-enforced unattended permission manifests with independent approval;
- scheduling guidance for interactive, session, local scheduled, CI, and remote modes;
- shell-free fixed command execution with integrity-linked evidence;
- two-failure blocker isolation and critical-workflow halting;
- connection-time DNS revalidation inside the transport;
- TCP connections bound to approved IPv4/IPv6 addresses;
- connected-peer verification and approved-address-only retries;
- preservation of the original HTTP Host and TLS SNI/certificate hostname;
- immutable connection audit evidence exposed by the safe client.

## Current interpretation

The platform is a secure research pipeline and decision-support prototype. It is not an autonomous vulnerability scanner, exploit framework, or production-grade vulnerability classifier.

## Current model status

Controlled benchmark results validate software plumbing and reproducibility only. They do not establish performance on real applications.

Before any real-world performance claim, the project still requires:

- diverse authorised applications;
- diverse observations reviewed through consensus or adjudication;
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
vulnhunter authorize --help
vulnhunter scan --help
vulnhunter findings --help
vulnhunter ml --help
vulnhunter benchmark --help
vulnhunter loop --help
vulnhunter research --help
vulnhunter unattended --help
```

## Repository health

The repository should remain:

- testable offline;
- free of tracked secrets;
- free of tracked local databases and generated model artifacts;
- organised into focused commits;
- documented alongside architectural changes.
