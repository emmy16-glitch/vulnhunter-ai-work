# Current State

## Implemented capabilities

VulnHunter currently includes:

- strict laboratory target validation and explicit time-limited target authorization;
- loopback/private-address enforcement with immutable `ApprovedTarget` and `ScopedUrl` trust-boundary models;
- derived-link and redirect containment;
- connection-time DNS revalidation, approved-address TCP pinning, connected-peer verification, and original-host TLS preservation;
- central sensitive-data redaction;
- GET/HEAD-only HTTP policy with cancellation, request budgets, rate limiting, timeouts, and response-size limits;
- passive HTML mapping and passive security observations;
- SQLite persistence for scans, pages, observations, review decisions, authorization records, and audit events;
- immutable two-reviewer consensus, independent adjudication, and reviewer-specific queues;
- duplicate and conflicting-label quality gates;
- reviewed dataset export, scan-group-isolated splitting, model provenance, controlled benchmarks, and training-only model selection;
- bounded engineering orchestration with deterministic proof, role separation, hard stops, human approval, and learning records;
- immutable evaluator boundaries, isolated one-commit experiments, deterministic keep-or-revert decisions, and human-confirmed promotion;
- bounded non-executable meta-search guidance and GitHub Actions quality gates;
- runtime-enforced unattended permission manifests, fixed shell-free commands, blocker isolation, and critical-workflow halting;
- authenticated local governance identities with explicit administrator, reviewer, and adjudicator roles;
- governed collection campaigns bound to exact authorization snapshots, narrower collection limits, application metadata, and distinct approval;
- completed-scan correlation with authorization validation/start/completion evidence;
- explicit reviewer assignments, identity-bound review attestations, conflict checks, and creator/owner separation;
- fail-closed campaign completion and immutable dataset-release manifests;
- read-only governed pilot readiness reporting over release manifests,
  authorization provenance, exact scan links, review attestations, duplicate
  evidence indicators, class balance, and dataset fingerprints;
- a framework-independent operational product application layer with typed
  read models for dashboard, campaigns, readiness, role/skill registry, and
  bounded agent runtime inspection;
- a local product CLI surface backed by the real stores and services:
  `python -m vulnhunter.product`;
- an authenticated Django operational surface connected to governed assessment,
  approval, activity, evidence, and candidate-finding state;
- a versioned scanner-manager protocol shared by a controlled Nuclei harness and
  planned OpenVAS/mobile adapters;
- a file-backed Nuclei execution lifecycle with hash-linked audit transitions,
  bounded redacted capture, fail-closed recovery, and production execution
  blocked;
- a central scanner compatibility manifest and a disabled isolated-container
  worker boundary.

## Current interpretation

The platform is a secure research pipeline and decision-support prototype. It is not an autonomous vulnerability scanner, exploit framework, or production-grade vulnerability classifier.

The governed collection and authenticated-review control plane is implemented. That implementation proves workflow enforcement; it does not mean a diverse real dataset has already been collected.

The product blueprint now includes an authenticated Django browser surface with
session, CSRF, route authorization, approval, and operational read models. The
scanner worker remains separate and disabled: no real Nuclei, OpenVAS, or mobile
scanner process is connected.

## Current model status

Controlled benchmark results validate software plumbing and reproducibility only. They do not establish performance on real applications.

Before any real-world performance claim, the project still requires:

- collection across multiple intentionally diverse authorised local applications;
- independent governed review of every retained real observation;
- application-family metadata and group-isolated development/holdout partitions;
- a locked external holdout evaluated only after development decisions are frozen;
- calibration, category-specific, and repeated-run analysis;
- documented false-positive and false-negative error analysis.

## Current operational commands

Use CLI help as the exact current interface:

```bash
vulnhunter --help
vulnhunter scope --help
vulnhunter authorize --help
vulnhunter scan --help
vulnhunter findings --help
vulnhunter governance --help
vulnhunter governance identity --help
vulnhunter governance campaign --help
vulnhunter governance campaign readiness --help
vulnhunter ml --help
vulnhunter benchmark --help
vulnhunter loop --help
vulnhunter research --help
vulnhunter unattended --help
python -m vulnhunter.product --help
```

## Repository health

The repository should remain:

- testable offline;
- free of tracked secrets;
- free of tracked local databases and generated model artifacts;
- organised into focused commits;
- documented alongside architectural changes.
