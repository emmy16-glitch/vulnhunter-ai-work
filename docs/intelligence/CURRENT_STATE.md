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
- deterministic append-only campaign release provenance packages that retain exact
  application-family, environment, authorization, primary-review and adjudication
  hashes after a governed dataset release;
- a protected read-only campaign operations workspace that separates pre-activation
  owned-target prerequisites from post-collection review and release readiness,
  reports application-family coverage and adjudication workload, and withholds
  ownership evidence references and local repository paths from the browser;
- read-only governed pilot readiness reporting over release manifests,
  authorization provenance, exact scan links, review attestations, duplicate
  evidence indicators, class balance, and dataset fingerprints;
- an identity-separated signed final-remediation report and export-manifest path
  that cannot publish by itself;
- a dedicated separately authorised publication service with exact destination
  policy, digest-verified artifact copying, signed append-only manifests,
  correction, independent revocation and protected browser controls;
- publication deployment preflight, signed-state and copied-artifact integrity
  checks, and inspect-first recovery that never overwrites report artifacts;
- a framework-independent operational product application layer with typed
  read models for dashboard, campaigns, readiness, role/skill registry, and
  bounded agent runtime inspection;
- a local product CLI surface backed by the real stores and services:
  `python -m vulnhunter.product`;
- an authenticated Django operational surface connected to governed assessment,
  approval, activity, evidence, candidate-finding and release state;
- optional Groq and Hugging Face advisory providers wired into the persistent
  conversational workspace with deterministic high-impact action routing,
  redacted context, bounded reasoning budgets and provider/model provenance;
- secure provider setup and a provider-neutral `vh_verify_llm` command that proves
  one harmless answer passes through the exact browser conversation path rather
  than accepting credential presence or low-level API reachability as readiness;
- a versioned scanner-manager protocol shared by a controlled Nuclei worker and
  planned mobile adapters;
- a file-backed Nuclei execution lifecycle with hash-linked audit transitions,
  bounded redacted capture, fail-closed recovery, and one activated passive
  RFC1918 private-lab path;
- a central scanner compatibility manifest, signed worker spool, restricted remote
  bridge and phone-only Codespaces laboratory.

## Current interpretation

The platform is a secure research pipeline and decision-support prototype with a narrowly controlled passive private-lab scanner path. It is not an autonomous public-Internet scanner, exploit framework, automatic vulnerability publisher, or production-grade vulnerability classifier.

The governed collection and authenticated-review control plane is implemented. The release provenance package now preserves exact application-family and review/adjudication lineage after a governed dataset release. The protected campaign operations workspace truthfully reports whether an approved or active campaign still satisfies private-target authorization, ownership-evidence declaration, family-diversity and review-separation prerequisites. These implementations prove workflow enforcement; they do not mean a diverse real dataset has already been collected, and an ownership declaration is not treated as proof without independent human verification.

The dedicated publication foundation is implemented and operationally hardened, but remains separately activation-gated by deployment-owned keys, authority identities and destination configuration. It does not publish reports merely because they were generated or approved, and it does not merge code, deploy software or close findings.

The product includes an authenticated Django browser surface with session, CSRF,
route authorization, exact approval, operational read models and a separate signed
Nuclei worker. The reviewed passive pilot can run one pinned template against one
exact authorized RFC1918 target. Public scanning, intrusive execution and dynamic
mobile analysis remain unavailable.

Remote LLM answers remain optional advisory output. A deployment can now verify the
same prompt construction, provider wrapper, structured decoding and user-facing
answer path used by the browser. Passing that readiness check proves connectivity
and integration only; deterministic services still own authorization, approvals,
scanner execution, finding verification, severity and publication.

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
python manage.py vh_configure_groq --help
python manage.py vh_configure_huggingface --help
python manage.py vh_verify_llm --help
python manage.py vh_publication_preflight --help
python manage.py vh_publication_recover --help
python manage.py vh_campaign_release_package --help
```

## Repository health

The repository should remain:

- testable offline;
- free of tracked secrets;
- free of tracked local databases and generated model artifacts;
- organised into focused commits;
- documented alongside architectural changes.
