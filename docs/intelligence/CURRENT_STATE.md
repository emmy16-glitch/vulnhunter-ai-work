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
- deterministic Multinomial and Bernoulli Naive Bayes research baselines with explicit thresholds;
- safe bounded JSON model artifacts rather than executable pickle artifacts;
- locked scan-holdout diagnostics by category and scan;
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

The governed collection and authenticated-review control plane is implemented. The release provenance package preserves exact application-family and review/adjudication lineage after a governed dataset release. The protected campaign operations workspace truthfully reports whether an approved or active campaign still satisfies private-target authorization, ownership-evidence declaration, family-diversity and review-separation prerequisites. These implementations prove workflow enforcement; they do not mean a diverse real dataset has already been collected, and an ownership declaration is not treated as proof without independent human verification.

The dedicated publication foundation is implemented and operationally hardened, but remains separately activation-gated by deployment-owned keys, authority identities and destination configuration. It does not publish reports merely because they were generated or approved, and it does not merge code, deploy software or close findings.

The product includes an authenticated Django browser surface with session, CSRF,
route authorization, exact approval, operational read models and a separate signed
Nuclei worker. The reviewed passive pilot can run one pinned template against one
exact authorized RFC1918 target. Public scanning, intrusive execution and dynamic
mobile analysis remain unavailable.

Remote LLM answers remain optional advisory output. A deployment can verify the
same prompt construction, provider wrapper, structured decoding and user-facing
answer path used by the browser. Passing that readiness check proves connectivity
and integration only; deterministic services still own authorization, approvals,
scanner execution, finding verification, severity and publication.

## Current product-experience classification

### AI-first assessment workspace reconciliation — 2026-08-07

The complete **Programme 1 AI-first assessment workspace repository-supported runtime scope is implemented and automatically verified** for website, APK and Source Hunt workflows. This completion statement supersedes the earlier reconciliation that stopped at PR #115; subsequent owner-document review identified and closed the remaining result-disposition, report-format and cross-assessment Findings continuity gaps before this final classification.

The implemented runtime now provides:

- one workflow-neutral selected-assessment projection binding chat, Activity, inspector, history, Findings, Evidence, contextual evidence relationships and Report to the same durable assessment identity;
- monotonic persisted projection revisions and one read-only frontend selected-assessment store, with stale reconnect responses and faulty subscribers unable to create a competing lifecycle source;
- one canonical assessment lifecycle with independent assessment, worker and advisory-provider health, typed actionable failures and scoped idempotent retry behaviour;
- one persisted task card and durable activity timeline using measured byte/stage progress or explicit unmeasured state, with fabricated percentages rejected;
- an idempotent APK finalisation path from resumable upload through immutable artifact creation, durable assessment create-or-bind, plan/task graph, approval, queue/worker recovery, persisted partial evidence, deterministic verification/abstention, bounded review receipt and evidence-backed report readiness;
- durable APK completion receipts and browser reconciliation for timeout-after-success, refresh, cleared local state and device-switch recovery without duplicate finalisation or queue work;
- contextual desktop assessment inspection and a mobile route/sheet preserving selected assessment and specialist context across refresh and Back navigation;
- consolidated mobile navigation around Chat, Activity, Findings and More, with Summary, Activity, Findings, Evidence and Report kept as assessment-scoped specialist views and Graph retained only as contextual Evidence relationships when meaningful persisted relationships exist;
- a simplified composer whose provider and answer-detail controls remain behind Advanced settings while deterministic workflows remain available without optional providers;
- website and Source Hunt flows routed through the same selected-assessment contract while retaining their existing authorisation, private-target, source-processing and worker restrictions;
- role-based entry, compact accessible empty states and ordinary-language assessment copy;
- persisted verified/rejected/abstained result disposition truth without browser-invented finding counts or attack relationships;
- one server-owned report-format readiness contract for HTML, JSON, SARIF, Evidence ZIP and PDF: contextual HTML becomes available only when the persisted report receipt is ready, JSON exposes persisted selected-assessment state, and unimplemented SARIF, Evidence ZIP and PDF renderers remain explicitly unavailable with reasons;
- server-selected Findings continuity across navigation and refresh, explicit assessment deep links that replace stale selection, deliberate account-wide Findings only through explicit global scope, and private-not-found behaviour for unknown or unreadable assessment selection.

The final runtime reconciliation was merged in dependency order through PR #117, PR #119 and PR #121. PR #119 merged as `491144f99a2e9f4eff956242e7fe582bc8eb7f59`; its exact head `6ae81ead0585eebd97b0e78ff9a54c1eafa90fb3` passed VulnHunter quality gates #1689, Conversational workspace quality #1194 and Phone acceptance #648, including Python 3.11/3.12 verification, Ruff lint/format, compile, scanner compatibility, restricted-worker checks, full tests, repository audit, conversational browser lifecycle, responsive UI and genuine RFC1918 Nuclei acceptance. PR #121 merged as `ef1bb60df42fd0bd0a4229e86626c340bd9a1110`; its exact head `d89d9cf725b5718cdb36ce569c8fe9a40a2a4222` passed VulnHunter quality gates #1691, Conversational workspace quality #1195 and Phone acceptance #650 with the same repository-required gate family.

This automated completion claim is deliberately narrower than physical-device acceptance. **No new physical Android performance, TalkBack, bright-environment contrast or non-technical usability evidence was collected in this reconciliation.** Those remain manual evidence categories and must not be inferred from Chromium phone acceptance or responsive-browser automation. Real-data collection and external-holdout evidence are also separate from this product-runtime programme.

Current classification:

```text
BACKEND SECURITY AND GOVERNANCE FOUNDATIONS   IMPLEMENTED
CONVERSATIONAL ENTRY POINT                    IMPLEMENTED
PERSISTED WORKER AND UPLOAD FOUNDATIONS       IMPLEMENTED
ONE CONSISTENT ASSESSMENT SOURCE OF TRUTH     IMPLEMENTED
LIVE AGENT EXECUTION EXPERIENCE               IMPLEMENTED
ACTIONABLE FAILURE AND RECOVERY EXPERIENCE    IMPLEMENTED
DESKTOP CONTEXTUAL INSPECTOR                  IMPLEMENTED
PHONE-FIRST RESPONSIVE WORKSPACE              IMPLEMENTED — AUTOMATED ACCEPTANCE
CONSOLIDATED NAVIGATION                       IMPLEMENTED
ASSESSMENT-SCOPED FINDINGS/EVIDENCE/REPORTS   IMPLEMENTED
REPORT FORMAT READINESS                       IMPLEMENTED — TRUTHFUL AVAILABILITY CONTRACT
AI-FIRST PRODUCT EXPERIENCE                   IMPLEMENTED — PROGRAMME 1 AUTOMATED SCOPE
PHYSICAL ANDROID/TALKBACK/USABILITY EVIDENCE  MANUAL — NOT RECOLLECTED IN THIS RECONCILIATION
PREMIUM INTERACTION/MOTION SYSTEM             IN PROGRESS — FOUNDATION MERGED IN PR #118
```

Programme 2 is now the active product programme. Premium interaction work may improve motion, primitive states, overlay ownership, session continuity, send/stream/retry/autoscroll behaviour, mobile direct manipulation and accessibility only on top of the authoritative Programme 1 state, lifecycle, navigation and security boundaries; it must not introduce a second state owner or use motion to imply progress, authority or success.

## Current ML and Hugging Face architecture review — 2026-08-02

A repository and Hugging Face ecosystem review confirmed that VulnHunter is stronger in security boundaries, evidence governance and reproducible baseline engineering than in production MLOps.

### Implemented and verified as repository capabilities

- human-reviewed binary labels remain separate from predictions;
- duplicate and conflicting-label controls;
- complete-scan group isolation;
- training-only two-fold grouped model selection;
- deterministic privacy-conscious features;
- Multinomial and Bernoulli Naive Bayes candidates;
- explicit decision thresholds;
- bounded non-executable JSON artifacts;
- dataset, feature, split and benchmark provenance;
- locked scan-holdout diagnostics;
- optional bounded Groq advisory provider;
- optional bounded Hugging Face advisory provider;
- explicit remote model allowlists;
- credential-file permissions and endpoint restrictions;
- safe `ABSTAIN` behaviour on remote-provider failure;
- provider-neutral full browser-path readiness verification.

### Documented architecture, not yet implementation

The following target architecture is now specified in `docs/intelligence/ML_AND_HUGGING_FACE_PRODUCTION_ARCHITECTURE.md`, but it is **not** implemented merely because the document exists:

- production training bound to verified immutable governed dataset releases;
- release correction/withdrawal impact on dependent models;
- application-family, application-instance and deployment-environment grouping enforced by ML partitions;
- a genuinely untouched application-family external holdout;
- separate development training and calibration groups;
- a versioned pluggable feature-extractor interface;
- revision-pinned local Hugging Face encoders;
- detector/template/application leakage ablations;
- probability calibration artifacts;
- explicit out-of-distribution detection;
- explicit model abstention for uncertain or unfamiliar inputs;
- review-budget and ranking metrics;
- grouped confidence intervals and repeated-seed reports;
- immutable model registry states and lineage;
- separate human promotion and deployment activation;
- complete-package activation, rollback and revocation;
- shadow and canary inference;
- delayed joins from predictions to consensus/adjudicated outcomes;
- production monitoring, drift and incident response;
- exact Hugging Face model/tokenizer revision and capability profiles;
- safe model/tokenizer supply-chain manifests and SBOM;
- local assessment-scoped embeddings and retrieval;
- Source Hunt code-model retrieval experiments;
- assessment-scoped evidence-grounded conversational citations;
- bounded provider streaming with final structured validation.

### Important corrected documentation issue

Earlier provider-routing documentation stated that Groq was the only AI/model provider in the production architecture. That statement contradicted the implemented optional Hugging Face advisory provider.

The provider architecture is now documented truthfully as provider-neutral with two currently implemented optional remote advisory providers:

- Groq;
- Hugging Face OpenAI-compatible router.

This documentation correction does not change runtime code and does not prove exact-revision Hugging Face capability profiles are implemented.

### Current ML classification

```text
HUMAN REVIEW AS LABEL AUTHORITY                  IMPLEMENTED
DUPLICATE/CONFLICT DATA GATES                    IMPLEMENTED
SCAN-GROUP SPLITTING                             IMPLEMENTED
TRAINING-ONLY BASELINE MODEL SELECTION           IMPLEMENTED
SAFE JSON MODEL ARTIFACTS                        IMPLEMENTED
CONTROLLED BENCHMARK AND DIAGNOSTICS             IMPLEMENTED
OPTIONAL GROQ ADVISORY PROVIDER                  IMPLEMENTED
OPTIONAL HUGGING FACE ADVISORY PROVIDER          IMPLEMENTED
PROVIDER-NEUTRAL END-TO-END READINESS CHECK      IMPLEMENTED
GOVERNED RELEASE-BOUND PRODUCTION TRAINING       NOT COMPLETE
APPLICATION-FAMILY EXTERNAL HOLDOUT              NOT COMPLETE
CALIBRATION                                      NOT COMPLETE
OOD DETECTION                                    NOT COMPLETE
EXPLICIT CLASSIFIER ABSTENTION                   NOT COMPLETE
MODEL REGISTRY/PROMOTION/ACTIVATION              NOT COMPLETE
SHADOW/CANARY DEPLOYMENT                         NOT COMPLETE
MODEL DRIFT AND OUTCOME MONITORING               NOT COMPLETE
REVISION-PINNED HF CAPABILITY REGISTRY           NOT COMPLETE
LOCAL HF EMBEDDING/FEATURE PIPELINE              NOT COMPLETE
ASSESSMENT-SCOPED RETRIEVAL AND CITATIONS        NOT COMPLETE
PRODUCTION VULNERABILITY CLASSIFIER              NOT ESTABLISHED
```

### Current model interpretation

The existing Naive Bayes model is an honest, inspectable software and research baseline. It should be preserved as a comparison point.

It must not be described as production-ready because:

- controlled benchmark performance is not real-application performance;
- scan isolation does not yet prove application-family generalisation;
- raw posterior values are not calibrated real-world probabilities;
- the current binary contract lacks an explicit uncertainty/OOD abstention path;
- no production registry, shadow, rollback or drift lifecycle exists;
- no sufficiently diverse governed real external holdout has been evaluated.

A larger Hugging Face model is not the next automatic step. Dataset lineage, family grouping, calibration, abstention, registry, rollback and monitoring must be established first.

## Required implementation order

The binding order is:

1. finish current active bounded implementation work;
2. complete the AI-first assessment workspace programme;
3. complete the premium interaction, motion and conversation programme;
4. execute the ML and Hugging Face programme in `ML_AND_HUGGING_FACE_PRODUCTION_ARCHITECTURE.md`;
5. continue remaining scanner, isolation, dataset-acquisition and production-deployment milestones.

The AI-first assessment workspace programme is complete in its automated repository-supported runtime scope. Programme 2 is therefore the active product programme. Do not begin Programme 3 ML/Hugging Face implementation until Programme 2 is also complete and accurately reconciled here.

## Real-world performance prerequisites

Before any real-world performance claim, the project still requires:

- collection across multiple intentionally diverse authorised local applications;
- independent governed review of every retained real observation;
- immutable verified dataset releases used directly by production training;
- complete application-family and instance metadata;
- group-isolated development and calibration partitions;
- a locked external application-family holdout evaluated only after all development decisions are frozen;
- leakage and ablation analysis;
- calibration, OOD and coverage-risk analysis;
- ranking and review-budget metrics;
- repeated-seed and grouped uncertainty analysis;
- documented false-positive and false-negative error analysis;
- model registry, shadow and rollback evidence;
- privacy, supply-chain and operational acceptance.

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

Commands proposed in future architecture documents are not operational until implemented and exposed by these help surfaces.

## Repository health

The repository should remain:

- testable offline;
- fully usable without optional remote providers;
- free of tracked secrets;
- free of tracked local databases and generated model artifacts;
- free of unreviewed executable model formats and remote custom code;
- organised into focused bounded commits;
- documented alongside architectural changes;
- truthful about implemented, partial, research-only and unavailable capabilities.