# Current State

## Current reconciliation — 2026-08-20

This section is the present-head reconciliation. The programme/PR ledger retained later in this document is historical evidence from earlier delivery slices; where a historical status such as “PR #135 pending” conflicts with this section or the current Git history, treat it as point-in-time history rather than current repository state.

The current repository now also includes capabilities delivered after that historical programme snapshot:

- the chat-first workspace composition/refinement merged through PR #175, including protected conversation width, contextual inspector behavior, responsive/mobile acceptance, persisted task continuity and removal of fake client-side word streaming;
- ordinary conversational high-reasoning availability routing with a silent `Groq -> Gemini -> loopback Ollama` chain, process-local circuit cooldown/recovery, provider-neutral user-facing copy, and short connection/long bounded read timeouts; exact-approved Source Hunt and finding-intelligence reasoning remain provider/model bound and do not inherit that cross-provider fallback;
- normalized APK intelligence that separates verified configurations, verified security findings, evidence-required candidates, operational issues, tool coverage, component surfaces, endpoint references, ownership, transport correlations and bounded-negative limitations;
- a real V380 static acceptance posture with six completed static tools, JADX partial, native analysis not applicable where no native libraries exist, dynamic analysis blocked behind its governed runtime gate, 18 verified configuration facts, 13 evidence-required candidates, and zero deterministically verified security vulnerabilities in the referenced acceptance slice;
- Mobile Source Hunt as a deterministic APK-backed code-level attack-surface investigation path with persisted provenance-bearing graph nodes/edges, explicit guards/controls, bounded-negative semantics and `verified` / `rejected` / `inconclusive` / `evidence_required` / `blocked` dispositions; the V380 Source Hunt acceptance intentionally promoted zero verified findings under partial source coverage;
- Browser Intelligence with pinned Obscura stdio MCP, typed policy-checked `BrowserAction` dispatch, screenshot/network/console evidence, owner/workspace persistence, complete supported-tool preflight, screenshot evidence byte limits, and persisted state restoration after web-process/runtime detachment without silently spawning a second browser;
- richer ML task/review contracts in `vulnhunter/ml/tasks.py`; model outputs remain advisory and human review remains authoritative.

Current important limitations remain explicit rather than implied away:

- PostgreSQL is the intended production Django authority, but legacy subsystem SQLite stores still exist and the complete authoritative-state migration is not finished;
- Browser Intelligence persists/reconstructs state and evidence, but a distributed live-runtime registry/reattachment mechanism for seamless continuation across worker-process loss is not complete;
- Browser Intelligence does not yet claim automatic runtime-browser-to-source-code attack-graph correlation; such edges require exact persisted evidence/provenance rather than string matching;
- APK dynamic analysis remains fail-closed until the approved isolated runtime, digest-bound approval, device identity and network policy exist;
- JADX processing is still bounded/partial rather than a complete resumable DEX-by-DEX source denominator;
- no V380 candidate should be called a verified vulnerability unless deterministic promotion evidence is added.

## Implemented capabilities

VulnHunter is an authorised, laboratory-only security-research and decision-support platform. The repository currently includes:

- strict loopback/private-lab target validation, explicit time-limited authorisation, redirect/derived-link containment, connection-time DNS revalidation, pinned approved-address transport, peer verification and bounded GET/HEAD collection;
- central redaction, bounded response handling, passive mapping and passive security observations;
- Django persistence with PostgreSQL production configuration plus legacy bounded subsystem stores that have not all been migrated yet;
- two-reviewer consensus, independent adjudication, reviewer-specific queues, duplicate/conflicting-label gates and immutable review attestations;
- governed collection campaigns, campaign/authorisation binding, application metadata, release manifests and deterministic release-provenance packages;
- controlled reviewed-dataset export, scan-group-isolated splits, deterministic Multinomial/Bernoulli Naive Bayes research baselines, bounded JSON model artifacts and locked holdout diagnostics;
- bounded orchestration, evaluator separation, unattended permission manifests and fail-closed verifier contracts;
- authenticated Django product surfaces, a persistent conversational workspace, optional advisory model providers with ordinary-chat failover, provider-bound protected reasoning paths, and provider-neutral browser/runtime readiness checks;
- a versioned scanner-manager protocol, signed worker spool, restricted remote bridge and activated bounded passive laboratory scanner paths;
- APK intelligence, Mobile Source Hunt and governed Browser Intelligence foundations described in the current reconciliation above;
- a separately authorised publication foundation with signed state, destination policy, correction/revocation and recovery checks.

The platform is not an autonomous public-Internet exploit framework, automatic vulnerability publisher or production-grade vulnerability classifier. Human review, deterministic services and verified evidence remain authoritative.

## Product programme status

The numbered programme narrative below is retained as a historical delivery ledger. Exact PR/gate statements describe the repository at the time those sections were written; the **Current reconciliation — 2026-08-20** section above owns present-head status where later work supersedes them.

### Programme 1 — AI-first assessment workspace

**Historical status: COMPLETE for repository-supported automated runtime scope.**

The implemented runtime provides one authoritative selected-assessment projection across Chat, Activity, inspector, history, Findings, Evidence and Report; monotonic persisted projection revisions; separate assessment/worker/provider health; typed failures and scoped retries; one durable task-card/activity timeline with measured byte/stage progress only; idempotent APK create/bind/finalise and timeout-after-success recovery; desktop and mobile contextual inspection; consolidated navigation; simplified provider controls; website/APK/Source Hunt alignment; assessment-scoped result truth; report-format readiness; and server-selected Findings continuity.

The final Programme 1 reconciliation is recorded through PRs #117, #119, #121, #122 and #123. Physical Android performance, TalkBack, bright-environment contrast and non-technical usability remain manual evidence categories and are not inferred from browser automation.

### Programme 2 — premium interaction, motion and conversation

**Historical status: COMPLETE for repository-supported automated interaction scope.**

The binding twelve-step premium interaction programme was implemented in dependency order:

1. **Inventory and measurable baseline** — PR #132 adds a deterministic repository interaction inventory and fail-closed owner checks.
2. **Shared semantic motion tokens** — PR #118 establishes product-wide duration, easing, distance, scale and opacity semantics.
3. **Primitive component states** — PR #118 establishes shared pressed, disabled, unavailable, locked, loading, selected, active, success, warning and failure presentation plus 44px targets.
4. **Overlay/dialog/sheet/focus ownership** — PR #120 provides one shared native-dialog controller with stacking, scroll lock, focus restoration, Escape/backdrop policy and browser/Android Back handling.
5. **Shell/navigation continuity** — PR #124 preserves server-owned active route, immediate acknowledgement, BFCache recovery and focus restoration without navigation-delay animation.
6. **Login/session/reauthentication** — PR #125 preserves validated return destinations, duplicate-submit protection, BFCache recovery and server-owned authentication/CSRF/session rotation.
7. **Conversation/send/scroll continuity** — PR #126 adds bounded message receipts, timeout-after-success idempotency, truthful optimistic states, same-identity retry, safe draft continuity and reader-controlled autoscroll/Jump-to-latest.
8. **Upload/artifact/task-card choreography** — PR #127 keeps byte upload, validation and ready states distinct; exposes bounded retry/reselect/cancel; and binds the existing task card to server-produced persisted-stage measurements.
9. **Inspector/activity/results continuity** — PR #128 removes browser-invented workflow percentages and limits arrival emphasis to newly persisted activity receipts.
10. **Mobile direct manipulation/viewport/Back** — PR #129 hardens the full-screen inspector sheet for dynamic viewport, safe areas, short-height landscape, 44px controls and existing Back/Escape/focus ownership.
11. **Performance/reduced-motion/accessibility hardening** — PR #130 routes remaining transition timing through shared tokens, collapses reduced-motion transitions, improves zoom/narrow reflow and preserves forced-colors focus/overlay boundaries.
12. **Cross-workflow cleanup** — PR #131 removes retired workspace patch layers; PR #132 verifies the canonical owner stack and measurable interaction surface.

The final Programme 2 repository slice, PR #132, merged as `3b5e62b27a7bf0878b8c7115b8cefcc286550a85`. Its exact head `afbde7cebc9e588062abe6fb97a0fffbc88c6a3f` passed the quality, conversational-workspace and phone gates recorded at that time.

This completion claim is intentionally narrower than physical-device acceptance. The following remain manual evidence categories and must not be fabricated from static inventory, Playwright or responsive Chromium automation:

- realistic physical Android frame/performance behaviour;
- TalkBack operation;
- bright-environment/real-device contrast review;
- non-technical usability and subjective polish review.

### Current product classification

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
AI-FIRST PRODUCT EXPERIENCE                   IMPLEMENTED — AUTOMATED SCOPE
PREMIUM INTERACTION/MOTION SYSTEM             IMPLEMENTED — AUTOMATED SCOPE
ORDINARY CHAT PROVIDER FAILOVER               IMPLEMENTED — POLICY-BOUNDED
APK INTELLIGENCE NORMALIZATION                IMPLEMENTED
MOBILE SOURCE HUNT ATTACK GRAPH               IMPLEMENTED — BOUNDED STATIC SOURCE COVERAGE
OBSCURA BROWSER INTELLIGENCE                  IMPLEMENTED — LIVE RUNTIME REATTACHMENT PARTIAL
FULL AUTHORITATIVE POSTGRESQL MIGRATION       NOT COMPLETE
PHYSICAL ANDROID/TALKBACK/USABILITY EVIDENCE  MANUAL — NOT CLAIMED
```

## Programme 3 — ML and Hugging Face production architecture

**Historical programme ledger.** The P3.1/P3.2/P3.3 status statements below record an earlier point in the delivery sequence. They are retained for provenance and must not be used to infer present Git/PR state. The current tree already includes richer task/review contracts in `vulnhunter/ml/tasks.py`; later ML production capabilities still require their own current acceptance evidence.

The existing ML foundation remains a responsible research baseline: human-reviewed labels, duplicate/conflict gates, scan-group splitting, training-only candidate selection, deterministic privacy-conscious features, Multinomial/Bernoulli Naive Bayes candidates, explicit thresholds, bounded JSON artifacts, provenance, locked diagnostics, optional advisory providers and provider-neutral readiness verification are implemented.

### P3.1 current-state reconciliation

PR #133 merged as `8f7b912197f6804cb56cdcda77e1d2cf17fea7a9` and reconciled Programme 2 completion before activating Programme 3. It did not claim any new production ML capability.

### P3.2 governed release-to-training boundary

PR #134 merged as `467b72bd0ea12cae796ba74af3a6367292bd5f67` after its recorded exact-head gates passed.

The merged P3.2 runtime adds an owner-private append-only training-eligibility ledger, exact governed-release registration, withdrawal/revocation/supersession blocking, deterministic content-addressed production training packages, redacted release/review lineage, package-integrity revalidation immediately before training and governed candidate provenance. It intentionally fails closed when legacy integer scan or observation identities overlap across applications because hierarchical identity belongs to the following programme slice.

P3.2 does not establish application-family external holdout, calibration, OOD, model registry activation, shadow inference, monitoring, Hugging Face production capability or real-world classifier performance.

### P3.3 hierarchical application identity and group isolation

The historical P3.3 slice introduced/planned the following bounded boundary:

- stable application-family, application-instance and deployment-environment identities derived from governed release metadata rather than integer scan IDs;
- one owner-private append-only hash-chained partition registry that freezes a whole application family to development training, development calibration or external holdout for one evaluation programme;
- explicit partition-programme reset lineage instead of silently moving a family between partitions;
- hierarchical scan and observation keys that preserve source lineage when legacy integer IDs overlap across applications;
- deterministic collision-checked compatibility IDs only at the legacy Naive Bayes training boundary;
- repeated releases of the same application family reusing the same frozen partition assignment;
- external-validation availability reported only when development-training, development-calibration and external-holdout families all actually exist;
- partitioned production-training entry points that consume development-training families only and leave calibration/external-holdout families untouched.

This historical section does not by itself claim that a diverse external holdout exists. It does not establish real-world classifier performance, calibration/OOD quality, production model activation, or complete Hugging Face production features.

The broader production ML/Hugging Face programme remains governed by `ML_AND_HUGGING_FACE_PRODUCTION_ARCHITECTURE.md`, including richer task contracts, pluggable feature extraction, leakage/ablation evaluation, calibration/abstention/OOD, model registry/rollback, shadow inference, monitoring/drift, revision-pinned model capability, local embeddings/retrieval, Source Hunt model experiments, evidence-grounded conversational retrieval and full cross-workflow acceptance.

### ML capability classification

```text
GOVERNED RELEASE-BOUND TRAINING PACKAGE          IMPLEMENTED
WITHDRAWAL/REVOCATION/SUPERSESSION TRAINING GATE IMPLEMENTED
RESEARCH NAIVE BAYES BASELINE                    IMPLEMENTED
RICH LABEL/TASK CONTRACTS                        IMPLEMENTED FOUNDATION
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

The current Naive Bayes model remains an honest comparison baseline. Controlled benchmark performance is not real-application performance; raw posterior values are not calibrated real-world probabilities; and no production classifier claim is permitted without its separate evidence.

## Real-world performance prerequisites

No real-world ML performance claim is permitted until the repository has diverse authorised application-family data, independent governed review, immutable verified release-bound training packages, complete application-family/instance/environment metadata, group-isolated development/calibration partitions, a locked external application-family holdout, leakage/ablation analysis, calibration/OOD/coverage-risk analysis, ranking/review-budget metrics, repeated-seed/grouped uncertainty analysis, error analysis, registry/shadow/rollback evidence and privacy/supply-chain/operational acceptance.

## Current operational commands

Use CLI help as the exact implemented interface:

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

Commands proposed in architecture documents are not operational until they are implemented and exposed by the help surfaces above.

## Repository health

The repository should remain testable offline, usable without optional remote providers, free of tracked secrets/local databases/generated model artifacts, free of unreviewed executable model formats and remote custom code, organised into focused bounded commits, documented alongside architectural changes and truthful about implemented, partial, research-only and unavailable capabilities.
