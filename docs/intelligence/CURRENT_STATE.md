# Current State

## Implemented capabilities

VulnHunter is an authorised, laboratory-only security-research and decision-support platform. The repository currently includes:

- strict loopback/private-lab target validation, explicit time-limited authorisation, redirect/derived-link containment, connection-time DNS revalidation, pinned approved-address transport, peer verification and bounded GET/HEAD collection;
- central redaction, bounded response handling, passive mapping and passive security observations;
- SQLite persistence for scans, observations, review decisions, authorisation records and audit events;
- two-reviewer consensus, independent adjudication, reviewer-specific queues, duplicate/conflicting-label gates and immutable review attestations;
- governed collection campaigns, campaign/authorisation binding, application metadata, release manifests and deterministic release-provenance packages;
- controlled reviewed-dataset export, scan-group-isolated splits, deterministic Multinomial/Bernoulli Naive Bayes research baselines, bounded JSON model artifacts and locked holdout diagnostics;
- bounded orchestration, evaluator separation, unattended permission manifests and fail-closed verifier contracts;
- authenticated Django product surfaces, a persistent conversational workspace, optional Groq and Hugging Face advisory providers and provider-neutral browser-path readiness verification;
- a versioned scanner-manager protocol, signed worker spool, restricted remote bridge and one activated passive RFC1918 Nuclei laboratory path;
- a separately authorised publication foundation with signed state, destination policy, correction/revocation and recovery checks.

The platform is not an autonomous public-Internet scanner, exploit framework, automatic vulnerability publisher or production-grade vulnerability classifier. Human review, deterministic services and verified evidence remain authoritative.

## Product programme status

### Programme 1 — AI-first assessment workspace

**Status: COMPLETE for repository-supported automated runtime scope.**

The implemented runtime provides one authoritative selected-assessment projection across Chat, Activity, inspector, history, Findings, Evidence and Report; monotonic persisted projection revisions; separate assessment/worker/provider health; typed failures and scoped retries; one durable task-card/activity timeline with measured byte/stage progress only; idempotent APK create/bind/finalise and timeout-after-success recovery; desktop and mobile contextual inspection; consolidated navigation; simplified provider controls; website/APK/Source Hunt alignment; assessment-scoped result truth; report-format readiness; and server-selected Findings continuity.

The final Programme 1 reconciliation is recorded through PRs #117, #119, #121, #122 and #123. Physical Android performance, TalkBack, bright-environment contrast and non-technical usability remain manual evidence categories and are not inferred from browser automation.

### Programme 2 — premium interaction, motion and conversation

**Status: COMPLETE for repository-supported automated interaction scope.**

The binding twelve-step premium interaction programme is implemented in dependency order:

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

The final Programme 2 repository slice, PR #132, merged as `3b5e62b27a7bf0878b8c7115b8cefcc286550a85`. Its exact head `afbde7cebc9e588062abe6fb97a0fffbc88c6a3f` passed VulnHunter quality gates #1742, Conversational workspace quality #1234 and Phone acceptance #701. No review threads remained.

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
AI-FIRST PRODUCT EXPERIENCE                   IMPLEMENTED — PROGRAMME 1 AUTOMATED SCOPE
PREMIUM INTERACTION/MOTION SYSTEM             IMPLEMENTED — PROGRAMME 2 AUTOMATED SCOPE
PHYSICAL ANDROID/TALKBACK/USABILITY EVIDENCE  MANUAL — NOT CLAIMED
```

## Programme 3 — ML and Hugging Face production architecture

**Status: ACTIVE. P3.1 is merged; P3.2 is implemented on the active bounded PR pending repository gates.**

PR #133 merged as `8f7b912197f6804cb56cdcda77e1d2cf17fea7a9` and reconciled Programme 2 completion before activating Programme 3. It also stabilized two fixed-time remediation web fixtures by injecting their declared clocks only in test code; production expiry validation remains unchanged and fail-closed.

The existing ML foundation remains a responsible research baseline: human-reviewed labels, duplicate/conflict gates, scan-group splitting, training-only candidate selection, deterministic privacy-conscious features, Multinomial/Bernoulli Naive Bayes candidates, explicit thresholds, bounded JSON artifacts, provenance, locked diagnostics, optional Groq/Hugging Face advisory providers and provider-neutral readiness verification are implemented.

### P3.2 governed release-to-training boundary

The active P3.2 implementation adds a production-only boundary on top of, rather than in place of, the research baseline:

- one owner-private append-only hash-chained training-eligibility ledger for exact governed release packages;
- authenticated campaign-administrator registration bound to the current immutable release ID, release-manifest digest and release-package digest;
- terminal withdrawal and revocation states that immediately prevent new production package derivation and training;
- supersession that requires a separately active successor release and preserves the old immutable lineage while blocking it from future production training;
- a deterministic content-addressed production training package containing canonical redacted examples, release/campaign/application/authorisation lineage, review/adjudication attestation digests, duplicate exclusions, explicit policy versions, permitted tasks, retention policy and exact source commit;
- hashed source references in the ML package so owner-local scan-database paths are not exposed as training metadata;
- production baseline/tuned entry points that revalidate package integrity and source-release eligibility immediately before fitting, while the existing direct `train_baseline` and `train_tuned` APIs remain research-mode foundations;
- a governed candidate wrapper binding the resulting baseline artifact to the exact production training-package and release provenance without giving the model label, severity, review, scanner or publication authority;
- a fail-closed guard when legacy integer scan or observation identities overlap across released applications, because P3.3 must establish hierarchical stable identity rather than silently inventing or collapsing groups.

This P3.2 boundary does **not** establish application-family external holdout, calibration, OOD, registry activation, shadow inference, monitoring, Hugging Face production capability or real-world classifier performance. It also does not make a production-candidate artifact equivalent to an approved or active model.

The complete production ML/Hugging Face programme continues in the binding order from `ML_AND_HUGGING_FACE_PRODUCTION_ARCHITECTURE.md`:

1. current-state reconciliation — **MERGED in PR #133**;
2. governed release-to-training boundary — **IMPLEMENTED on PR #134; merge requires green exact-head gates**;
3. hierarchical application identity and group isolation — **NEXT**;
4. richer label and task contracts;
5. pluggable feature-extractor interface;
6. leakage and ablation evaluation;
7. calibration, abstention and OOD handling;
8. complete evaluation and uncertainty reporting;
9. model registry, signing, activation and rollback;
10. shadow inference and reviewer-feedback linkage;
11. monitoring, drift and incident response;
12. revision-pinned Hugging Face capability registry;
13. local embedding and retrieval experiments;
14. Source Hunt code-model experiments;
15. evidence-grounded conversational retrieval;
16. full cross-workflow production acceptance and cleanup.

### ML capability classification

```text
GOVERNED RELEASE-BOUND TRAINING PACKAGE          IMPLEMENTED ON ACTIVE P3.2 PR — GATES REQUIRED
WITHDRAWAL/REVOCATION/SUPERSESSION TRAINING GATE IMPLEMENTED ON ACTIVE P3.2 PR — GATES REQUIRED
RESEARCH NAIVE BAYES BASELINE                    IMPLEMENTED
HIERARCHICAL APPLICATION/GROUP IDENTITY          NOT COMPLETE — P3.3 NEXT
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

The current Naive Bayes model remains the honest comparison baseline. Controlled benchmark performance is not real-application performance; raw posterior values are not calibrated real-world probabilities; and no production registry, activation, shadow, rollback or drift lifecycle exists yet.

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

The new P3.2 interfaces are Python contracts on the active bounded PR, not new CLI commands. Commands proposed in architecture documents are not operational until they are implemented and exposed by the help surfaces above.

## Repository health

The repository should remain testable offline, usable without optional remote providers, free of tracked secrets/local databases/generated model artifacts, free of unreviewed executable model formats and remote custom code, organised into focused bounded commits, documented alongside architectural changes and truthful about implemented, partial, research-only and unavailable capabilities.