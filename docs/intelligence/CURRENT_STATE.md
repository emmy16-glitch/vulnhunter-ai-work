# Current State

**Status owner:** this file is the authoritative implementation-state summary for VulnHunter.  
**Rule:** product contracts may describe approved future behavior; this file states what the runtime actually implements now.

---

## 1. Product classification

VulnHunter is an **authorised security-assessment and decision-support platform**.

The product contract supports both private and authorised public targets, but the current scanner runtime does **not** yet provide a production-accepted public-host execution path.

Current high-level classification:

```text
AUTHORIZATION / GOVERNANCE FOUNDATIONS          IMPLEMENTED
PRIVATE-TARGET PASSIVE WEBSITE EXECUTION        IMPLEMENTED — CONFIGURATION/ENVIRONMENT DEPENDENT
PUBLIC-TARGET PRODUCT CONTRACT                  APPROVED
PUBLIC-TARGET WORKER EXECUTION                  NOT COMPLETE
CONVERSATION/TASK WORKSPACE FOUNDATION          IMPLEMENTED
LOCKED UI CONTRACT V2                           APPROVED / MERGED
FULL UI V2 RUNTIME CONFORMANCE                  NOT COMPLETE
PERSISTED TASK/ACTIVITY FOUNDATION              IMPLEMENTED
RICH LIVE EXECUTION ACTIVITY ACROSS ALL FLOWS   PARTIAL
SOURCE HUNT PYTHON-FIRST PIPELINE                IMPLEMENTED — BOUNDED
SOURCE HUNT PREFLIGHT/ACTIVITY UX                PARTIAL
APK RESUMABLE UPLOAD/STATIC PIPELINE             IMPLEMENTED — ENVIRONMENT DEPENDENT
HUMAN REVIEW/ADJUDICATION/GOVERNED RELEASE       IMPLEMENTED
PROGRAMME 3 ML FOUNDATIONS THROUGH P3.9          IMPLEMENTED / MERGED
PRODUCTION REAL-WORLD VULNERABILITY CLASSIFIER   NOT ESTABLISHED
PHYSICAL ANDROID/TALKBACK/USABILITY EVIDENCE     MANUAL — NOT CLAIMED
```

---

## 2. Implemented foundations

The repository currently includes:

- explicit time-limited authorization records and append-only audit events;
- exact scheme/host/port/path/address scope controls;
- redirect/derived-link containment foundations;
- connection-time DNS revalidation and address pinning in the bounded HTTP path;
- sensitive-data redaction;
- bounded request/response handling;
- scanner manager/worker separation;
- signed worker spool and immutable plan/approval identity;
- one reviewed passive private-target Nuclei worker path;
- task/activity persistence and selected-assessment projection foundations;
- evidence normalization and deterministic verification;
- finding/review/adjudication/release governance;
- Source Hunt exact snapshots, processing approvals, Python inventory/attack-surface mapping, model-assisted hunt/falsification/capability filtering and remediation proposal;
- resumable APK upload and bounded static-analysis foundations;
- optional advisory provider routing including Groq and Hugging Face families under current policy;
- controlled ML/retrieval/governance foundations;
- canonical browser design/interaction governance.

---

## 3. Public-target support

### Product status

**APPROVED PRODUCT REQUIREMENT.**

The binding contract is `docs/product/PUBLIC_TARGET_ASSESSMENT.md`.

Authorised public targets are legitimate VulnHunter targets when an exact active authorization covers the target and requested scan profile.

Public does not mean permission. Arbitrary public scanning remains prohibited.

### Runtime status

**NOT COMPLETE.**

The current scope and Nuclei activation models can represent public addresses, but the current passive worker pilot is explicitly private-target-only and requires a private literal target. Therefore a public hostname such as a normal TLS virtual host cannot yet be truthfully classified as supported end-to-end execution.

Do not work around this by removing the private worker assertion.

### Required remaining runtime work

A public-capable execution path must implement and verify:

- explicit worker target-class capability;
- exact public authorization binding;
- connection-time public DNS/address containment;
- protection against public-to-private/metadata rebinding;
- original hostname preservation for HTTP Host, TLS SNI and certificate validation while using approved address containment;
- redirect revalidation;
- passive template/rate/concurrency limits;
- signed job/evidence/activity continuity;
- public-target success and failure acceptance tests.

Until those gates pass, UI/status must say `public execution unavailable/not configured` rather than claiming a scan is running.

---

## 4. UI Contract V2

The locked conversation/task-first UI direction has been merged and is authoritative.

Canonical sources include:

- `docs/design/VULNHUNTER_UI_CONTRACT.md`;
- `docs/design/AI_AGENT_UI_IMPLEMENTATION_STANDARD.md`;
- `docs/design/references/manifest.json`;
- `docs/design/DEPRECATIONS.md`;
- `docs/product/CHAT_FIRST_WORKSPACE.md`;
- `docs/product/LIVE_EXECUTION_ACTIVITY.md`;
- `docs/product/UI_ACCEPTANCE_CRITERIA.md`.

### Runtime conformance status

**PARTIAL / MIGRATION REQUIRED.**

Documentation/design governance is complete enough to prevent future agents from treating the old dashboard-style UI as authority. Existing templates/CSS/tests may still contain deprecated presentation.

Known runtime presentation debt includes surfaces that may still show:

- old wide utility action rows;
- clipped phone controls;
- giant dark Source Hunt panels/forms;
- low-contrast or undersized conversation text;
- incomplete live activity while a worker runs;
- separate-page monitoring instructions instead of one in-workspace task experience.

Do not classify UI V2 as fully implemented until browser acceptance proves the affected runtime surfaces conform.

---

## 5. Live execution activity

### Foundation

The repository already persists important task/activity events for several workflows and has task-card/projection foundations.

### Current limitation

**RICH CROSS-WORKFLOW LIVE ACTIVITY IS PARTIAL.**

Website assessment has more persisted activity than Source Hunt. Source Hunt's selected-assessment projection currently exposes only a shallow summary in places and may not expose an active tool/current detailed operation even while work is running.

The user must not be forced to accept a generic message such as “the backend is executing; check elsewhere.”

The binding target contract is `docs/product/LIVE_EXECUTION_ACTIVITY.md`.

### Exit gate

Live execution may be classified implemented for a workflow only when:

1. worker/service persists meaningful stage/tool/activity events;
2. authoritative assessment projection exposes them;
3. chat/task UI renders them in place;
4. reconnect reconstructs/deduplicates them;
5. browser acceptance verifies UI against persisted state.

---

## 6. Source Hunt

### Implemented

- operator-approved repository roots;
- exact revision/snapshot identity;
- bounded eligible-file snapshot;
- exact source-processing approval;
- password re-authentication in browser flow;
- separate queued worker;
- deterministic Python mapper;
- model-assisted reconnaissance/hypothesis;
- independent falsification;
- capability filtering;
- evidence-bound remediation planning;
- persisted report/job state.

### Current limitations

- Python-first only;
- repository file/byte limits can fail a hunt before queueing;
- current form-level `permitted_paths` does not by itself guarantee that the snapshot builder avoided scanning a larger repository root before the approval boundary is created;
- predictable file/byte-limit failure should be surfaced through preflight before submission;
- live Source Hunt activity should expose more persisted stage/tool/candidate state in the originating workspace.

Do not claim permitted-path narrowing solved snapshot-size failure unless the runtime actually uses it during snapshot construction.

---

## 7. Website/private scanner path

The current reviewed passive Nuclei pilot remains deliberately bounded:

- passive profile;
- rate limit 1;
- concurrency 1;
- reviewed template manifest;
- no automatic updates;
- no public OAST;
- no cloud upload;
- no raw command arguments;
- exact plan/approval identity;
- bounded output/timeouts/cancellation.

The existing private-target safety boundary remains valid while public support is implemented separately.

---

## 8. APK/mobile

Implemented foundations include resumable upload, integrity validation and bounded static tooling where the environment is configured.

Uploading does not execute an APK.

Dynamic execution, emulator, ADB, Frida and MobSF capabilities remain separately governed/environment dependent.

Physical Android performance, TalkBack, bright-environment contrast and non-technical usability remain manual evidence categories.

---

## 9. AI/provider state

Global provider policy is provider-neutral and currently recognizes optional advisory provider families including Groq and Hugging Face.

Do not reintroduce a blanket statement that Groq is the only provider everywhere.

Source Hunt itself may remain Groq-specific under `docs/product/SOURCE_HUNT.md`.

Models remain non-authoritative for authorization, execution, verification, review, severity, merge, release and publication.

---

## 10. Programme 3 ML status

Programme 3 work through P3.9 has been merged, including:

- governed release-bound production training packages;
- hierarchical application/family/environment identity and partition registry;
- explicit task/label separation;
- pluggable governed feature extractors;
- development-only leakage/ablation evaluation;
- calibration/OOD/abstention foundations;
- expanded evaluation/uncertainty reporting;
- signed model registry, activation and rollback lifecycle.

The remaining programme still includes later capabilities such as shadow inference, delayed reviewer feedback joins, monitoring/drift/incident response, revision-pinned Hugging Face capability registry, retrieval/code-model experiments and complete production acceptance.

No real-world production vulnerability-classifier performance claim is established merely because these foundations exist.

---

## 11. Documentation reconciliation rule

After a major PR merges, update this file, `ROADMAP.md` and `KNOWN_FAILURES.md` together when their status is affected.

Never leave states such as:

```text
CURRENT_STATE: complete
KNOWN_FAILURES: still missing
ROADMAP: in progress
```

for the same exact capability without explaining the difference in scope.

Use explicit qualifiers such as `contract approved`, `runtime partial`, `automated acceptance complete`, `manual evidence pending`.

---

## 12. Immediate highest-priority gaps

1. implement public-capable passive execution without weakening private-worker protections;
2. implement the complete persisted live-execution activity contract across website/Source Hunt/APK;
3. migrate remaining browser surfaces to UI Contract V2 and remove deprecated presentation;
4. add Source Hunt preflight that surfaces file/byte/path limits before queue submission;
5. keep current-state/roadmap/known-failure documents reconciled after each implementation slice.
