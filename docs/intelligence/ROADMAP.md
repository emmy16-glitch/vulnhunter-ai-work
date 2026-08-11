# VulnHunter Dependency-Ordered Roadmap

**Status:** BINDING DELIVERY ORDER  
**Current baseline date:** 2026-08-11  
**Status owner:** `docs/intelligence/CURRENT_STATE.md`

---

## 0. Roadmap rules

Before every implementation sequence:

1. re-check current `main`, open PRs, recent merges, CI and review threads;
2. read `AGENTS.md` and the exact product/security contracts affected;
3. do not repeat already merged work;
4. do not classify documentation as runtime implementation;
5. finish one bounded dependency-aligned change before unrelated later work;
6. preserve authorization, scope, evidence, review and publication authority;
7. never weaken a security/test gate just to advance the roadmap;
8. reconcile `CURRENT_STATE.md` and `KNOWN_FAILURES.md` after a capability changes status.

The current mandatory order is:

```text
P0 — documentation/state reconciliation                 COMPLETE BY THIS CONTRACT UPDATE
→ P1 — authorised public-target passive execution
→ P2 — persisted live execution activity across workflows
→ P3 — UI Contract V2 runtime migration and cleanup
→ P4 — Source Hunt preflight/path-bound snapshot UX
→ P5 — cross-workflow browser/phone acceptance
→ P6 — resume remaining Programme 3 ML/Hugging Face work
→ P7 — remaining production/isolation/readiness milestones
```

A later slice may proceed in parallel only when it is demonstrably independent and does not depend on an incomplete earlier trust/state boundary.

---

# P0 — Documentation and authority reconciliation

**Status:** CONTRACT UPDATED; merge/CI review still required.

Goals:

- remove stale “laboratory-only/private-only product” wording while preserving authorization requirements;
- define authorised public targets as a supported product class;
- distinguish product contract from current private-only worker implementation;
- define one persisted live execution activity contract;
- remove contradictory completion claims;
- update all agent entry points so they read the same authority chain;
- keep UI V2 as the sole visual/interaction authority.

Exit gate:

- no binding document says arbitrary public scanning is allowed;
- no binding document says authorised public scanning is permanently prohibited;
- public runtime is truthfully marked incomplete until implemented;
- live execution is truthfully marked partial until implemented end-to-end;
- Source Hunt limitations are explicit;
- agent instructions point to the new contracts.

---

# P1 — Authorised public-target passive execution

**Status:** NEXT REQUIRED RUNTIME PROGRAMME.

**Binding contract:** `docs/product/PUBLIC_TARGET_ASSESSMENT.md`

## P1.1 Authorization model and UX

- support exact public target authorization records;
- preserve owner/controller, approver, evidence reference and purpose;
- permit owner self-attestation only under an explicit owner-controlled policy;
- require appropriate written/program evidence for client/third-party/bounty targets;
- bind exact hostname/scheme/port/path/profile/expiry;
- reject ambiguous/missing/expired/revoked authorization;
- reuse an active exact record instead of repeatedly asking for the same evidence.

## P1.2 Public target scope classification

- represent `public` and `private` as explicit target classes;
- reject mixed public/private resolution;
- reject localhost, loopback, link-local, metadata and unsupported special-use addresses;
- preserve exact authorization path/port/scheme boundaries;
- every redirect remains independently revalidated.

## P1.3 Public-capable worker transport

Implement a separate reviewed worker capability rather than weakening the private pilot.

Required:

- explicit worker target-class capability;
- connection-time DNS/address revalidation;
- approved-address pinning or equivalent containment;
- original hostname preserved for HTTP Host, TLS SNI and certificate validation;
- no scanner-internal uncontrolled re-resolution that can escape authorization;
- public-to-private/metadata rebinding fails closed;
- passive profile only initially;
- rate limit 1 / concurrency 1 defaults;
- no public OAST, cloud upload, automatic update or raw command arguments;
- signed job and immutable plan identity remain intact.

If the scanner cannot preserve these properties, stop and redesign the transport rather than removing the protection.

## P1.4 Public-target acceptance

Required tests include:

- authorized public hostname success;
- wrong port/path failure;
- expired/revoked authorization failure;
- mixed resolution failure;
- DNS rebinding to private/metadata failure;
- redirect escape failure;
- Host/SNI/certificate identity preservation;
- private-only worker still rejects public jobs;
- public-capable worker rejects unauthorised jobs;
- plan-digest change requires new decision;
- cancellation/timeout/reconnect state remains truthful.

## P1 exit gate

Do not classify public execution implemented until one real controlled authorised public target completes the full path:

```text
authorization
→ plan
→ confirmation/approval
→ public-capable worker
→ bounded evidence
→ deterministic verification
→ persisted activity
→ completion/recovery state
```

and the public containment tests pass.

---

# P2 — Persisted live execution activity

**Status:** REQUIRED AFTER/ALONGSIDE P1 WORKER FOUNDATION.

**Binding contract:** `docs/product/LIVE_EXECUTION_ACTIVITY.md`

## P2.1 Event contract

- stable event/sequence identity;
- assessment/workspace/task/attempt binding;
- stage/kind/status/time/safe summary;
- worker/tool identity where known;
- receipt/evidence/candidate references;
- bounded redacted metadata;
- append-only persistence.

## P2.2 Website assessment events

Persist and project meaningful events for:

- authorization;
- plan;
- approval;
- queue;
- worker claim;
- Nuclei start/progress/completion;
- evidence normalization;
- verification;
- cancellation/failure/recovery;
- report readiness where supported.

## P2.3 Source Hunt events

Persist/project meaningful milestones for:

- snapshot/preflight;
- inventory;
- attack-surface mapping;
- source path tracing;
- hypotheses;
- falsification;
- capability filtering;
- remediation proposal;
- failure/recovery/completion.

## P2.4 APK/mobile events

Persist/project:

- upload/byte progress;
- integrity validation;
- individual static tool states;
- partial failure;
- evidence normalization;
- verification;
- optional separately governed dynamic state.

## P2.5 Projection and reconnect

- one selected-assessment activity projection;
- current stage/current tool derived from persisted events;
- deduplicate events on polling/reconnect;
- no replay animation for old events;
- browser refresh never restarts work;
- same task identity survives reconnect/device switching.

## P2 exit gate

A running workflow must no longer rely on a generic “backend is executing it” response when meaningful backend activity exists.

---

# P3 — UI Contract V2 runtime migration

**Status:** CONTRACT APPROVED; RUNTIME CONFORMANCE PARTIAL.

Authoritative UI sources:

- `docs/design/VULNHUNTER_UI_CONTRACT.md`;
- `docs/design/AI_AGENT_UI_IMPLEMENTATION_STANDARD.md`;
- `docs/design/references/manifest.json`;
- `docs/design/DEPRECATIONS.md`;
- `docs/product/CHAT_FIRST_WORKSPACE.md`;
- `docs/product/LIVE_EXECUTION_ACTIVITY.md`;
- `docs/product/UI_ACCEPTANCE_CRITERIA.md`.

## P3.1 Shell

- compact task/chat sidebar on desktop;
- overlay task drawer on phone;
- main conversation owns the workspace;
- contextual detail closed by default;
- persistent composer.

## P3.2 Remove deprecated workspace presentation

Remove/refactor affected instances of:

- four-card Authorization/Scope/Approval/Active strip;
- wide Source Hunt/Search/Export/History/New workspace toolbar;
- KPI-card workspace/history walls;
- giant dark Source Hunt/admin panels;
- low-contrast/tiny conversation copy;
- blue-glow identity;
- desktop UI squeezed/clipped on phone;
- duplicate navigation systems;
- CSS patch layers that exist only to override older contradictory styling.

## P3.3 Live task components

- task rows from persisted stages;
- tool chips from real receipts;
- inline authorization/plan/approval cards;
- evidence/finding/recommendation cards;
- live activity disclosure;
- full-width mobile detail sheets.

## P3.4 Public-target UX

- show target class and exact authorization requirement;
- collect/reference appropriate authorization evidence through backend-supported workflow;
- never imply a public URL itself is authorized;
- show worker capability blocker truthfully until public runtime exists;
- after implementation, flow directly into exact plan/live task state.

## P3 exit gate

Real browser acceptance at representative phone/tablet/desktop widths passes the explicit anti-regression gates.

---

# P4 — Source Hunt preflight and enforceable path boundary

**Status:** REQUIRED.

## P4.1 Preflight

Before queueing, compute/show safe deterministic preflight:

- resolved repository root;
- revision;
- eligible Python file count;
- maximum file count;
- eligible byte count;
- repository byte limit;
- excluded/generated/cache directories;
- unsupported language note;
- whether requested permitted paths actually reduce the snapshot boundary.

Predictable `repository exceeds approved file-count/byte limit` failures should be shown before the user submits the full approval when possible.

## P4.2 Snapshot/path semantics

Current form-level permitted paths must not be presented as if they constrained snapshot construction when they do not.

Choose and implement one explicit contract:

- permitted paths constrain snapshot construction itself; or
- repository root is the snapshot boundary and permitted paths constrain only remote/model processing, with UI explaining this clearly.

Prefer the first where it can preserve immutable complete snapshot semantics safely.

## P4.3 Conversation projection

Source Hunt setup is a focused continuation of chat, and queued/running work returns to the original workspace with live stages.

---

# P5 — Cross-workflow browser/phone acceptance

**Status:** REQUIRED BEFORE CALLING PRODUCT UX MIGRATION COMPLETE.

Test the same product semantics across:

- private website;
- authorized public website once P1 exists;
- Source Hunt;
- APK/mobile;
- authorization missing/verified;
- plan confirmation/independent approval;
- queued/running;
- follow-up queued;
- evidence/finding;
- failure/recovery/cancellation;
- reconnect/restoration;
- report readiness.

Representative widths near:

`360`, `390`, `412`, `768`, `1024`, `1280`, `1440` CSS pixels.

Physical Android/TalkBack/usability remain separately recorded manual evidence.

---

# P6 — Remaining Programme 3 ML/Hugging Face work

**Status:** RESUME AFTER PRODUCT/EXECUTION STABILIZATION OR IN PROVEN INDEPENDENT PARALLEL WORK.

Already merged through P3.9:

- governed release-to-training boundary;
- hierarchical application/family partitioning;
- task/label separation;
- pluggable feature extraction;
- leakage/ablation evaluation;
- calibration/OOD/abstention foundations;
- expanded evaluation/uncertainty;
- signed model registry/activation/rollback.

Remaining major slices include:

- shadow inference and delayed governed reviewer-feedback linkage;
- monitoring/drift/incident response;
- revision-pinned Hugging Face capability registry;
- local embedding/retrieval experiments;
- Source Hunt code-model experiments;
- evidence-grounded conversational retrieval;
- complete cross-workflow production acceptance.

Models remain advisory. No later ML work may bypass target authorization, evidence verification or human review authority.

---

# P7 — Production/isolation/readiness

Remaining production work includes environment-specific acceptance for:

- TLS/proxy/DNS;
- PostgreSQL/migrations;
- backup/restore;
- worker isolation;
- external signing/secret rotation;
- evidence retention;
- monitoring/incident response;
- public-target worker deployment;
- production rollback;
- independent security review.

---

## Final roadmap rule

When code and documents disagree, do not silently choose the more convenient version.

Establish the current runtime truth, preserve security authority, update the status owners, and implement the next dependency without weakening a gate.
