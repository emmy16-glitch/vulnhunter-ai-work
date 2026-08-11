# VulnHunter AI-First Assessment Workspace Architecture

**Status:** Binding for state/lifecycle architecture; **subordinate for UI composition and visual design**  
**Repository:** `emmy16-glitch/vulnhunter-ai-work`  
**Original programme:** 2026-08-02  
**UI authority corrected:** 2026-08-11

## 0. Authority correction

This document previously mixed useful state/lifecycle architecture with presentation guidance from an earlier interface. That created a competing source of truth and allowed agents to preserve obsolete dashboard/dark-UI patterns.

From 2026-08-11 onward, the authority order is:

1. `AGENTS.md` and backend security contracts;
2. `vulnhunter/web/AGENTS.md` for web work;
3. `docs/design/VULNHUNTER_UI_CONTRACT.md` for canonical product interaction and visual design;
4. `docs/design/AI_AGENT_UI_IMPLEMENTATION_STANDARD.md` for implementation/rejection rules;
5. `docs/design/references/manifest.json` for reference use/ignore rules;
6. `docs/design/DEPRECATIONS.md` for retired presentation;
7. `docs/product/CHAT_FIRST_WORKSPACE.md` for chat/task workflow semantics;
8. **this document** for state/lifecycle architecture that does not conflict with the sources above.

This document must **not** be used to justify:

- an all-dark product surface;
- a dashboard-first layout;
- KPI card walls;
- a permanent assessment inspector;
- old top action strips;
- bottom-tab mobile dashboards;
- desktop UI squeezed onto phone;
- old CSS/layout details;
- any visual rule that conflicts with the locked cream/dotted/dusty-pink VulnHunter system.

The current implementation is not visual authority either.

---

## 1. Permanent architectural principle

> VulnHunter is one conversational assessment workspace whose chat, task activity, evidence, findings, approvals, reports and specialist views all project the same authoritative backend state.

The backend — not the browser and not AI prose — owns:

- authorization;
- scope;
- immutable plan identity;
- execution state;
- worker/tool receipts;
- evidence;
- verification;
- review/adjudication;
- cancellation/recovery;
- report/release eligibility.

The browser projects that state through the chat/task product defined by the canonical design documents.

---

## 2. Core state architecture

Every supported operation should converge on one durable workspace/assessment identity.

```text
user request / attachment
→ owner-scoped workspace
→ typed intent + exact object resolution
→ authorization / policy / role validation
→ immutable plan or action identity
→ required confirmation / independent approval
→ persisted task graph or bounded service
→ worker/tool receipts
→ evidence and candidate findings
→ deterministic verification / controlled validation when applicable
→ human review / adjudication when applicable
→ remediation / retest / report state
→ conversation projection + optional deep views
```

The UI may have multiple views, but those views must not create multiple competing state machines.

---

## 3. One assessment identity

As soon as a supported workflow reaches the repository-defined point where a durable assessment/workspace should exist, all subsequent records must remain linked to the same identity:

- messages;
- uploads;
- target/repository/artifact identity;
- plan digest;
- approvals;
- task graph;
- worker receipts;
- tool receipts;
- evidence;
- findings;
- verification;
- review/adjudication;
- remediation/retest;
- report/export;
- cancellation/recovery.

A deep view must never say “no active assessment” while rendering artifacts or task state that actually belong to one.

---

## 4. State-aware conversation

The conversation response layer consumes the authoritative workspace projection before producing user-facing prose.

It must not ask for a prerequisite that is already completed.

Examples:

Before upload:

```text
Attach the APK and I will validate it before preparing analysis.
```

During upload:

```text
Digi Volt.apk is uploading. You can continue chatting while the upload proceeds.
```

After integrity validation:

```text
The APK passed integrity validation. The assessment is ready for the next governed stage.
```

After a real tool failure:

```text
Static analysis stopped during JADX extraction. The uploaded artifact and completed evidence were preserved.
```

The model must not guess these states. Backend projection supplies exact state and allowed next actions.

---

## 5. Persisted task execution

Every long-running operation should expose one persisted task lifecycle that answers:

- What is happening now?
- What already completed?
- What comes next?
- Which worker/tool is active?
- Is human action required?
- What failed or recovered?
- What evidence was preserved?
- What can be retried safely?

The canonical UI projection is defined by the UI contract and may use task rows/tool chips/context cards. This architecture document does not define their color, geometry or placement.

Technical task-graph nodes, worker lease IDs, spool envelopes, command versions and hashes belong in progressive detail rather than ordinary task copy.

---

## 6. Failure, retry and recovery architecture

A terminal or blocked state should make the backend truth available to the UI:

- exact stage;
- safe reason category;
- stable error/reference ID;
- completed stages;
- preserved artifact/evidence state;
- whether automatic recovery is occurring;
- whether retry is supported;
- retry boundary;
- whether user action or operator configuration is required.

Do not expose retry in the UI unless backend execution is safe and idempotent for that retry boundary.

Refresh/reconnect reconstructs persisted state; it never restarts work.

---

## 7. Navigation/state ownership architecture

The following concepts may have specialist views but remain projections of the same workspace state:

- task/activity;
- findings;
- evidence;
- report/export;
- authorization;
- Source Hunt setup;
- review/adjudication;
- campaigns/releases/datasets;
- readiness/audit/settings.

The **visual placement and everyday navigation hierarchy are not defined here**. They are defined by `docs/design/VULNHUNTER_UI_CONTRACT.md` and `docs/design/AI_AGENT_UI_IMPLEMENTATION_STANDARD.md`.

In particular, this document must not be used to resurrect permanent global navigation for every subsystem.

---

## 8. Website workflow architecture

```text
authorized target intent
→ exact target + authorization resolution
→ immutable bounded passive plan
→ required confirmation / independent approval
→ persisted worker/task execution
→ evidence
→ candidate findings
→ deterministic verification
→ optional controlled active validation
→ review
→ report/release state
```

The UI begins and remains centered in the conversational/task workspace.

---

## 9. Source Hunt workflow architecture

```text
approved repository intent
→ exact root + revision + snapshot + path boundary
→ exact source-processing approval where required
→ queued Source Hunt worker
→ hypotheses
→ falsification
→ capability filtering
→ evidence-backed remediation proposal
→ deterministic verification / human-controlled engineering workflow
→ conversation projection
```

A specialist setup/deep view may exist for exact fields and re-authentication. It is not a competing product or visual authority.

---

## 10. APK/mobile workflow architecture

```text
conversation attachment
→ resumable upload
→ final archive + SHA-256 validation
→ durable artifact/assessment binding
→ static/native analysis only where policy/worker support exists
→ tool receipts
→ evidence/finding projection
→ optional separately governed dynamic path
```

Uploading never implies execution.

---

## 11. Controlled active validation architecture

```text
persisted finding
→ exact synthetic scenario and limits
→ required requester/independent authority
→ isolated networkless controlled worker
→ bounded trials
→ evidence hashes
→ cleanup verification
→ persisted result / abstention
→ original conversation projection
```

---

## 12. Remediation, retest and report architecture

Remediation, retest and report requests remain part of the same workspace lifecycle.

- AI recommendations remain advisory.
- deterministic verification remains separate.
- human-controlled merge/review remains separate.
- report/export readiness is assessment-bound.
- seeded/demo records must never appear as if they belong to the user's active assessment.

---

## 13. Responsive architecture boundary

This document requires state continuity across desktop and phone, but **does not define visual responsive layout**.

The binding responsive rules are in:

- `docs/design/VULNHUNTER_UI_CONTRACT.md`;
- `docs/design/AI_AGENT_UI_IMPLEMENTATION_STANDARD.md`;
- `docs/product/RESPONSIVE_AND_ACCESSIBILITY.md`.

Any older wording suggesting a dark responsive console, permanent inspector or bottom-tab mobile product is superseded.

---

## 14. Definition of architectural done

A workspace capability is architecturally complete only when:

1. it binds to an owner-scoped durable workspace/assessment;
2. chat intent becomes a typed policy-checked operation;
3. required authorization/confirmation/approval cannot be bypassed;
4. long-running execution persists independently of the browser;
5. disconnect/reconnect restores exact current state;
6. worker/tool receipts are tied to the same operation identity;
7. evidence/findings/reports remain correctly bound;
8. failure/recovery/cancellation state is truthful;
9. specialist views project the same state;
10. the conversation can explain what happened and what the user may do next without guessing;
11. desktop and phone see the same underlying product state;
12. the browser presentation separately passes the canonical UI contract and UI acceptance criteria.

A page, endpoint, card or test token by itself is not completion.
