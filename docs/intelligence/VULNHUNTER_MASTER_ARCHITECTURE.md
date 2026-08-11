# VulnHunter AI — Master Architecture

**Owner:** Emmanuel Okunlola  
**Repository:** `emmy16-glitch/vulnhunter-ai-work`  
**Architecture revision:** 2026-08-11  
**Status:** CURRENT READABLE PRODUCT BLUEPRINT  
**Implementation status owner:** `docs/intelligence/CURRENT_STATE.md`  
**Delivery-order owner:** `docs/intelligence/ROADMAP.md`

---

## 0. Authority

This document describes the finished product architecture. It does **not** replace implementation-status or delivery-order documents.

When sources disagree, use:

1. `AGENTS.md` — security/engineering rules;
2. current binding product/security contracts;
3. `docs/design/VULNHUNTER_UI_CONTRACT.md` — browser interaction/visual design;
4. `docs/intelligence/CURRENT_STATE.md` — what runtime actually implements now;
5. `docs/intelligence/ROADMAP.md` — next dependency order;
6. this document — cross-system architecture;
7. specialist/historical plans/trackers — supporting detail/provenance only.

Do not use old baselines/trackers to override current state.

---

## 1. Finished product definition

VulnHunter is an **authorised security-assessment platform** controlled through conversation but governed by deterministic backend state.

The finished product supports:

- authorised private/laboratory website targets;
- authorised public Internet website targets;
- exact target/scope/authorization records;
- bounded passive scanner execution;
- rich persisted live execution activity;
- evidence normalization and deterministic verification;
- human finding review/adjudication/governed release;
- Python-first Source Hunt with exact source-processing approval;
- APK/mobile static analysis and separately governed dynamic/active capabilities;
- advisory AI/provider routing;
- controlled ML/retrieval assistance;
- remediation/retest/report workflows;
- responsive conversation/task-first web UI.

A public URL is not permission. A model is not authority. A scanner match is not vulnerability proof. A browser state is not worker truth.

---

## 2. End-to-end architecture

```text
User / operator
      │
      ▼
Conversation/task workspace
      │
      ├─ intent/entity resolution
      ├─ selected workspace/assessment identity
      │
      ▼
Deterministic policy layer
      │
      ├─ authentication / role
      ├─ authorization
      ├─ exact scope
      ├─ target class (private/public)
      ├─ plan / approval / confirmation
      ├─ worker capability
      └─ privacy/provider policy
      │
      ▼
Persisted task graph + activity stream
      │
      ├─────────────┬────────────────┬──────────────────┐
      ▼             ▼                ▼                  ▼
Website worker   Source Hunt      APK/static        Other governed
(Nuclei etc.)    worker           workers           workflows
      │             │                │
      └─────── tool/worker receipts + bounded evidence ───────┘
                            │
                            ▼
                 Evidence normalization
                            │
                            ▼
                 Deterministic verification
                            │
                            ▼
               Human review / adjudication
                            │
                            ▼
                 Remediation / retest
                            │
                            ▼
                    Report / release
```

All browser surfaces project the same persisted assessment identity.

---

## 3. Target and authorization architecture

### 3.1 Target classes

Supported product classes:

- `private` — private/laboratory target;
- `public` — globally routable target with explicit authorization.

Always fail closed for ambiguous/mixed/special-use target resolution according to the exact scope contract.

### 3.2 Authorization

Authorization records bind:

- target URL/hostname;
- scheme;
- port;
- path boundary;
- approved addresses/address policy;
- owner/controller;
- approving actor;
- purpose;
- evidence reference;
- profile/limits;
- validity/expiry/revocation;
- integrity digest/audit history.

### 3.3 Public-target policy

Public targets are permitted only when exactly authorized.

See `docs/product/PUBLIC_TARGET_ASSESSMENT.md`.

Self-attestation may be used only for a genuine owner-controlled target under explicit product policy. Client/third-party/bug-bounty targets require the appropriate external permission/scope evidence.

---

## 4. Network containment architecture

### Private targets

Preserve private-network scope and worker policy.

### Public targets

Finished public execution must preserve:

- connection-time DNS/address revalidation;
- approved-address pinning or equivalent containment;
- no public-to-private/metadata pivot;
- original Host/TLS SNI/certificate identity;
- redirect revalidation;
- explicit public-capable worker policy;
- bounded passive execution.

Do not obtain public support by deleting private-target assertions.

---

## 5. Website scanner architecture

```text
exact authorization
→ target-class-capable worker check
→ immutable Nuclei plan
→ exact confirmation/approval
→ signed job
→ worker validation
→ fixed bounded command/tool invocation
→ activity receipts
→ bounded redacted evidence
→ deterministic verification
```

Nuclei is an evidence producer, not authority.

The first public execution profile remains passive and tightly bounded.

See `docs/product/NUCLEI_INTEGRATION.md`.

---

## 6. Persisted live execution architecture

Every long-running workflow emits meaningful persisted events into one append-only assessment activity stream.

Conceptual event fields:

```text
event_id / sequence
assessment/workspace/task/attempt IDs
stage / kind / status
timestamp
safe summary
worker/tool identity when known
subject reference
receipt/evidence/candidate references
bounded metrics
failure reference
redacted metadata
```

Browser projection uses these events to render:

- current stage;
- completed/pending stages;
- active tool/worker;
- latest activity;
- real counts;
- failure/recovery;
- preserved work.

See `docs/product/LIVE_EXECUTION_ACTIVITY.md`.

---

## 7. Source Hunt architecture

```text
repository intent
→ approved root
→ deterministic preflight
→ exact revision + eligible snapshot
→ exact path-bound source-processing approval
→ queued worker
→ Python inventory / entry points / sinks / paths
→ Groq reconnaissance/hypothesis
→ independent falsification
→ capability filter
→ remediation/test proposal
→ deterministic/human-controlled fix verification
```

Critical rules:

- source truth comes from snapshot/hash/line validation;
- provider never grants source access;
- permitted paths must match enforceable runtime semantics;
- preflight surfaces predictable file/byte limits;
- running hunt exposes persisted activity in the original workspace;
- model output cannot verify/merge/publish.

See `docs/product/SOURCE_HUNT.md`.

---

## 8. APK/mobile architecture

```text
attachment
→ resumable upload
→ archive/integrity validation
→ immutable artifact identity
→ static tool plan
→ individual tool receipts
→ evidence
→ verification
→ optional separately governed dynamic environment
```

Uploading never implies execution.

Dynamic analysis remains a distinct worker/environment authorization boundary.

---

## 9. AI/provider architecture

Provider policy is owned by `docs/product/AI_ROUTING.md` and current registry/runtime.

Models may:

- explain supplied state;
- summarize redacted evidence;
- propose hypotheses/remediation;
- support exact Source Hunt processing under approval;
- later support governed retrieval/prioritisation tasks.

Models may not:

- authorize targets/source;
- expand scope;
- execute scanner/shell tools through advisory path;
- verify findings;
- set final severity;
- overwrite human labels;
- merge/publish.

Do not use stale global “Groq only” wording when other provider families exist. Source Hunt may remain Groq-specific.

---

## 10. Evidence/finding architecture

Evidence is assessment-scoped, redacted and provenance-bound.

```text
tool receipt
→ evidence record
→ candidate observation/finding
→ deterministic verification / abstention
→ human review / adjudication
→ remediation/retest/report/release
```

Zero findings does not mean zero evidence/history.

A candidate is not silently promoted to a confirmed finding by model confidence or tool severity.

---

## 11. Review/governance architecture

Human authority remains explicit for governed outcomes.

Preserve:

- authenticated governance identities;
- assignment/separation rules;
- independent primary review;
- adjudication when required;
- immutable attestations;
- release/publication separation;
- correction/revocation history.

---

## 12. ML/intelligence architecture

Current programme foundations include governed training packages, application-family partitioning, explicit advisory task contracts, pluggable extraction, leakage/ablation evaluation, calibration/OOD/abstention foundations, expanded evaluation and signed model lifecycle.

Finished architecture adds:

- shadow inference;
- governed delayed outcome joins;
- monitoring/drift/incident response;
- revision-pinned HF capability registry;
- safe local embeddings/retrieval;
- source-code model experiments;
- evidence-grounded conversational retrieval.

No model becomes security authority.

---

## 13. Browser architecture

VulnHunter browser UI is conversation/task-first.

```text
desktop:
compact task/chat sidebar
→ main conversation + task timeline + live activity
→ persistent composer
→ optional contextual detail drawer

mobile:
overlay task/chat drawer
→ one-column conversation + task timeline + live activity
→ persistent composer
→ full-width detail sheet/deep view
```

The visual contract is `docs/design/VULNHUNTER_UI_CONTRACT.md`.

Current implementation is subordinate and may contain deprecated UI debt.

---

## 14. Browser state architecture

Server/persisted state owns:

- assessment identity;
- authorization;
- plan;
- approval;
- worker/tool state;
- activity;
- evidence/findings;
- cancellation/recovery;
- report readiness.

Browser state owns only ephemeral UI concerns such as open drawer, draft, selected disclosure and last-seen activity cursor.

Reconnect reconstructs. It does not restart.

---

## 15. Security invariants

Never allow:

- arbitrary public scanning;
- authorization inferred from text;
- public-to-private/metadata pivot;
- unrestricted redirects;
- raw command injection;
- unreviewed scanner templates;
- secret leakage to logs/providers;
- model-created authority;
- browser-invented task state;
- destructive execution without separate explicit policy;
- hidden chain-of-thought rendering.

---

## 16. Product status separation

Architecture, implementation and acceptance are different states.

Use:

```text
CONTRACT APPROVED
RUNTIME NOT COMPLETE
RUNTIME IMPLEMENTED
AUTOMATED ACCEPTANCE COMPLETE
MANUAL EVIDENCE PENDING
IMPLEMENTED AND VERIFIED
```

rather than ambiguous `complete`.

Current truth lives in `CURRENT_STATE.md`.

---

## 17. Current priority sequence

1. public-target passive worker/transport implementation;
2. rich persisted live execution activity across website/Source Hunt/APK;
3. UI Contract V2 runtime migration/cleanup;
4. Source Hunt preflight/path semantics;
5. cross-workflow browser/phone acceptance;
6. remaining ML/Hugging Face programme;
7. production/isolation/readiness.

Exact delivery details live in `ROADMAP.md`.

---

## 18. Definition of finished product

VulnHunter is not finished merely when routes exist or tests are green.

The finished product must demonstrate:

- exact authorization for private/public targets;
- safe public/private transport containment;
- bounded scanner execution;
- one persisted live task experience;
- evidence/finding integrity;
- human governance;
- Source Hunt/APK workflows in same task model;
- browser UI conformance on desktop/phone;
- reconnect/recovery correctness;
- truthful provider/ML behavior;
- production environment acceptance.

Security truth, persisted state, user experience and documentation must agree.
