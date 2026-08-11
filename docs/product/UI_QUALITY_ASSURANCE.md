# VulnHunter UI Quality Assurance

**Status:** BINDING BROWSER / RESPONSIVE / ACCESSIBILITY / STATE-TRUTH GATE  
**Canonical design:** `docs/design/VULNHUNTER_UI_CONTRACT.md`  
**Agent standard:** `docs/design/AI_AGENT_UI_IMPLEMENTATION_STANDARD.md`  
**Workflow:** `docs/product/CHAT_FIRST_WORKSPACE.md`  
**Live execution:** `docs/product/LIVE_EXECUTION_ACTIVITY.md`  
**Public targets:** `docs/product/PUBLIC_TARGET_ASSESSMENT.md`  
**Hard acceptance:** `docs/product/UI_ACCEPTANCE_CRITERIA.md`

A page is not ready because it renders, a route returns 200, a screenshot looks attractive or a test finds an expected string.

A product-facing slice is ready only when the browser presents the same authoritative backend state, follows the locked conversation/task-first product design, remains usable on supported phone/desktop layouts, and provides reproducible evidence.

---

## 1. Quality ownership

The locked UI contract owns visual/interaction design.

The AI agent implementation standard owns frontend implementation/rejection discipline.

The chat-first contract owns task/workflow semantics.

The live-execution contract owns running operational telemetry.

The public-target contract owns authorised public-target UX/security semantics.

Backend services remain authoritative for authorization, scope, worker capability, evidence, verification, review, release and publication.

A green UI audit cannot override a failed security/worker/repository gate. A green backend test cannot excuse an unreadable or contradictory UI.

---

## 2. Required PR gate levels

### 2.1 Repository/static correctness

Run applicable gates from `AGENTS.md`.

No UI test may weaken an authorization, scope, worker, evidence or review invariant to obtain a green result.

### 2.2 Backend-connected browser behavior

Exercise real routes, views, permissions, projections and commands rather than static mock pages only.

For lifecycle work, browser assertions must be paired with authoritative persisted state or projection assertions.

A screenshot that says `Running` while the backend says `Blocked` is a failure.

### 2.3 Cross-surface state identity

Verify:

- one workspace/assessment identity across chat/activity/inspector/history/findings/evidence/report;
- queued/running state never coexists with contradictory “no active assessment” UI;
- findings/evidence/report identify the owning assessment;
- worker failure updates the same task;
- zero findings does not erase evidence/history;
- provider health is not confused with worker/assessment health;
- refresh/reconnect restores the same selected task;
- browser code does not fill missing state with demonstration values.

### 2.4 Product/design conformance

Verify:

- conversation/task-first hierarchy;
- compact task/chat navigation;
- contextual detail closed by default;
- canonical cream/dotted/dusty-pink/dark-sidebar visual language;
- square/nearly-square controls/cards;
- hard zero-blur shadows;
- readable assistant/body text;
- no deprecated dashboard/tool-bar patterns;
- no hidden chain-of-thought.

---

## 3. Public-target browser gate

When public-target behavior is affected, verify all applicable states.

### Authorization missing

```text
Authorization required
Target  https://example.com/
Class   Public
Port    443
Path    /
```

The UI must not imply that public reachability equals permission.

### Authorization verified but worker unavailable

Until a public-capable worker exists, this must remain truthful:

```text
✓ Authorization verified
! Public execution unavailable
  Configured worker supports private targets only.
```

The task must not transition visually to queued/running.

### Public execution implemented

Only after runtime support exists, verify:

- exact authorization identity;
- public target class;
- exact immutable plan;
- worker public capability;
- queued/running state from backend;
- live activity/evidence;
- reconnect continuity;
- expiry/revocation/blocker state.

Browser controls must never toggle worker target class, disable DNS containment or bypass authorization.

---

## 4. Live execution browser gate

For every affected long-running workflow, verify the UI can answer from persisted state:

- what is happening now?;
- what completed?;
- what is next?;
- which worker/tool is active, when known?;
- what real receipts/evidence/candidates exist?;
- did anything fail/recover?;
- what was preserved?;
- what action is actually available?

Required assertions include:

- queued → worker claimed/running updates same task;
- task rows update from persisted stages/events;
- tool chips appear only after real state/receipts;
- latest activity is visible from the conversation;
- event counts/receipt counts/candidate counts match backend truth;
- duplicate polls do not duplicate rows;
- reconnect does not replay old events as new;
- terminal state stays stable after refresh;
- no hidden reasoning is rendered;
- no browser-generated fake percentage is shown.

A generic `backend is executing; check another page` message is insufficient when backend activity exists.

---

## 5. Source Hunt QA

Verify:

- conversation/context can initiate Source Hunt;
- setup page remains a focused continuation;
- preflight shows resolved root/revision and effective limits;
- predictable file-count/byte-limit blockers appear before full submission where possible;
- permitted-path wording matches actual runtime snapshot semantics;
- successful queue binds to the originating workspace;
- running hunt shows persisted snapshot/inventory/hypothesis/falsification/capability/remediation stages where emitted;
- failed hunt preserves snapshot/approval/activity/report identity;
- reconnect does not create a second job.

Regression requirement: a Source Hunt in `running` state must fail QA if only a generic timestamp is shown while richer persisted worker information exists.

---

## 6. Website assessment QA

Verify the applicable sequence:

```text
target
→ authorization
→ immutable plan
→ decision
→ queue
→ worker activity
→ evidence
→ verification
→ result/report
```

For private/public target classes, the same task identity and UI semantics apply; only the required authorization/worker containment differs.

Verify no target-class-specific UI creates a second workflow state machine.

---

## 7. APK/mobile QA

Verify distinct states for:

- selected file;
- uploading bytes;
- upload complete but validating;
- integrity verified;
- assessment bound;
- each static tool queued/running/completed/failed;
- evidence normalization;
- verification;
- completion/failure/recovery.

100% bytes uploaded is not analysis complete.

Uploading does not imply dynamic execution.

Partial tool failure preserves completed evidence where backend supports continuation.

---

## 8. Browser defect checklist

Fail on:

- HTTP/Django errors;
- uncaught JS/page errors;
- failed static assets;
- duplicate IDs;
- unnamed controls;
- dead actions;
- incorrect active navigation;
- horizontal body overflow;
- clipped primary controls;
- overlays outside viewport;
- mobile desktop-sidebar visible by default;
- missing mobile drawer trigger;
- covered/unreachable composer;
- unreadable message copy;
- permanent context panel without requested context;
- competing navigation systems;
- fabricated task state.

---

## 9. Responsive visual evidence

Representative widths:

- `1440×900`;
- `1280×800`;
- `1024×768`;
- `768×1024`;
- `412×915` or similar;
- `390×844`;
- `360×800`.

Also check short-height landscape for sticky headers/composer/dialog/sheet/keyboard work.

Screenshots are evidence, not authority.

---

## 10. Mobile shell gate

At phone width:

- desktop sidebar becomes overlay task/chat drawer;
- workspace is one column;
- no permanent desktop inspector beside chat;
- context/activity detail uses full-width sheet/drawer/deep view;
- task state remains readable;
- no essential horizontal page scroll;
- primary actions do not clip/truncate;
- safe areas are respected;
- composer remains usable with virtual keyboard;
- body copy remains readable;
- desktop KPI grids/toolbars are restructured, not miniaturized;
- tool chips wrap cleanly.

Primary mobile navigation remains task/chat-oriented, not a competing bottom-tab dashboard unless a separately approved product change says otherwise.

---

## 11. Composer gate

Primary composition remains:

```text
Attach / add
Text input
Send
```

Provider/advanced diagnostics belong behind progressive disclosure/settings.

Validate:

- ~16px input text where needed to avoid mobile browser zoom;
- ~44px critical touch targets;
- composer reachable with keyboard open;
- latest content not permanently covered;
- one authoritative upload-progress source;
- disabled state explains actual backend reason;
- composer usable during supported running/approval states;
- queued follow-up state visible where supported.

---

## 12. AI-native component gate

### Task rows

One coherent state language for pending/running/blocked/recovering/failed/cancelled/completed.

### Tool chips

Only real tool/receipt/provenance state.

### Authorization/approval cards

Exact object/action/scope and real backend actions. Authorization, plan confirmation, independent approval, review and adjudication remain distinct.

### Context/evidence/finding cards

Concise summary first, deeper view on demand.

### Recommendations

Advisory only unless backend confirms action/verification.

### Activity/thinking

Safe operational text only. Never hidden reasoning.

---

## 13. Product-truth scenarios

Use real/representative backend states rather than one fixture for all lifecycle states.

Cover applicable:

- no selected assessment;
- authorization missing/verified;
- public target with private-only worker blocker;
- planning;
- confirmation/approval;
- queued;
- worker claimed/running;
- follow-up queued;
- evidence/tool receipt;
- dependency blocked;
- partial tool failure;
- recovery;
- cancellation requested/race/completed;
- terminal failure;
- complete with zero findings but preserved evidence;
- complete with findings;
- review required;
- report ready;
- archived/historical task.

---

## 14. Idempotency/recovery scenarios

Cover applicable:

- double tap/duplicate submission;
- slow network;
- timeout after backend success;
- refresh;
- disconnect/reconnect;
- stale page resubmission;
- stale CSRF/session recovery;
- Android Back/forward;
- same assessment on another device;
- browser-local state cleared.

The UI should recover the existing authoritative object rather than create duplicate assessment/approval/job/cancellation/retry records.

---

## 15. Failure/retry scenarios

When failure UI changes, verify available typed fields:

- error category;
- stable reference ID;
- exact failed stage;
- understandable reason;
- completed stages;
- preserved evidence;
- user-vs-operator action required;
- backend retry eligibility;
- retry scope/new attempt identity;
- prior attempts/receipts retained.

No Retry control when safe idempotent retry is unavailable.

---

## 16. Accessibility

Verify applicable:

- keyboard-only operation;
- logical focus order;
- visible focus;
- dialog/sheet focus containment/restoration;
- Escape/Android Back behavior;
- accessible control names;
- status conveyed by text/icon not color alone;
- reduced motion;
- forced-colors/zoom/reflow where affected;
- important lifecycle announcements to assistive technology;
- high-frequency activity does not spam screen readers.

Physical TalkBack remains manual evidence unless actually tested.

---

## 17. Required evidence before merge

A meaningful product-facing PR should report:

- exact affected routes/workflows;
- backend states tested;
- relevant unit/integration/browser gates;
- desktop/phone browser evidence;
- public-target blocked/success state if applicable and actually runtime-supported;
- live activity compared with persisted event state;
- remaining manual/environment limitations;
- no console/page/static-asset errors;
- no essential phone overflow.

Do not claim a capability because a screenshot was rendered from mock data.

---

## Final rule

VulnHunter UI QA passes only when **security authority, persisted task state, public/private target truth, live execution truth, canonical design and responsive/accessibility evidence** agree.
