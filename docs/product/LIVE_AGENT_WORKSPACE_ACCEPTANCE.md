# VulnHunter Live Agent Workspace — Acceptance Scenarios

**Status:** binding acceptance companion for live-agent implementation  
**Product contract:** `docs/product/LIVE_AGENT_WORKSPACE.md`  
**Engineering plan:** `docs/engineering/LIVE_AGENT_WORKSPACE_IMPLEMENTATION_PLAN.md`  
**Existing UI gates remain binding:** `docs/product/UI_ACCEPTANCE_CRITERIA.md`

## 1. Purpose

This document defines how to prove that VulnHunter behaves like a real live agent workspace rather than a request/response chatbot with animated decoration.

A change is accepted only when the applicable scenarios below pass with truthful persisted state.

Passing screenshots alone is insufficient.

## 2. Global acceptance principles

Every scenario must preserve these rules:

- conversation/task-first product hierarchy;
- backend-owned authorization, scope, approval, verification, review and publication authority;
- no hidden chain-of-thought;
- no fabricated percentages or tool state;
- no browser-only completion claims;
- no unsupported Pause control;
- no arbitrary shell execution from chat;
- no public-target authorization bypass;
- no secret-bearing live-event payloads;
- same task semantics on phone and desktop;
- reconnect restores rather than restarts.

## 3. Scenario A — Brand-new clean workspace

### Given

The authenticated user creates a new assessment workspace with no prior messages.

### Expected

- persisted conversation message count is zero;
- no synthetic assistant welcome message is inserted;
- the UI displays a clean empty state;
- quick-start actions may be visible;
- quick-start actions are not persisted assistant turns;
- composer is focused/reachable;
- no run/task card is fabricated;
- no provider/model badge is shown merely because the workspace is empty.

### Failure examples

- an assistant message appears before the user has interacted;
- the UI invents a target or current assessment;
- quick starts are stored in history as assistant content.

## 4. Scenario B — Ordinary conversational answer

### Given

The user asks a non-execution question supported by the advisory conversation layer.

### Expected

- user message appears immediately after successful local submission handling;
- one network request is prevented from double-submit;
- the whole workspace is not treated as a long-running execution;
- assistant answer appears atomically unless real server text streaming is implemented;
- no fake word animation is labelled/implied as server streaming;
- provider failover remains silent when fallback succeeds;
- hidden reasoning/private prompts are never returned.

## 5. Scenario C — Start an authorised website assessment

### Given

The user requests a scan of a target already covered by a valid authorization.

### Expected sequence

```text
request accepted
→ target/scope resolved
→ authorization verified
→ immutable passive plan prepared
→ exact confirmation shown
```

### Expected UI

- task/session appears in the conversation;
- timeline shows authorization and plan states truthfully;
- confirmation object contains exact target/port/profile/scanner/limits/digest when persisted;
- scanner traffic does not start before required confirmation;
- composer remains available.

### Blocked case

If authorization does not cover the exact URL/port, show authorization required and do not create scanner execution.

## 6. Scenario D — Confirm exact passive plan

### Given

A valid immutable passive plan is awaiting owner confirmation.

### Expected

- displayed plan identity matches authoritative digest;
- stale/tampered digest is rejected;
- confirmation is persisted by backend;
- task timeline updates from blocked to queued/running only after backend transition;
- the UI does not optimistically mark the scanner running before receipt;
- no generic independent approval is conflated with owner confirmation.

## 7. Scenario E — Running task feels live

### Given

A worker has begun a supported assessment.

### Expected

- EventSource/live transport connects from a durable cursor;
- meaningful task transitions appear close to persistence time;
- the active stage shows `◌` or equivalent running state;
- completed stages use `✓` only after completion is authoritative;
- pending stages remain pending;
- real tool start/completion/failure receipts appear as appropriate;
- elapsed time is shown only from trustworthy timestamps;
- no fake percent bar is introduced;
- the composer remains usable;
- safe cancel/stop is available only if backend says the task is cancellable.

## 8. Scenario F — Tool execution and receipts

### Given

A task invokes one or more deterministic tools.

### Expected

For each tool receipt, the UI may show persisted values such as:

- tool name;
- version;
- start/end;
- duration;
- worker;
- exit state;
- receipt/digest;
- produced evidence/artifacts.

### Required semantics

- tool failure is not automatically a finding;
- a tool cannot appear successful before a receipt/state confirms success;
- replayed event does not duplicate tool row;
- unavailable fields remain unavailable.

## 9. Scenario G — Follow-up while execution is running

### Given

The user sends a relevant follow-up while the task is running.

Example:

```text
Focus more on libhsMediaLibrary.so.
```

### Expected

- composer accepts the instruction while execution continues;
- the original task is not restarted;
- backend validates and persists the follow-up;
- if deferred, UI shows `Queued` only after backend confirms queued state;
- queued instruction survives refresh;
- when applied, state changes from queued to applied/completed from backend events;
- duplicate submission does not create duplicate queue items.

### Unsupported case

If the active workflow does not support queued follow-ups, the assistant explains that limitation truthfully and does not show a fake queue state.

## 10. Scenario H — Refresh/reconnect during running work

### Given

A task is running and the user refreshes the browser or temporarily loses the live connection.

### Expected

- no new task/run is created;
- no previous user message is re-posted;
- workspace hydrates from persisted messages/state;
- current task projection is restored;
- last event sequence/cursor is recovered;
- EventSource reconnects from the known cursor;
- duplicate replay does not duplicate timeline/tool rows;
- UI may show `Restoring workspace…` or reconnecting state;
- EventSource disconnect is not presented as worker failure;
- terminal state cannot regress to running because an old event is replayed.

## 11. Scenario I — Live transport unavailable temporarily

### Given

The SSE/activity endpoint returns a retryable error or connection is interrupted.

### Expected

- task remains visible from persisted state;
- composer remains usable where possible;
- UI displays a restrained reconnecting state;
- retry/backoff occurs safely;
- REST resync may be used;
- no task restart;
- no fabricated events while disconnected.

## 12. Scenario J — Cancel a running task

### Given

The active task supports safe cancellation.

### Expected

- user can invoke cancel/stop;
- optional confirmation explains the real consequence;
- backend validates ownership/state/cancellability;
- cancellation request is persisted;
- timeline shows cancelling only if such backend state exists;
- terminal cancelled state appears only after confirmed;
- completed stages/evidence remain visible;
- no additional scanner work starts after cancellation contract takes effect;
- queued follow-ups are handled according to backend policy;
- composer remains available for a new task/conversation action.

### Failure

A browser-only button that merely hides the timeline does not count as cancellation.

## 13. Scenario K — Worker interruption and recovery

### Given

A worker/task temporarily interrupts while persisted recovery is supported.

### Expected

- UI shows recovery, not automatic terminal failure;
- persisted completed stages remain completed;
- valid evidence remains visible;
- user-facing copy may state that persisted state is preserved;
- successful recovery is shown only after backend confirms it;
- failed recovery becomes a truthful terminal failure.

## 14. Scenario L — Terminal tool/task failure

### Expected

- terminal failure state is explicit;
- completed stages do not disappear;
- valid evidence is preserved;
- failure reason is redacted and understandable;
- safe next action is shown only if repository-backed;
- no completion animation or success color is displayed.

## 15. Scenario M — APK upload and automatic static analysis

### Given

The user attaches a valid APK.

### Expected sequence

```text
upload
→ archive validation
→ SHA-256/integrity
→ artifact identity
→ static/native plan
→ worker queue
→ tool execution
→ evidence/findings/verification
```

### Expected UI

- resumable upload state is visible when applicable;
- upload progress comes from received/expected bytes, not a fake timer;
- archive/integrity state is explicit;
- APK execution is never implied by upload;
- static tools appear as real tool receipts;
- one tool failure may remain isolated if backend continues later tools;
- dynamic follow-up remains separately gated;
- refresh restores the same mobile job.

## 16. Scenario N — APK contextual inspection

### Given

APK analysis has persisted inspectable objects.

### Expected

The user can open supported context views such as:

- package/artifact metadata;
- manifest;
- DEX inventory;
- native library inventory;
- bounded tool output;
- evidence;
- findings.

### Security

- object ownership is rechecked server-side;
- guessed artifact/object IDs do not expose another workspace;
- no arbitrary file-path fetch endpoint exists.

## 17. Scenario O — Source Hunt start and approval

### Given

The user asks VulnHunter to review an approved repository/root.

### Expected

- task begins in conversation;
- exact repository/root/revision/snapshot is shown from persisted state;
- source-processing approval is visibly distinct when required;
- giant standalone source dashboard is not required for the primary flow;
- protected specialist view may open for re-authentication/permitted paths/approval;
- result projects back into originating conversation.

## 18. Scenario P — Source evidence contextual view

### Expected

- source reference opens exact file/revision/hash/line range;
- stale/mismatched hash is rejected;
- path expansion/traversal is rejected;
- user returns to same conversation/task after closing context;
- source excerpts remain within privacy/redaction policy.

## 19. Scenario Q — Finding appears during/after task

### Expected

- finding is shown only after persisted finding object exists;
- candidate/verification/review state is truthful;
- severity is not upgraded by browser/model presentation;
- evidence/provenance link opens contextual detail;
- full finding view remains same workspace/deep-view concept;
- no fake finding counts.

## 20. Scenario R — Report ready and preview

### Given

A persisted report has been generated.

### Expected

```text
✓ Security report created
[Open report]
```

- report action is absent before report exists;
- preview opens in context drawer/sheet/deep view;
- closing preview returns to same conversation;
- report identity/ownership is verified;
- preview does not create a second task workflow.

## 21. Scenario S — Silent provider failover

### Given

Groq cannot answer and configured fallback succeeds through Gemini or Ollama.

### Expected

- user receives one normal advisory answer;
- ordinary conversation does not show `Groq failed`, `Trying Gemini`, etc.;
- provider/model chain may remain in internal diagnostics/audit;
- task/authorization/execution state is unaffected;
- provider output cannot grant security authority.

### All providers unavailable

- short retry/unavailable message is acceptable;
- deterministic workflows remain available where supported;
- no fake AI answer is generated.

## 22. Scenario T — Real assistant text streaming

Apply only if implemented.

### Expected

- server emits user-facing answer deltas in order;
- deltas assemble into the exact final answer;
- reconnect handling avoids duplicate text;
- hidden reasoning tokens are never present;
- provider failover errors are not streamed to ordinary user view;
- fallback to atomic answer works when streaming is unavailable.

### Failure

Animating a fully received answer word-by-word is not accepted as server streaming.

## 23. Scenario U — Desktop context viewer

### Expected

- viewer is closed by default;
- opens beside conversation only when requested;
- selected object identity is clear;
- conversation remains readable;
- Escape/close returns focus to trigger;
- long code/hash/path does not expand viewport uncontrollably;
- no permanent metric/detail rail is introduced.

## 24. Scenario V — Mobile context viewer

### Expected

- viewer becomes full-width sheet/deep view;
- browser/Android Back closes context before leaving workspace where feasible;
- primary actions are not hidden under system bars;
- close returns to same conversation scroll/task state;
- no desktop side drawer is squeezed into phone width.

## 25. Scenario W — Mobile running workspace

Verify near 360, 390 and 412 CSS px.

### Required

- one-column layout;
- task drawer overlay, not permanent desktop sidebar;
- readable 15–17px primary body range;
- critical controls approximately 44px minimum;
- composer reachable while task runs;
- queued follow-up visible;
- no essential horizontal scroll;
- task rows/tool chips wrap safely;
- long filenames/hashes/code do not break viewport.

## 26. Scenario X — Tablet/desktop workspace

Verify near 768, 1024, 1280 and 1440 CSS px.

### Required

- conversation owns main width;
- context panel closed by default;
- reading width remains comfortable;
- sidebar proportions remain task-focused;
- composer anchored and reachable;
- no KPI wall or utility toolbar competes with execution timeline.

## 27. Scenario Y — Accessibility of live updates

### Expected

- important state transitions are announced semantically;
- low-level event spam is not continuously announced;
- state is conveyed by text/icon, not color alone;
- keyboard can open timeline disclosures/context objects;
- visible focus states remain;
- drawer/sheet focus is trapped/restored appropriately;
- reduced-motion preference suppresses non-essential movement;
- no hidden reasoning is placed in visually hidden accessibility text.

## 28. Scenario Z — Event integrity and replay

### Required tests

- monotonic/stable sequence handling;
- duplicate event ignored safely;
- stale cursor triggers authoritative resync;
- out-of-order event cannot regress terminal state;
- cross-workspace event is rejected/ignored;
- event payload ownership enforced server-side;
- secret-bearing payload is redacted/rejected;
- reconnect does not recreate task/tool/finding objects.

## 29. Anti-fabrication gates

The implementation fails immediately if any changed surface does any of the following:

- creates a fake percentage;
- marks a tool complete from a frontend timer;
- shows a finding before persistence;
- shows a report action before report existence;
- claims a queued follow-up before backend persistence;
- treats SSE disconnect as scanner failure without backend evidence;
- labels client word animation as model streaming;
- displays hidden reasoning;
- exposes fallback-provider failures as ordinary task activity;
- invents arbitrary terminal/command execution.

## 30. Security adversarial acceptance

At minimum, test:

- guessed run ID;
- guessed workspace/thread ID;
- guessed evidence/finding/report/artifact ID;
- stale approval request;
- stale/tampered plan digest;
- duplicate follow-up submission;
- chat text attempting to self-authorize;
- chat text attempting to expand scope;
- source path traversal;
- stale source hash/revision;
- cancelled task receiving old running event;
- event containing prohibited sensitive value.

All must fail closed without leaking another user's/state's data.

## 31. Manual reference-behavior parity checklist

The live workspace reaches the intended reference behavior when a reviewer can observe all applicable items below in a real browser session:

- user gives one task in chat;
- task creates visible live execution state quickly;
- completed steps remain visibly completed;
- one current step is clearly active;
- real tools/files/evidence appear during the task;
- user can keep typing while task runs;
- supported follow-up becomes visibly queued/applied;
- user can inspect the current artifact/evidence/source/report without abandoning the conversation;
- cancel/stop is available when supported;
- elapsed duration is truthful;
- refresh reconnects to same work;
- final result is part of the same conversation;
- no fake reasoning/progress is used to create the effect.

This checklist is about interaction quality only. Another product's branding, colors, unsupported tools, arbitrary terminal access, provider controls or account concepts are explicitly out of scope.

## 32. Required automated and manual evidence before merge

Use the repository's normal verification suite plus applicable live-agent tests.

Required evidence for a substantial live-agent batch should include:

- unit/contract test output;
- conversation regression tests;
- activity/SSE tests;
- browser lifecycle tests;
- phone screenshots or equivalent browser evidence at supported widths;
- desktop screenshots/evidence;
- changed failure/recovery state evidence;
- APK/Source Hunt evidence when those batches are changed;
- exact remaining limitations.

## 33. Definition of accepted

A live-agent implementation is accepted only when:

1. the workspace is genuinely clean on first use;
2. execution state is durable and live;
3. events are replay/reconnect safe;
4. task/tool activity is truthful and inline;
5. the composer remains usable during running work;
6. supported follow-ups are truly queued/applied;
7. context objects open without breaking workspace continuity;
8. cancellation/recovery/terminal states are truthful;
9. website/APK/Source Hunt flows preserve existing governance;
10. provider failover remains silent and non-authoritative;
11. phone and desktop pass the same critical workflow;
12. no fake progress, fake streaming or hidden reasoning appears;
13. existing VulnHunter visual/security contracts still pass.
