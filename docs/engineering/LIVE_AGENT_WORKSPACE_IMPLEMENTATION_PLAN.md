# VulnHunter Live Agent Workspace — Engineering Implementation Plan

**Status:** implementation plan  
**Product contract:** `docs/product/LIVE_AGENT_WORKSPACE.md`  
**Parent workflow contract:** `docs/product/CHAT_FIRST_WORKSPACE.md`  
**Visual authority:** `docs/design/VULNHUNTER_UI_CONTRACT.md`  
**Batch-delivery authority:** `docs/engineering/TEST_ENGINEERED_BATCH_DELIVERY.md`  
**Acceptance:** `docs/product/LIVE_AGENT_WORKSPACE_ACCEPTANCE.md`

## 1. Goal

Implement the live-agent workspace as an evolution of the current conversational architecture, not as a parallel frontend and not as a cosmetic clone.

The required end state is:

```text
clean conversation
→ user request
→ durable task/session
→ live ordered activity events
→ inline task/tool execution timeline
→ persistent composer
→ queued follow-ups where supported
→ contextual object viewer
→ reconnect/replay
→ same-workspace findings/evidence/report outputs
```

The implementation must preserve all authorization, approval, evidence, review, worker and publication boundaries already enforced by the repository.

## 2. Current implementation inventory

The repository already contains major pieces required for this work.

### 2.1 Conversation backend

Primary file:

- `vulnhunter/web/conversational_views.py`

Current responsibilities include:

- loading/storing conversation messages;
- resolving active run state;
- interpreting user requests;
- target/authorization/profile resolution;
- exact passive-plan confirmation;
- cancellation handoff;
- run/status payload generation;
- recent run hydration.

Important current behavior to change during implementation:

- `_messages()` injects a synthetic assistant welcome message when the conversation is empty. The new live-agent contract requires a genuinely empty persisted conversation and UI-only quick starts.

### 2.2 Conversation frontend

Primary file:

- `vulnhunter/web/static/web/conversation.js`

Current useful behavior includes:

- conversation rendering;
- run-card rendering;
- approval controls;
- finding/evidence rendering;
- message submission;
- run status refresh;
- history drawer;
- input resizing;
- elapsed-time derivation.

Important current behavior to refactor:

- `setBusy()` disables both send and input for a request-in-flight state. A live-agent workspace needs to distinguish request submission from long-running task execution.
- assistant text currently has a word-by-word client animation after the complete response has already arrived. That must not be represented as real streaming.
- active run updates are driven primarily by repeated status fetches. Live activity should move to the existing SSE/event infrastructure with REST retained for initial hydration/resynchronization.
- a large run card/disclosure model currently carries much of the progress experience. The primary execution story should move into the conversation timeline, with deep detail remaining contextual.

### 2.3 Conversation template

Primary file:

- `vulnhunter/web/templates/web/conversation.html`

Useful existing primitives:

- primary conversation feed;
- thinking/activity row;
- persistent composer;
- attachment flow;
- history drawer;
- run/task template;
- task stages;
- tool chips;
- inline approval;
- findings/evidence/verification disclosures;
- mobile analysis inspector hooks.

Implementation direction:

- keep the conversation shell;
- simplify the base run representation;
- render live task rows/tool receipts directly in the main task flow;
- move large evidence/source/report detail into one contextual viewer model;
- keep the viewer closed by default.

### 2.4 Existing SSE/activity infrastructure

Primary files:

- `vulnhunter/web/stream_views.py`
- `vulnhunter/web/static/web/app.js`

The repository already has:

- authenticated SSE activity responses;
- `Last-Event-ID` / `after_sequence` cursor support;
- redacted activity summaries;
- retry/reconnect semantics;
- EventSource client use;
- terminal-state connection shutdown patterns.

This should be reused rather than inventing a new WebSocket stack for the first implementation.

The live-agent work should consolidate live conversation behavior around one authoritative event projection.

### 2.5 APK conversation flow

Primary files include:

- `vulnhunter/web/conversation_mobile_views.py`
- `vulnhunter/web/mobile_execution.py`
- `vulnhunter/web/mobile_conversation.py`
- `vulnhunter/web/mobile_conversation_state.py`

Useful current capabilities include:

- resumable upload;
- content-hash validation;
- automatic safe static-analysis start;
- mobile plan persistence;
- queued static worker execution;
- status URLs;
- follow-up conversation handling.

The implementation should project these existing states into the same live timeline/event model rather than maintaining a visually separate mobile-analysis product.

### 2.6 AI provider failover

Primary files:

- `vulnhunter/web/ai_failover.py`
- `docs/AI_PROVIDER_FAILOVER.md`

Current architecture supports silent advisory failover:

```text
Groq → Gemini → Ollama
```

Implementation rule:

- keep this invisible during normal successful fallback;
- do not build a provider-error timeline in the ordinary conversation;
- keep provider identity/details in diagnostics/audit where appropriate;
- never grant providers execution/authorization/verification authority.

## 3. Architectural principles for the migration

### 3.1 No second frontend state machine

Do not implement one state machine for polling, another for SSE, another for mobile APK work and another for Source Hunt.

The browser should receive a normalized workspace/task projection and ordered events and render them through shared primitives.

### 3.2 REST hydrates, events advance

Preferred architecture:

```text
page load
→ REST/server-rendered hydration of current durable workspace
→ EventSource connects from last known sequence
→ ordered events advance UI
→ occasional REST resync only when required
```

### 3.3 Persisted task truth precedes animation

The browser never marks a stage complete because a timeout finished or an animation reached the end.

The state changes because the authoritative run/task/job/event state changed.

### 3.4 Context is object-based

The contextual viewer should open a typed persisted object:

```text
artifact
source reference
tool receipt
evidence
finding
report
approval detail
```

Do not make the viewer an arbitrary HTML dumping area.

### 3.5 Incremental migration

Do not rewrite the entire conversation stack in one change.

Each batch must leave a coherent working product and must include regression/blocked/reconnect coverage.

## 4. Proposed normalized client runtime state

The browser should converge on a shape conceptually equivalent to:

```text
workspace
  id
  title
  connection_state
  messages[]
  active_task
  queued_followups[]
  selected_context
  last_event_sequence

active_task
  id
  type
  state
  subject
  started_at
  terminal
  cancellable
  stages[]
  tools[]
  artifacts[]
  findings[]
  approval
  recovery
```

This is a browser projection only. The backend remains authoritative.

## 5. Proposed event projection layer

Prefer a server-side adapter that normalizes existing activity/task-graph/mobile/source events into one redacted event envelope.

A possible module boundary is:

- `vulnhunter/web/conversation_events.py`

Responsibilities:

- accept existing persisted task/activity records;
- map them into normalized event types;
- enforce redaction;
- attach workspace/run/job identity;
- preserve stable sequence/order;
- expose replay-safe summaries;
- never invent progress.

Do not create a new database if existing activity/task stores already provide sufficient immutable sequence and recovery semantics.

## 6. Proposed live conversation endpoint

A dedicated or generalized endpoint may expose workspace/task events.

Prefer extending existing SSE patterns rather than replacing them.

Requirements:

- authentication;
- owner/workspace visibility check;
- `Last-Event-ID` and/or `after_sequence` support;
- private/no-store headers;
- `X-Accel-Buffering: no`;
- bounded event payload;
- redaction;
- retry guidance;
- terminal close behavior;
- no hidden reasoning.

If the current activity SSE remains run-specific, the conversation client may bind to the active run while the normalized projection layer handles workflow differences.

## 7. Frontend module strategy

Do not create another global patch stylesheet.

Prefer consolidating responsibilities in existing component owners.

Suggested JavaScript responsibility split only if the existing file becomes too large:

- `conversation.js` — conversation orchestration and form/message lifecycle;
- `conversation-events.js` — EventSource connection, cursor/replay/dedup/resync;
- `conversation-task-timeline.js` — task/stage/tool projection;
- `conversation-context-viewer.js` — typed contextual drawer/sheet behavior.

If fewer files are clearer, keep the behavior together. The important requirement is one state model, not a specific file count.

CSS must be implemented at the current shared owner for:

- task rows;
- tool chips;
- context viewer;
- composer state;
- mobile drawer/sheet;
- reconnect/queued/recovery states.

Do not add a late `live-agent-fixes.css` file.

## 8. Batch 0 — Contract and regression scaffolding

### Product outcome

Create tests that lock the target behavior before major frontend changes.

### Work

Add or extend tests for:

- empty workspace has zero persisted synthetic assistant messages;
- initial quick starts are UI actions, not stored messages;
- running task does not imply disabled composer;
- task status comes from backend state;
- EventSource cursor/reconnect semantics;
- duplicate event suppression;
- terminal event stability;
- no hidden reasoning fields in event payloads;
- no browser-created fake percentage;
- current cancellation contract preserved.

### Likely test areas

- `tests/unit/test_conversational_workspace.py`
- `tests/unit/test_conversation_experience.py`
- `tests/unit/test_assessment_workspace_ui.py`
- `tests/unit/test_web_activity_stream.py`
- responsive/browser acceptance tests.

### Done

The target behavior is testable before the UI migration begins.

## 9. Batch 1 — Clean empty workspace and client busy-state separation

### Product outcome

A new workspace is genuinely clean and the frontend distinguishes message submission from long-running execution.

### Backend work

In `conversational_views.py`:

- remove the automatic persisted welcome assistant message;
- return an empty message list for a new conversation;
- preserve thread creation/title behavior after the first real user turn;
- ensure reset/new assessment returns a clean message list.

### Frontend work

In the conversation shell:

- render an empty-state prompt and quick starts when `messages.length === 0`;
- quick starts must not become assistant messages;
- split local state such as:

```text
messageSubmitting
assistantResponding
executionRunning
reconnecting
humanDecisionRequired
```

- do not disable the composer merely because `executionRunning === true`;
- keep double-submit prevention for the same message request.

### Remove misleading behavior

- remove fake word-by-word animation as a substitute for server streaming;
- render atomic assistant responses until real delta streaming exists.

### Tests

- reset/new workspace clean state;
- first actual user message becomes first persisted message;
- composer remains enabled during mocked running run state;
- double submit still blocked while one submission request is in flight.

### Done

The workspace feels user-led before any SSE work begins.

## 10. Batch 2 — Unified live event transport

### Product outcome

A running assessment updates the conversation from ordered server events instead of relying mainly on 1.5-second status polling.

### Backend work

- introduce/extend normalized conversation event projection;
- reuse existing task/activity sequence where possible;
- ensure redacted summaries;
- expose active state, terminal state, sequence and object references;
- support replay from a cursor;
- expose a resync response when required.

### Frontend work

- connect EventSource when an active task exists;
- track last sequence;
- deduplicate events;
- update the task projection in place;
- set `reconnecting` state on transport interruption;
- reconnect automatically;
- close at terminal state;
- use status REST only for hydration/resync/fallback.

### Migration rule

Do not let polling and SSE independently mutate the same task state indefinitely.

During migration, if both temporarily exist, define one as authoritative and remove the other after parity tests pass.

### Tests

- reconnect with `Last-Event-ID`;
- duplicate replay does not duplicate UI rows;
- stale cursor resync;
- terminal close;
- 403/404 ownership failure;
- 503 retryable event service failure;
- refresh restores current state without creating a new run.

### Done

Task transitions become visibly live and durable.

## 11. Batch 3 — Inline live task timeline and tool receipts

### Product outcome

The main conversation shows what VulnHunter is doing without requiring the user to open a large run card.

### Frontend work

Create/reuse shared primitives for:

- task row;
- stage group;
- tool receipt/chip;
- blocked/human-decision row;
- recovery/failure row;
- compact task header with state and elapsed duration.

### State language

Use only:

```text
✓ completed
◌ running
○ pending
Ⅱ blocked / action required
↻ recovering
! failed
× cancelled
```

### Rendering rule

The same task row updates in place as its persisted state changes.

Do not append a new row every time the server repeats the same state.

### Existing run card

Refactor the current large run card so that:

- primary progress becomes inline timeline;
- summary/finding/evidence actions remain available;
- large technical detail moves to context viewer;
- approval remains impossible to miss when required.

### Tests

- correct row state transitions;
- tool fail does not create finding;
- event ordering;
- elapsed duration derives from authoritative timestamps;
- unknown duration stays unavailable;
- stage list does not duplicate on replay.

### Done

The conversation itself feels like the execution interface.

## 12. Batch 4 — Contextual workspace viewer

### Product outcome

Users can inspect artifacts/evidence/source/tool/report objects without abandoning the conversation.

### Desktop behavior

- right-side contextual drawer;
- closed by default;
- opens from a selected typed object;
- conversation remains visible;
- Escape/close restores focus.

### Mobile behavior

- full-width sheet/deep view;
- Back closes the context first;
- no desktop side panel squeezed onto phone;
- return restores conversation position.

### Initial viewer object types

Implement only repository-backed types available now:

- evidence;
- finding;
- tool receipt/output;
- APK artifact/manifest/native library inventory where available;
- source reference/file-line view where available;
- report preview where persisted.

### Security

Every detail fetch repeats backend authorization/ownership checks.

Do not trust object IDs supplied by browser state.

### Tests

- cross-workspace object access rejected;
- missing/stale object safe failure;
- focus restoration;
- mobile Back behavior;
- long hash/path/code containment;
- context drawer closed by default.

### Done

The product has an inspection surface equivalent in usefulness to an agent workspace viewer, without arbitrary terminal authority.

## 13. Batch 5 — Follow-up instruction lifecycle

### Product outcome

The user can keep directing a supported active task while it runs.

### Backend requirements

Define a typed follow-up record bound to:

- workspace/thread;
- active task/run/job;
- requesting identity;
- submitted text after validation/redaction;
- lifecycle state;
- creation/applied/completion timestamps;
- safe rejection reason.

Recommended states:

```text
accepted
queued
applied
completed
rejected
cancelled
```

### Scheduling rule

Do not claim a follow-up is queued unless the backend has persisted it.

The task executor decides when a follow-up may be applied.

### Frontend work

- submit follow-up while execution continues;
- show `Queued` on the user instruction when appropriate;
- update to applied/completed from events;
- keep the composer enabled;
- prevent accidental duplicate follow-up submission.

### Tests

- queued follow-up survives refresh;
- duplicate request idempotency;
- wrong owner cannot view/modify queue;
- follow-up after terminal task handled truthfully;
- cancellation of task handles pending follow-ups according to backend contract.

### Done

The user can steer long-running work without creating a second conversation.

## 14. Batch 6 — APK live execution integration

### Product outcome

APK analysis becomes a first-class live-agent task rather than a separate status experience.

### Reuse current backend

Preserve:

- resumable upload;
- archive validation;
- SHA-256 record;
- artifact binding;
- mobile plan;
- static worker queue;
- tool receipts;
- dynamic-analysis gating.

### Add projection

Normalize APK stages/tools into the shared timeline:

```text
Upload
Integrity
Manifest
DEX/decompile
Native libraries
Crypto/search passes
Evidence correlation
Verification
```

Only show a stage if backed by real plan/task/tool state.

### Context viewer

Open:

- APK metadata;
- manifest;
- DEX inventory;
- native libraries;
- bounded tool output/evidence;
- findings.

### Tests

- upload resume;
- integrity failure;
- one static tool failure with later tools continuing when backend permits;
- worker unavailable;
- refresh restores mobile job;
- dynamic action remains gated.

### Done

The APK workflow matches the same conversation/runtime semantics as website assessment.

## 15. Batch 7 — Source Hunt live execution integration

### Product outcome

Source Hunt begins conversationally and projects its progress/evidence back into the same live task system.

### Preserve

- exact repository/root/revision/snapshot/path binding;
- remote-processing approval;
- deterministic entry/sink mapping;
- AI reconnaissance/falsification/capability filtering;
- evidence-backed remediation;
- read-only fix verification;
- human review/merge authority.

### Timeline examples

```text
✓ Repository resolved
✓ Revision snapshot created
Ⅱ Source-processing approval required
○ Map entry points
○ Trace candidate paths
○ Falsify candidates
○ Capability filter
○ Prepare remediation
```

### Context viewer

Open source evidence by exact file/revision/hash/line range.

### Tests

- stale revision;
- path expansion blocked;
- approval binding;
- source reference hash mismatch rejected;
- reconnect;
- same workspace result projection.

### Done

Source Hunt no longer feels like a separate product surface.

## 16. Batch 8 — Findings, evidence, remediation and report previews

### Product outcome

Outputs become natural continuations of the active task.

### Conversation behavior

Examples:

```text
✓ Evidence normalized

Finding available
[Open finding]
```

```text
✓ Security report created
[Open report]
```

### Context viewer

- finding detail;
- evidence/provenance;
- remediation recommendation;
- report preview;
- retest link/action when backend permits.

### Authority

Model recommendations remain advisory.

Verification, review, adjudication, release and publication remain governed.

### Tests

- report action absent before report exists;
- finding ownership;
- evidence redaction;
- stale report/finding IDs;
- deep view returns to same conversation.

### Done

A user can move from request to result without leaving the workspace conceptually.

## 17. Batch 9 — Real assistant text streaming, only if backend supports it

### Product outcome

User-facing answer text can stream progressively without exposing private reasoning.

### Preconditions

Do this only after operational event streaming is stable.

### Contract

Server emits:

```text
assistant.response.started
assistant.response.delta
assistant.response.completed
```

Deltas contain only final user-facing answer text.

### Fallback

If provider/backend streaming is unavailable, render the complete answer atomically.

Never simulate provider streaming by animating a fully received answer and labelling it live.

### Tests

- ordered delta assembly;
- reconnect/partial stream handling;
- no hidden reasoning field;
- fallback to atomic response;
- provider failover does not leak error chain.

## 18. Batch 10 — Responsive, accessibility and presentation-debt consolidation

### Product outcome

The complete live-agent workspace behaves correctly across phone/tablet/desktop and reduces CSS/JS duplication.

### Required viewports

- 360;
- 390;
- 412;
- 768;
- 1024;
- 1280;
- 1440 CSS px.

### Required states

- clean empty workspace;
- running timeline;
- queued follow-up;
- approval required;
- tool failure;
- recovery;
- evidence/finding context;
- APK context;
- Source Hunt context;
- report preview;
- terminal completed/cancelled/failed.

### Cleanup

- remove deprecated status/polling presentation paths no longer used;
- consolidate duplicate mobile rules;
- remove fake streaming animation;
- remove dead run-card UI that duplicates timeline/context viewer;
- do not add a new override stylesheet.

### Accessibility

- meaningful event announcements, not low-level spam;
- keyboard context navigation;
- focus restore;
- reduced motion;
- 44px critical phone controls;
- text/icon state semantics.

### Done

The live-agent workspace satisfies all existing UI acceptance criteria plus the dedicated acceptance companion document.

## 19. Detailed message-submission state machine

Recommended browser behavior:

```text
idle
  └─ submit → submitting
submitting
  ├─ accepted task → idle + executionRunning
  ├─ normal response → idle
  └─ error → idle + error message

executionRunning
  ├─ user submits follow-up → followupSubmitting
  ├─ live event updates → executionRunning
  ├─ reconnect error → reconnecting
  └─ terminal event → idle/terminal projection
```

`executionRunning` is not a reason to disable the composer.

## 20. Connection-state model

Recommended states:

```text
disconnected
connecting
connected
reconnecting
terminal
forbidden
```

User-facing copy should be calm and sparse.

Examples:

```text
Restoring live task state…
Connection interrupted — reconnecting…
Live updates restored.
```

Do not imply worker failure merely because EventSource disconnected.

## 21. Event deduplication requirements

Client must store at least:

- last accepted sequence;
- stable event IDs already rendered when needed for non-linear objects.

Rules:

- ignore sequence <= confirmed cursor when replayed and already applied;
- never duplicate a tool row because EventSource reconnects;
- rebuild from authoritative REST/task projection if continuity is uncertain;
- terminal state cannot regress to running because an old event is replayed.

## 22. Context viewer API guidance

Prefer typed endpoints/actions such as:

```text
GET persisted finding detail
GET persisted evidence detail
GET tool receipt detail
GET APK artifact detail
GET source reference detail
GET persisted report detail
```

Avoid a generic endpoint that accepts arbitrary file paths or shell commands.

Every object remains owner/scope checked.

## 23. Provider UX implementation rule

Remove ordinary per-message provider/model badges from the main conversation if they distract from the task.

Provider information may remain available in:

- diagnostics;
- advanced settings;
- audit/provenance;
- explicit troubleshooting.

A successful Groq→Gemini→Ollama fallback should look like one normal answer.

An all-providers-unavailable condition may show a short user-facing retry message while deterministic workflows remain available where supported.

## 24. Testing matrix

Every batch should add the applicable tests from this matrix.

### Unit

- event normalization;
- redaction;
- state transition mapping;
- cursor handling;
- follow-up lifecycle;
- object ownership checks.

### Conversation

- empty state;
- normal chat;
- assessment start;
- approval;
- running execution + new message;
- cancellation;
- reconnect;
- terminal restore.

### Browser

- EventSource updates DOM;
- duplicate event replay;
- context open/close;
- phone drawer/sheet;
- composer reachable;
- Back/Escape;
- long code/hash/path containment.

### Adversarial

- stale cursor;
- guessed run/object ID;
- cross-workspace access;
- forged approval in chat;
- duplicate follow-up;
- stale plan digest;
- hidden reasoning accidentally included in payload;
- event payload containing prohibited sensitive data.

## 25. Repository verification commands

At the end of each substantial implementation batch, follow repository policy, including:

```bash
python -m ruff format .
python -m ruff check .
python -m compileall -q vulnhunter
python -m pytest -q
python -m ruff format --check .
git diff --check
git status --short
```

Run the applicable browser/phone/private-lab acceptance in addition to the generic suite.

## 26. Browser evidence required before claiming completion

Capture applicable evidence for:

- desktop empty workspace;
- desktop running task;
- desktop context viewer;
- phone empty workspace;
- phone running task;
- phone queued follow-up;
- phone approval;
- phone context view;
- reconnect state;
- recovery/failure;
- APK live execution;
- Source Hunt live execution;
- finding/report preview.

Do not use only static screenshots of ideal states; exercise real state transitions.

## 27. Main implementation risks

### Risk: duplicated browser state

Mitigation: one normalized task projection and one event cursor.

### Risk: fake liveliness

Mitigation: no animation/state transition without backend truth.

### Risk: SSE and polling contradict each other

Mitigation: define REST hydration/resync and SSE advancement roles explicitly.

### Risk: context viewer becomes arbitrary file access

Mitigation: typed persisted object APIs with ownership/path/hash checks.

### Risk: queued follow-ups grant command authority

Mitigation: typed validated follow-up actions; text never becomes arbitrary shell execution.

### Risk: mobile becomes a squeezed desktop drawer layout

Mitigation: full-width sheet/deep view and one-column task flow.

### Risk: CSS debt increases

Mitigation: update shared owners and remove replaced selectors instead of adding overrides.

### Risk: provider details leak into UX

Mitigation: keep silent failover and diagnostics separation.

## 28. Recommended implementation order

Start in this exact dependency order unless repository inspection proves a different dependency:

1. contract/regression tests;
2. clean empty workspace;
3. frontend busy-state separation;
4. normalized event projection;
5. EventSource client + replay/resync;
6. inline task/tool timeline;
7. contextual viewer;
8. queued follow-ups;
9. APK projection;
10. Source Hunt projection;
11. finding/evidence/report preview;
12. optional real assistant text streaming;
13. responsive/a11y/presentation-debt cleanup;
14. full browser/phone/private-lab evidence.

## 29. Do not begin with these changes

Do **not** start by:

- changing colors/branding to match the reference video;
- adding a fake terminal;
- adding a generic Pause button;
- adding a browser-owned progress percentage;
- animating fake reasoning;
- adding provider/model selectors;
- replacing the entire conversation code before tests exist;
- adding another CSS override layer;
- implementing WebSockets simply because they sound more advanced;
- moving security decisions into the UI.

## 30. First implementation slice

The safest first code slice after these docs is:

```text
Batch 0 + Batch 1
```

That means:

- tests for clean/new workspace and composer semantics;
- remove persisted synthetic welcome message;
- UI-only quick starts;
- separate message-submitting state from execution-running state;
- remove simulated text streaming;
- preserve all current backend assessment/approval/cancellation behavior.

This gives a clean foundation before changing live transport.
