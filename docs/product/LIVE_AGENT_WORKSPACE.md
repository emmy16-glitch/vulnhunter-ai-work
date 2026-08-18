# VulnHunter Live Agent Workspace

**Status:** implementation-grade product extension  
**Parent workflow contract:** `docs/product/CHAT_FIRST_WORKSPACE.md`  
**Visual authority:** `docs/design/VULNHUNTER_UI_CONTRACT.md`  
**Agent implementation authority:** `docs/design/AI_AGENT_UI_IMPLEMENTATION_STANDARD.md`  
**Acceptance companion:** `docs/product/LIVE_AGENT_WORKSPACE_ACCEPTANCE.md`  
**Engineering plan:** `docs/engineering/LIVE_AGENT_WORKSPACE_IMPLEMENTATION_PLAN.md`

## 1. Purpose

This document translates the approved chat-first VulnHunter direction into a detailed live-agent workspace contract.

The target product is **not a chatbot that waits and returns a large answer**. VulnHunter should feel like a security operating environment controlled through conversation:

```text
user request
→ governed interpretation
→ durable task/session created
→ truthful live execution events
→ tools/evidence/findings appear as work happens
→ contextual workspace views open without abandoning the conversation
→ follow-up instructions remain possible while work is running
→ persisted results remain available after refresh/reconnect
```

The reference behavior that motivated this document is the experience of an agent that visibly works through a task: completed steps appear as completed, the current step remains visibly active, tool/file/browser activity appears in sequence, elapsed time is shown only when derivable, a stop/cancel action remains available when supported, and the composer stays available while work continues.

This document adapts that behavior to VulnHunter. It does **not** copy another product's branding, capabilities, provider UI, account model, visual theme, private reasoning display or unsupported actions.

## 2. Core product statement

> **VulnHunter is a security operating environment controlled through conversation.**

The conversation is the command surface.

The live task timeline is the execution surface.

The contextual workspace viewer is the inspection surface.

Workers/tools are the execution layer.

Persisted evidence is the truth layer.

Findings, remediation, retest and reports are outputs of the same durable workspace.

The browser never becomes security authority merely because it renders these surfaces.

## 3. Non-negotiable user experience

### 3.1 Clean empty workspace

A brand-new conversation must not fabricate a prior assistant turn.

The initial state should be visually clean and user-led. It may contain UI-only quick-start actions such as:

```text
Analyse APK
Scan authorised website
Source Hunt
Investigate finding
```

These are interface actions, not stored assistant messages.

The first persisted chat message in a new workspace should normally be the user's first actual message or attachment action.

### 3.2 Work becomes visible immediately

After a supported request is accepted, the interface should transition quickly from request submission to a durable task/session projection.

The user should not stare at one generic spinner while the server performs many invisible steps.

As persisted transitions occur, the conversation should render concise activity such as:

```text
✓ APK archive validated
✓ SHA-256 recorded
◌ Mapping DEX files
  JADX
○ Inspect native libraries
○ Trace cryptographic routines
```

Only real persisted or verifiably derived state may appear.

### 3.3 The conversation remains usable while work runs

A running task must not freeze the whole workspace.

The composer remains available unless a real backend constraint requires otherwise.

A user may submit a follow-up while work is running, for example:

```text
Focus more on libhsMediaLibrary.so.
```

If the follow-up can be applied immediately, the backend may bind it to the active task.

If it cannot run yet but the workflow supports deferred instructions, it must be persisted and shown as `Queued`.

If queuing is unsupported for the current task type, the UI must state that truthfully rather than pretending the instruction has been queued.

### 3.4 The execution timeline is primary

The base conversation should show the most useful execution sequence directly.

Do not make the user open a giant run card merely to learn what VulnHunter is doing.

A compact task timeline may contain:

- stage completion;
- current running stage;
- blocked/approval-required stage;
- tool start/completion/failure receipts;
- artifact creation;
- evidence availability;
- finding availability;
- recovery/cancellation/completion state.

Large technical detail remains progressively disclosed.

### 3.5 Stop/cancel is persistent only when real

When the backend supports safe cancellation for a running task, the active task surface should expose a clear stop/cancel control.

It must map to the existing governed cancellation contract.

Do not add a generic Pause control. Pause remains forbidden until an explicit pause/resume backend contract exists.

### 3.6 Context opens without losing the conversation

A user should be able to inspect the thing VulnHunter is working on without navigating away from the task mentally.

Desktop: open a contextual right-side viewer/drawer.

Mobile: open a full-width sheet or deep view.

Closing the viewer returns the user to the same conversation and the same persisted task position.

## 4. Canonical workspace anatomy

### 4.1 Desktop

```text
┌──────────────────┬──────────────────────────────────────────┬────────────────────┐
│ task/chat sidebar│ conversation + live task execution       │ context viewer     │
│                  │                                          │ closed by default  │
│ + New assessment │ user request                             │                    │
│ current task     │ VulnHunter response                      │ APK explorer       │
│ recent tasks     │ ✓ stage                                  │ source file        │
│ history          │ ◌ active stage                           │ tool receipt       │
│ Manage / Settings│   tool activity                          │ evidence           │
│                  │ ○ pending stage                          │ finding            │
│                  │                                          │ report preview     │
│                  │ [persistent composer]                    │                    │
└──────────────────┴──────────────────────────────────────────┴────────────────────┘
```

The context viewer is closed by default.

The main conversation owns the user's attention.

### 4.2 Mobile

```text
☰  current task / title                              ⋯

Running · 03:42

✓ APK archive validated
✓ SHA-256 recorded
◌ Mapping native libraries
  readelf
○ Tracing playback functions

VulnHunter
I found several media-library entry points…

[readelf ✓] [JADX ✓] [Evidence 3]

+  Ask VulnHunter…                                   ➜
```

A context item opens full-width and returns to the same chat when closed.

No essential horizontal scrolling is permitted.

## 5. Durable live-agent session model

The live experience must be backed by a durable session/task model rather than browser-only state.

Each active conversation/task needs enough persisted identity to reconstruct:

- workspace/thread ID;
- task/run/job ID;
- owner/user scope;
- task type;
- target/repository/artifact identity;
- authorization reference when applicable;
- plan/action identity when applicable;
- current lifecycle state;
- ordered activity/event cursor;
- tool receipts;
- artifact/evidence references;
- findings;
- approvals/confirmations/review requirements;
- follow-up instruction state;
- cancellation/recovery state;
- timestamps used for trustworthy elapsed duration;
- terminal result/report references.

The browser may cache rendering state for performance, but authoritative reconstruction comes from persisted backend state.

## 6. Event-driven conversation contract

### 6.1 Why events are required

The current experience must evolve from request/response plus periodic status refresh into a live event projection.

The user should see meaningful changes close to when they are persisted.

Existing SSE/activity infrastructure should be reused and consolidated rather than creating a second incompatible live-state system.

### 6.2 Event properties

Every user-visible operational event should have an immutable or replay-safe identity sufficient for deduplication.

Recommended fields:

```text
event_id / sequence
event_type
workspace_id
run_id / task_id / job_id
timestamp
state
summary
object_type
object_id
parent_id (optional)
tool_name (optional)
tool_state (optional)
artifact/evidence reference (optional)
terminal (boolean where applicable)
```

Only safe/redacted summaries are sent to the conversation surface.

### 6.3 Canonical event categories

The exact storage model may reuse existing task-graph/activity records, but the UI should be able to project categories equivalent to:

```text
workspace.restored
request.accepted
request.interpreted
authorization.checking
authorization.verified
authorization.required
plan.preparing
plan.ready
confirmation.required
approval.required
task.queued
task.running
stage.started
stage.completed
stage.blocked
stage.failed
tool.started
tool.completed
tool.failed
artifact.created
evidence.created
finding.created
verification.started
verification.completed
followup.accepted
followup.queued
followup.applied
task.recovering
task.cancelled
task.failed
task.completed
report.ready
assistant.response.started
assistant.response.delta
assistant.response.completed
```

Not every workflow needs every category.

A category may be a projection over existing persisted state rather than a new database table.

### 6.4 Ordering and replay

The client must support:

- ordered sequence/cursor processing;
- duplicate-event suppression;
- reconnect from the last confirmed cursor;
- state resynchronization when a cursor is stale or missing;
- terminal-state stability;
- no task restart merely because the browser reconnects.

### 6.5 SSE first, REST fallback

For the browser, server-sent events are the preferred live-update transport because the repository already contains EventSource infrastructure.

REST status remains useful for:

- initial hydration;
- explicit resynchronization;
- fallback when EventSource is unavailable;
- specialist detail fetches.

The frontend must not keep two independent state machines where polling and SSE can contradict each other.

## 7. Real streaming versus simulated animation

A completed answer must not be split into words and animated in a way that implies server streaming.

Two truthful modes are allowed:

1. **real text streaming** — the server emits user-facing answer deltas;
2. **atomic answer** — the complete answer is rendered when received.

If real text streaming is not yet implemented, use the atomic answer mode while operational task events stream independently.

Never expose hidden chain-of-thought or private reasoning tokens.

## 8. User-facing activity language

Activity text should explain real work at a useful level without dumping internal noise.

Good:

```text
Checking authorization…
Validating APK integrity…
Mapping DEX files…
Inspecting native libraries…
Running reviewed passive checks…
Normalizing evidence…
Waiting for independent approval…
Restoring persisted task state…
```

Avoid:

- model private reasoning;
- raw prompts;
- every queue/internal node name;
- fabricated deliberation;
- fake percentages;
- timer animation that is not tied to a real start time.

## 9. Task row contract

Every live task row should use one shared state language:

```text
✓ completed
◌ running
○ pending
Ⅱ blocked / human action required
↻ recovering
! failed
× cancelled
```

A row may show:

- short action label;
- real tool name/receipt beneath it;
- trustworthy duration;
- compact disclosure for details.

Rows update in place when the same underlying task changes state.

Do not repeatedly append duplicate status rows for the same stage.

## 10. Tool activity contract

Tools must feel like part of the execution, not hidden implementation detail and not decorative badges.

Examples:

```text
◌ Inspecting native libraries
  readelf

✓ Decompiling application code
  JADX · receipt recorded

! Native symbol extraction
  tool exited safely · details available
```

Tool receipts may expose, where persisted:

- tool name/version;
- policy/profile;
- start/end time;
- duration;
- worker identity;
- exit state;
- receipt/digest;
- produced artifacts/evidence count.

A tool failure does not automatically equal a security finding.

## 11. Contextual workspace viewer

### 11.1 Purpose

The viewer lets the user inspect the current task context without replacing the conversation.

### 11.2 Supported viewer types

Only repository-backed data should be exposed. Candidate viewer modes include:

- **APK explorer** — manifest, DEX list, native-library list, package metadata already extracted;
- **source viewer** — repository file and line evidence;
- **tool receipt/output** — bounded redacted tool result/provenance;
- **evidence viewer** — proof/evidence metadata and safe payload excerpts;
- **finding viewer** — full finding detail;
- **report preview** — persisted generated report;
- **browser/request evidence** — bounded request/response evidence when already supported;
- **diff/remediation preview** — only where repository-backed and governed.

Do not add an arbitrary shell/terminal console merely to imitate another agent product. A tool-output view is not unrestricted command execution.

### 11.3 Context-link behavior

Inline task items, tool chips, artifact rows, evidence cards and finding cards may open the viewer.

The viewer must preserve:

- workspace/task identity;
- selected object identity;
- scroll/focus restoration where practical;
- permissions;
- redaction;
- mobile Back behavior.

## 12. Report and artifact preview contract

A persisted result should appear contextually:

```text
✓ Security report created

[Open report]
```

Opening the report should not create a new unrelated workflow.

The preview can be a drawer/sheet/deep view of the same persisted report object.

The same rule applies to evidence, source files and generated remediation material.

## 13. Follow-up instruction contract

A follow-up submitted during running work has an explicit lifecycle.

Recommended states:

```text
accepted
queued
applied
completed
rejected
cancelled
```

The conversation may show:

```text
You
Focus more on libhsMediaLibrary.so.

Queued
Will apply after native-library inventory completes.
```

The explanation must come from the backend scheduling contract, not browser guesswork.

Queued instructions must be owner/workspace/task bound.

A refresh must not duplicate them.

## 14. Website-assessment reference flow

```text
User requests assessment
→ target parsed
→ authorization checked
→ exact scope/port/profile resolved
→ immutable passive plan prepared
→ confirmation/approval shown inline
→ user confirms exact plan
→ worker job queued
→ live task/tool events appear
→ evidence normalized
→ findings/verification appear contextually
→ report/remediation/retest become available from same conversation
```

Example timeline:

```text
✓ Authorization verified
✓ Exact passive plan prepared
Ⅱ Confirmation required
○ Queue scanner
○ Run Nuclei
○ Collect evidence
○ Verify observations
```

After confirmation:

```text
✓ Authorization verified
✓ Exact passive plan prepared
✓ Plan confirmed
✓ Worker job queued
◌ Running Nuclei
  Nuclei
○ Collect evidence
○ Verify observations
```

## 15. APK-analysis reference flow

```text
APK attached
→ resumable upload
→ archive validation
→ SHA-256/integrity record
→ artifact identity bound to workspace
→ static/native plan created
→ worker queued
→ tool-by-tool receipts stream into conversation
→ extracted artifacts/evidence become inspectable
→ findings/verification appear
→ gated dynamic follow-up remains separately governed
```

Example timeline:

```text
✓ Upload complete
✓ APK archive validated
✓ SHA-256 recorded
✓ Manifest inspected
◌ Decompiling DEX files
  JADX
○ Mapping native libraries
○ Searching cryptographic primitives
○ Correlating evidence
○ Verification
```

A failure of one safe static tool should be represented independently when the backend continues later tools.

Uploading an APK never implies dynamic execution.

## 16. Source Hunt reference flow

```text
User requests repository review
→ repository/root/revision resolved
→ snapshot identity created
→ permitted paths resolved
→ remote-processing approval when required
→ deterministic entry-point/sink mapping
→ AI reconnaissance/falsification/capability filtering
→ evidence/source references appear in conversation
→ remediation proposal appears contextually
→ read-only verification and human review remain governed
```

Source files/line references open in the contextual source viewer.

A giant source-analysis dashboard is not the primary experience.

## 17. Provider behavior

The existing silent advisory provider chain may use Groq, then Gemini, then local Ollama fallback according to repository policy.

Normal conversation must not expose provider failover as an error sequence.

The user should see the task continue normally when a fallback succeeds.

Provider/model detail belongs in diagnostics/audit/settings where appropriate, not in every ordinary assistant response.

Provider failover never changes authorization, scope, scanner execution, verification, severity or publication authority.

## 18. Empty-state quick starts

Quick starts may populate the composer or begin an attachment chooser, but they must not create fake assistant history.

Recommended semantics:

- `Analyse APK` → open APK attachment flow;
- `Scan authorised website` → focus composer with a scan-oriented hint;
- `Source Hunt` → focus composer or open repository selection only where supported;
- `Investigate finding` → open/select a persisted finding or focus the composer.

Do not pre-populate a fake conversation transcript.

## 19. Busy-state separation

The frontend must separate at least these concepts:

- **message request in flight** — one network request is being submitted;
- **task execution running** — backend work continues independently;
- **assistant text streaming** — optional response stream;
- **workspace reconnecting** — EventSource/status restoration;
- **human decision blocked** — approval/confirmation/input required.

A single `busy` boolean must not disable the entire workspace for all of these states.

## 20. Reconnect and restoration

On reload, reconnect or device switch:

1. load the selected workspace/thread;
2. hydrate persisted messages;
3. resolve the authoritative active task/job;
4. fetch current task projection and last event cursor;
5. render the latest durable timeline;
6. reconnect to live activity from the known cursor;
7. restore queued follow-ups;
8. restore any approval/recovery/terminal state;
9. do not replay a scan or re-submit a user message.

The UI may briefly show:

```text
Restoring workspace…
```

but must transition to the actual persisted state.

## 21. Cancellation behavior

Cancellation is a governed task action, not a client-side visual shortcut.

When supported:

```text
user requests cancel
→ backend validates ownership/state/cancellability
→ cancellation request persisted
→ worker/task graph honors safe checkpoints
→ cancellation event appears
→ completed stages/evidence remain visible
→ no further scanner work starts
```

The UI must distinguish `cancelling` when such a state exists from terminal `cancelled`.

## 22. Recovery behavior

A worker disconnect/interruption should not automatically look like task failure if durable recovery is supported.

Example:

```text
↻ Worker interrupted — recovering task
  Persisted state preserved
```

After recovery:

```text
✓ Worker connection restored
◌ Continuing evidence normalization
```

If recovery fails, preserve completed stages and valid evidence and show terminal failure truthfully.

## 23. Security and authority boundaries

The live-agent UX must never turn the AI or browser into authority.

The UI must not:

- convert arbitrary chat text directly into shell commands;
- grant target authorization;
- expand scope;
- grant approval/review/adjudication authority;
- mark a finding verified from a model statement;
- set final severity from model output;
- merge/release/publish without the existing governed contract;
- fabricate tool success;
- expose secrets or prohibited raw data in live events;
- execute uploaded APKs automatically;
- expose hidden chain-of-thought.

All existing repository safety rules remain binding.

## 24. Visual behavior

This document does not replace the locked visual contract.

The live-agent experience must still use:

- warm cream/off-white dotted working canvas;
- compact dark sidebar;
- dusty-pink active accent;
- near-black technical text/borders;
- square/nearly-square geometry;
- hard zero-blur shadows;
- readable body text;
- restrained motion;
- no dashboard KPI wall;
- no neon/cyberpunk/glassmorphism redesign.

## 25. Accessibility behavior

Live events must remain understandable without relying only on animation or color.

Requirements:

- textual state labels;
- semantic status announcements for meaningful transitions;
- no announcement spam for every low-level receipt;
- keyboard access to timeline/context actions;
- focus preservation when opening/closing drawers/sheets;
- `prefers-reduced-motion` support;
- critical mobile actions at least approximately 44px;
- no hidden reasoning in accessibility text.

## 26. Performance behavior

The live timeline must remain usable during long tasks.

Client requirements:

- deduplicate events by stable identity/sequence;
- do not re-render the entire conversation for every event;
- bound default visible low-level activity and progressively disclose older detail;
- keep the composer responsive;
- avoid timer loops that imply operational progress;
- close live connections at terminal states;
- back off/reconnect safely on transport errors;
- fetch full detail only when the user opens it.

## 27. Product acceptance summary

The live-agent workspace is product-complete only when a user can:

1. open a genuinely clean new workspace;
2. submit a supported task;
3. see a durable task session appear quickly;
4. see truthful live stages/tool activity as work happens;
5. continue typing while work runs;
6. queue supported follow-ups;
7. open contextual evidence/source/APK/report views without losing the conversation;
8. cancel safely when supported;
9. refresh/reconnect without restarting work;
10. see recovery/failure truthfully;
11. receive findings/evidence/report outputs in the same workspace;
12. use the critical flow on phone and desktop;
13. experience silent AI-provider failover where configured;
14. never see fake progress or private reasoning.

Detailed scenario gates are defined in `docs/product/LIVE_AGENT_WORKSPACE_ACCEPTANCE.md`.

## 28. Explicit exclusions

This specification does **not** authorize or require:

- arbitrary public Internet scanning;
- arbitrary shell access from chat;
- generic operator Pause;
- hidden reasoning display;
- dynamic APK execution without its existing gated environment;
- unsupported provider/model selectors;
- fictional browser automation;
- unsupported file editing;
- automatic merge/release/publication;
- fake percentage progress;
- a new visual brand copied from the reference application.

## 29. Implementation rule

Implementation must follow `docs/engineering/LIVE_AGENT_WORKSPACE_IMPLEMENTATION_PLAN.md` in dependency-aligned batches and must satisfy `docs/product/LIVE_AGENT_WORKSPACE_ACCEPTANCE.md` plus all existing repository UI/security acceptance criteria.

Do not attempt a cosmetic clone first and wire truth later.

The correct order is:

```text
durable state/event contract
→ reconnect/replay truth
→ conversation runtime
→ live task/tool projection
→ contextual viewer
→ queued follow-ups
→ workflow-specific integration
→ visual polish and browser evidence
```
