# Live Execution Activity Contract

**Status:** BINDING PRODUCT + STATE CONTRACT  
**Applies to:** website assessment, Source Hunt, APK/mobile analysis, controlled validation, remediation/retest and other long-running governed work  
**Visual authority:** `docs/design/VULNHUNTER_UI_CONTRACT.md`  
**Workflow authority:** `docs/product/CHAT_FIRST_WORKSPACE.md`

---

## 1. Product rule

When VulnHunter says work is queued or running, the Assessment Workspace must show enough persisted operational state for the user to understand what the system is actually doing.

A static message such as:

```text
The backend is executing the scan. Check another page for status.
```

is not an acceptable primary running-task experience.

The conversation/task workspace must answer, from backend truth:

- what is happening now;
- what already completed;
- what comes next;
- which worker/tool is active when known;
- what object/file/target is currently being processed when safe to display;
- whether a human decision is required;
- what evidence/receipts/candidates exist;
- what failed or recovered;
- what state was preserved;
- what safe next action is available.

A deep Activity/Inspector view may expose more detail, but the user must not be forced to leave the conversation just to know whether the task is alive.

---

## 2. Not chain-of-thought

Live execution is **operational telemetry**, not model private reasoning.

Allowed examples:

```text
Checking authorization…
Worker claimed the signed assessment job.
Nuclei is evaluating reviewed passive templates.
JADX extraction completed.
Reviewing persisted source candidate #4.
Candidate #4 rejected by falsification.
Evidence normalization completed.
```

Forbidden:

- hidden chain-of-thought;
- private model reasoning tokens;
- fabricated deliberation;
- invented tool activity;
- browser-generated fake progress;
- “thinking” animations that continue after backend work stopped.

---

## 3. One persisted activity stream

Every long-running assessment has one authoritative append-only activity stream tied to the same assessment/workspace identity used by chat, task card, inspector, history, evidence, findings and report.

Each event should contain, where applicable:

```text
event_id / sequence
assessment_id
workspace_id
task_id
attempt_id
stage
kind
status
timestamp
safe_summary
worker_id
tool_id / tool_name / tool_version
subject_reference
duration or started_at/completed_at
receipt_reference
evidence_reference
candidate_reference
counts / bounded metrics
failure_reference
metadata (redacted, typed, bounded)
```

Event identity must be stable so reconnect/polling can deduplicate events.

The browser does not create authoritative activity rows. It renders persisted events and derived summaries from those events.

---

## 4. Canonical event families

Implementations may use different internal names, but the persisted product projection must support equivalent semantics.

### Lifecycle

- `task_created`
- `authorization_check_started`
- `authorization_verified`
- `authorization_required`
- `plan_preparation_started`
- `plan_prepared`
- `confirmation_required`
- `approval_required`
- `queued`
- `worker_claimed`
- `running`
- `recovering`
- `cancellation_requested`
- `cancelled`
- `completed`
- `failed`
- `blocked`

### Stage execution

- `stage_started`
- `stage_progress`
- `stage_completed`
- `stage_failed`
- `stage_skipped`

### Tool execution

- `tool_started`
- `tool_progress`
- `tool_completed`
- `tool_failed`
- `tool_receipt_recorded`

### Evidence/findings

- `evidence_recorded`
- `candidate_created`
- `candidate_rejected`
- `candidate_abstained`
- `candidate_verified`
- `verification_started`
- `verification_completed`
- `finding_persisted`
- `report_preparation_started`
- `report_ready`

### Source Hunt

- `snapshot_started`
- `snapshot_completed`
- `inventory_completed`
- `attack_surface_discovered`
- `source_path_traced`
- `hypothesis_created`
- `falsification_started`
- `hypothesis_rejected`
- `hypothesis_survived`
- `capability_filter_started`
- `capability_filter_completed`
- `remediation_proposed`

### APK/mobile

- `upload_started`
- `upload_progress`
- `upload_completed`
- `integrity_verification_started`
- `integrity_verified`
- `static_tool_started`
- `static_tool_completed`
- `static_tool_failed`
- `artifact_evidence_recorded`

---

## 5. Stage model

The UI should normally show understandable stage labels rather than internal queue/graph names.

Canonical high-level stages include:

```text
Understanding request
Checking authorization
Preparing plan
Waiting for confirmation
Waiting for approval
Queued for analysis
Collecting evidence
Analyzing evidence
Verification
Waiting for independent review
Preparing remediation
Retesting
Preparing report
Report ready
Recovering
Blocked
Cancelled
Failed safely
```

A task row can expand to show technical node/worker/tool detail.

---

## 6. Website assessment activity

A running website assessment should be able to project, when backed by real receipts:

```text
Website assessment — Running

✓ Authorization verified
✓ Passive plan confirmed
✓ Worker claimed signed job
◌ Passive assessment
  Nuclei · 17 reviewed templates
  Target: example.com:443
  Latest: template receipt persisted
○ Evidence normalization
○ Deterministic verification

Receipts   12
Candidates 2
Evidence   9
```

Do not invent a `47 / 183 templates` counter unless the worker actually emits and persists that measurement.

If the worker only knows template-set size and current tool state, show that truth instead.

---

## 7. Source Hunt activity

Source Hunt must not appear as a black box after queueing.

The persisted workspace should progressively show real milestones such as:

```text
Source Hunt — Running

✓ Snapshot created
  684 eligible Python files
✓ Deterministic inventory completed
✓ Entry points and sinks mapped
◌ Attack-path hunt
  Current surface: web/conversational_views.py
  Surfaces examined: 9
  Candidates: 4
○ Independent falsification
○ Capability filtering
○ Remediation proposal
```

When individual candidate transitions are persisted, the expandable activity view may show:

```text
Candidate #4 created
Falsification started
Candidate #4 rejected — authorization guard blocks attacker reachability
```

The ordinary chat layer should use concise language; full file/hash/line/provider-call detail belongs under Activity/Evidence/Source detail.

---

## 8. APK/mobile activity

A mobile assessment should distinguish upload, integrity and tool execution.

Example:

```text
APK assessment — Running

✓ Upload completed · 47.2 MB
✓ SHA-256 verified
◌ Static analysis
  [AAPT ✓] [JADX ◌] [Apktool ○]
○ Evidence normalization
○ Verification
```

A tool failure should not erase other truthful work:

```text
JADX failed safely
AAPT evidence preserved
Apktool continues where policy permits
```

Uploading an APK never implies it was executed dynamically.

---

## 9. Progress rules

Progress must be measurable and explainable.

Allowed progress sources:

- uploaded bytes / expected bytes;
- completed declared stages / total declared stages;
- processed items / known total where the worker truly emits those counts;
- exact task/event counts from persisted state.

Forbidden:

- elapsed-time-based fake percentages;
- browser timers presented as worker progress;
- arbitrary 30/60/90% lifecycle mapping;
- animation that implies a tool is active without a persisted event.

If no trustworthy percentage exists, show stage state and activity rather than a percentage.

---

## 10. Current activity summary

The task projection should provide a derived current-activity object, for example:

```json
{
  "stage": "passive_assessment",
  "status": "running",
  "safe_summary": "Nuclei is evaluating reviewed passive templates.",
  "tool": "nuclei",
  "worker": "scanner-worker-01",
  "started_at": "...",
  "latest_event_id": "..."
}
```

Fields absent from authoritative state remain absent/unknown; the browser does not fill them with guesses.

---

## 11. Tool chips

Tool chips are compact projections of actual receipts.

Examples:

```text
[Nuclei ◌]
[HTTP probe ✓ 1.2s]
[JADX !]
[Evidence normalizer ✓]
[Groq source hunt ◌]
```

Expanded tool detail may include, only when persisted:

- tool/provider identity;
- version/profile;
- worker identity;
- start/end/duration;
- receipt ID/digest;
- exit/result state;
- evidence count;
- bounded error reference.

A model/provider chip is provenance, not authority.

---

## 12. Failure and recovery

Failure UI must preserve the timeline.

Example:

```text
Source Hunt — Failed safely

✓ Snapshot created
✓ Inventory completed
! Groq attack-path stage failed

Preserved
- repository snapshot
- processing approval
- deterministic inventory
- 3 source-surface receipts

Reference: SH-FAIL-...
Retry: unavailable
```

If the backend supports safe scoped retry, show the exact retry scope and create a new attempt identity while retaining previous attempt receipts.

Recovery should update the same task:

```text
Worker interrupted — recovering
Persisted state preserved
Restoring execution context…
```

Do not append a second fake task card for the same operation.

---

## 13. Reconnect and polling

Refresh, navigation away, device switching and network interruption must reconstruct from persisted state.

Required behavior:

1. load selected assessment/workspace identity;
2. load current task projection;
3. load persisted activity after the browser's last known event/sequence when possible;
4. deduplicate by stable event ID/sequence;
5. render current state without replaying old animations as new work;
6. resume polling/stream subscription;
7. never restart the worker merely because the browser reconnected.

---

## 14. Polling / streaming transport

The product may use polling, SSE, WebSocket or another bounded mechanism.

The transport choice does not change authority. The backend event store remains authoritative.

Polling must not:

- create duplicate visible events;
- append repeated assistant messages for the same state;
- reset elapsed task state;
- fabricate activity between polls.

Streaming must not:

- expose model reasoning tokens;
- bypass redaction;
- become the only persistence mechanism.

---

## 15. Conversation integration

Long-running work should update a stable task group in the conversation rather than spamming a new assistant paragraph for every poll.

A good structure is:

```text
VulnHunter
The passive assessment is running.

✓ Authorization verified
✓ Plan confirmed
◌ Nuclei assessment
○ Verification

[Nuclei ◌] [Evidence 4]

Latest activity
HTTP probe receipt persisted · 19:42:11

[View activity]
```

The assistant may add meaningful milestone messages, but the task card/timeline remains the primary live state projection.

---

## 16. Mobile behavior

Phone is one column.

While running:

- current task state appears near the active conversation;
- task rows wrap naturally;
- tool chips wrap rather than force horizontal page scrolling;
- `View activity` opens a full-width sheet/deep view;
- the composer remains reachable;
- keyboard opening does not make current status inaccessible;
- touch targets remain approximately 44px minimum;
- long file paths/URLs/hashes wrap or truncate with a deliberate detail affordance.

No desktop monitoring dashboard may be squeezed onto the phone.

---

## 17. Accessibility

Meaningful state changes should be exposed to assistive technology without announcing every high-frequency heartbeat.

Prefer announcements for:

- queued;
- started;
- approval/authorization required;
- stage completed;
- failure/blocker;
- recovery;
- completion.

Rapid tool progress updates should be visually available without overwhelming screen-reader users.

Reduced motion must not reduce information.

---

## 18. Persistence and redaction

Activity records must be safe to persist.

Never place in activity events:

- passwords;
- API keys;
- bearer/session tokens;
- cookies;
- private keys;
- raw authorization evidence containing secrets;
- unredacted sensitive request/response material;
- hidden model reasoning.

Use bounded safe summaries plus references to separately governed evidence.

---

## 19. Acceptance tests

A supported long-running workflow is not complete until tests cover the applicable scenarios:

1. queued state appears in the same workspace;
2. worker claim updates the same task;
3. current stage changes from persisted events;
4. completed stages remain visible;
5. tool receipt appears only after a real receipt;
6. evidence/candidate counts come from persisted state;
7. reconnect reconstructs the exact timeline;
8. duplicate polls do not duplicate events;
9. old events do not reanimate as new after reconnect;
10. failure preserves completed stages and evidence references;
11. recovery updates the same task identity;
12. cancellation is reflected truthfully;
13. terminal completion remains stable after refresh;
14. zero findings does not erase activity/evidence;
15. mobile has no essential horizontal overflow;
16. composer remains usable while running;
17. unknown active tool is shown as unknown, not invented;
18. no hidden chain-of-thought/private reasoning appears anywhere.

For Source Hunt specifically, acceptance must fail if the job is `running` but the UI exposes only one generic timestamp and no meaningful persisted stage/activity data despite the worker having more information available.

---

## 20. Implementation status rule

Documentation, browser visuals and unit fixtures do not prove a live execution experience is implemented.

A workflow may be classified `LIVE EXECUTION IMPLEMENTED` only when:

- the worker/service persists meaningful stage/activity events;
- the authoritative assessment projection exposes them;
- the conversation/task UI renders them;
- reconnect reconstructs them;
- browser acceptance verifies them against backend state.

If any layer is missing, status must be `PARTIAL` and the gap must be recorded in `docs/intelligence/CURRENT_STATE.md` / `KNOWN_FAILURES.md`.
