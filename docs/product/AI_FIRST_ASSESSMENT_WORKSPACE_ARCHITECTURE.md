# VulnHunter AI-First Assessment Workspace Architecture

**Status:** Binding product-experience and implementation contract  
**Owner:** Emmanuel Okunlola  
**Repository:** `emmy16-glitch/vulnhunter-ai-work`  
**Created:** 2026-08-02  
**Audit basis:** Direct phone and desktop-site review of the authenticated Codespaces product, including login, chat, APK upload, assessment inspector, navigation, Source Hunt, authorisations, history, campaigns, findings, reports, upload progress, failed worker state, and responsive behaviour.

---

## 0. Purpose and authority

This document defines how VulnHunter must behave and be arranged as an AI-first security assessment product. It converts the product review into an implementation-ready architecture rather than a visual mood board or a collection of optional design suggestions.

The current backend security, authorisation, evidence, verification, review, publication, and worker boundaries remain authoritative. This document does not weaken those controls. It defines how those controls must be presented through one coherent task experience.

The permanent product rule is:

> VulnHunter is not a governance dashboard with a chat box attached. VulnHunter is one conversational assessment workspace whose chat, task activity, evidence, findings, approvals, reports, and specialist views all project the same authoritative backend state.

When this document conflicts with an implementation detail, the implementation must be changed unless the detail is required by `AGENTS.md` or another stronger security boundary. When a security boundary cannot be simplified safely, the product must explain it progressively without exposing unnecessary internal terminology by default.

This document is mandatory reading together with:

1. `AGENTS.md`;
2. `docs/intelligence/VULNHUNTER_MASTER_ARCHITECTURE.md`;
3. `docs/product/CHAT_FIRST_WORKSPACE.md`;
4. `docs/intelligence/CURRENT_STATE.md`;
5. `docs/intelligence/KNOWN_FAILURES.md`.

A feature is not complete merely because a page, model, worker, card, or endpoint exists. It is complete only when the user can start, understand, continue, recover, and inspect the operation through one state-consistent workspace on desktop and phone.

---

# 1. Product diagnosis

## 1.1 What the current product already does well

The reviewed product has several valuable foundations that must be retained:

- secure local sign-in with a clear private-lab identity;
- a consistent dark visual language;
- an authenticated conversation surface;
- resumable APK upload that can continue while the user navigates;
- persisted backend operations rather than fabricated browser-only progress;
- explicit authorisation, approval, evidence, verification, and release boundaries;
- a desktop inspector concept for detailed assessment state;
- a mobile navigation shell;
- separate worker processes and persisted queues;
- deterministic fallback when the configured model provider is unavailable;
- support for website, APK, and source-repository workflows;
- specialist views for authorisations, assessment history, findings, campaigns, reports, and Source Hunt.

These foundations are not the problem. The problem is that they are presented as competing products rather than one operation.

## 1.2 Primary product failure

The current interface is dashboard-first rather than task-first. It behaves like several systems placed beside each other:

- a chat application;
- an administrative console;
- a governance portal;
- an assessment inspector;
- a reports portal;
- a worker/readiness console;
- a mobile bottom-navigation application.

The user must determine which surface contains the real state. Modern AI workspaces reverse this relationship: the current conversation or task is central, while files, activity, approvals, evidence, logs, results, and specialist tools support it.

The intended experience is:

```text
Ask VulnHunter to do something
        ↓
VulnHunter identifies the exact object and required authority
        ↓
One assessment is created
        ↓
One live task card shows the real operation
        ↓
Approvals and failures appear exactly when relevant
        ↓
Findings, evidence and reports remain attached to that assessment
        ↓
The user can continue naturally in the same conversation
```

The current experience too often becomes:

```text
Chat with an assistant
→ upload a file
→ receive repeated prose
→ inspect a separate panel
→ inspect another history page
→ inspect a global findings page
→ inspect a reports page
→ try to determine whether the worker ran
```

## 1.3 Reference interaction patterns

VulnHunter must adopt proven interaction patterns without copying another product's branding or weakening its security model.

### Conversation-first shell

The current conversation or assessment remains the main workspace. Navigation contains recent workspaces, creation, and supporting areas. It does not expose every backend subsystem as an equal primary destination.

### Contextual result panel

Large or structured outputs open in a contextual side panel on desktop. The panel belongs to the selected assessment and does not create a second workflow. On mobile it becomes a full-screen or bottom-sheet view rather than a permanently compressed desktop column.

### Visible agent execution

Long-running work has a live, persisted execution view that answers:

- What is happening now?
- What has completed?
- What comes next?
- Which tool or worker is active?
- Is user action required?
- What failed?
- What can be retried safely?
- What evidence has already been preserved?

### Progressive disclosure

The default interface uses ordinary task language. Provider identifiers, model names, queue envelopes, canonical receipts, hashes, governance internals, and worker diagnostics remain available under details, activity, evidence, or settings.

### One source of truth

Chat, inspector, history, findings, graph, evidence, campaigns, and reports do not maintain competing interpretations of an assessment. They render the same assessment ID, lifecycle, task graph, evidence references, and terminal state.

---

# 2. Observed failures that must be corrected

## 2.1 Contradictory assessment state

During the reviewed `Digi Volt.apk` workflow, the interface displayed combinations of the following:

- upload completed;
- artifact verified;
- static APK analysis queued with ten tools;
- analysis started;
- APK inspection failed because the worker did not complete;
- assessment inspector reported `No active assessment`;
- graph displayed `Digi Volt.apk` as a verified artifact;
- findings remained zero;
- assessment history reported zero runs;
- global campaigns reported zero;
- reports displayed a separate pilot example unrelated to the current APK.

This is a critical product defect. It creates uncertainty about whether the system lost work, fabricated state, or attached the work to another record.

### Required correction

As soon as final artifact validation succeeds, the backend must create or bind one durable assessment record. Every subsequent message, task, receipt, tool result, evidence item, finding, graph node, failure, retry, and report must carry the same assessment identity.

The product must be able to render a single authoritative summary such as:

```text
Digi Volt.apk
Assessment VH-2026-0042

Upload                 Complete
Artifact validation    Complete
Planning               Complete
Static analysis        Failed
Verification           Not started
Report                  Unavailable
```

No page may show `No active assessment` while displaying an artifact or operation belonging to that assessment.

## 2.2 Chat is insufficiently state-aware

The assistant repeatedly requested the APK or explained that it could perform passive analysis even while the user was already uploading or had completed the upload.

### Required correction

The response generator must use the authoritative workspace projection before producing prose. It must not repeat a completed prerequisite. The response should change by lifecycle stage.

Before upload:

```text
Attach the APK and I will validate it before creating an assessment.
```

During upload:

```text
Digi Volt.apk is 47% uploaded. You can continue chatting while it finishes.
```

After validation:

```text
The APK is valid. I created assessment VH-2026-0042 and prepared the static-analysis plan.
```

After failure:

```text
Static analysis stopped during JADX extraction. The uploaded artifact, hash and manifest evidence were preserved.
```

The model must not be responsible for guessing these statements. The backend projection supplies the exact state and allowed next actions.

## 2.3 Generic, unactionable failure reporting

The reviewed message stated that the APK inspection failed because the governed worker did not complete. It did not identify the failed stage, worker, reason, preserved evidence, retry boundary, or next action.

### Required correction

Every terminal or blocked task state must provide:

- the exact stage that failed;
- a user-readable reason category;
- a stable error/reference ID;
- completed stages;
- preserved artifact/evidence state;
- whether retry is safe;
- whether retry restarts one node or the whole graph;
- whether user action or operator configuration is required;
- a link to redacted technical details.

Example:

```text
Static analysis stopped

JADX exited before producing the expected source directory.
Completed: upload, validation and manifest extraction.
Preserved: APK, SHA-256, package metadata and manifest evidence.

[Retry JADX] [View activity] [View error details]
```

The product must never expose a retry button if the backend cannot safely and idempotently perform that retry.

## 2.4 No coherent agent-working experience

Cards and status labels exist, but they do not form one credible execution timeline. The user cannot easily see which tool is active, which steps are complete, or why the system is waiting.

### Required correction

Every long-running assessment needs one persisted task card. The card must update in place from authoritative events rather than adding repetitive prose messages.

The user-facing stages should be understandable:

```text
Uploading
Validating artifact
Preparing analysis
Waiting for confirmation
Queued
Extracting metadata
Decompiling
Running static checks
Inspecting native libraries
Correlating evidence
Verifying candidates
Preparing report
Complete
Blocked
Failed safely
Cancelled
```

Technical task-graph nodes, worker lease IDs, spool envelopes, command versions, and receipt hashes belong under an expandable `Technical activity` view.

## 2.5 Duplicate navigation and competing views

The reviewed workspace exposed overlapping navigation through:

- hamburger sidebar;
- top actions such as Source Hunt, Search, Export, History and New workspace;
- inspector tabs such as Overview, Findings, Evidence and Graph;
- bottom tabs such as Chat, Analysis, Findings and Graph;
- standalone global pages for Findings, Reports, Campaigns and Assessment History.

### Required correction

Each concept must have one primary location and at most one contextual shortcut.

The canonical destinations are:

- **Chat** — conversation and active task card;
- **Activity** — task stages, approvals, workers, retries and logs;
- **Findings** — findings for the selected assessment;
- **Evidence** — evidence for the selected assessment;
- **Report** — report/export readiness for the selected assessment;
- **More** — global or specialist areas such as authorisations, all assessments, campaigns, settings and provider readiness.

`Graph` is not a permanent top-level mobile destination. It is an optional assessment view inside Evidence or Inspector when real graph data exists.

Global Findings and Reports pages may remain for cross-assessment searching, but the primary workflow always opens them already filtered to the current assessment. They must not appear to own a separate state machine.

## 2.6 Broken responsive behaviour

The screenshots showed two incompatible mobile modes. Some views adapted to a mobile layout. Others compressed a desktop conversation and inspector into a very narrow screen, producing tiny text, clipped controls, horizontal overflow and unreadable tables.

### Required correction

There must be one deliberate responsive system, not a desktop layout squeezed by viewport width.

On mobile:

- the inspector is closed by default;
- the inspector opens as a full-screen sheet, route, or bottom sheet;
- global tables become stacked cards;
- no primary control is horizontally clipped;
- no page requires horizontal scrolling for normal use;
- the composer remains usable with the keyboard open;
- safe-area insets are respected;
- the active task remains visible without covering the latest message;
- text does not shrink below the product type scale;
- sticky elements do not overlap each other;
- desktop-site simulation remains usable and is separately tested.

## 2.7 Overloaded composer

The reviewed composer exposed attachment, text input, reasoning mode, send, provider selection, provider status, prompt history, explanatory text, character count and bottom navigation at the same time.

### Required correction

The primary composer contains only:

```text
[Attach] [Ask VulnHunter about this assessment…] [Mode] [Send]
```

Secondary settings use progressive disclosure:

- model/provider selection under `Advanced` or settings;
- provider health under readiness/settings;
- character count only near the limit;
- prompt history through a prompt button or slash command;
- detailed reasoning controls under the mode menu;
- current task status in the task card, not under the composer.

When the keyboard opens, the message list, composer and latest-message affordance must remain stable and must not cover one another.

## 2.8 Infrastructure labels dominate user content

Labels such as provider name, model identifier, deterministic fallback, canonical worker state, signed receipts, and gated-worker warnings were displayed prominently.

### Required correction

The default message footer should communicate only meaningful user-facing provenance, for example:

```text
Answered using deterministic fallback
```

An expandable details section may show:

```text
Requested provider: Groq
Requested model: openai/gpt-oss-120b
Resolved mode: deterministic fallback
Reason: live provider verification unavailable
```

Provider failure must not make a valid deterministic answer look like a failed product operation.

## 2.9 Governance language is presented before task meaning

The interface uses correct but heavy phrases such as:

- live governed workspace;
- canonical worker state only;
- signed or persisted progress receipts;
- no browser control can activate a gated worker;
- exact snapshot;
- source-processing approval;
- deterministic artifact generated from stored plan and readiness report;
- rendering does not publish.

### Required correction

Use normal language first, then provide policy detail on demand.

Preferred default:

```text
Worker status
No analysis worker is assigned yet.
```

Expandable explanation:

```text
Why can the browser not start this worker?
The worker requires an approved policy and signed job. The browser can request the operation but cannot activate the worker directly.
```

Security terminology remains exact in evidence, audit and specialist views. It does not need to dominate ordinary task progress.

## 2.10 Empty pages are overbuilt

Several pages use multiple large metric cards to communicate that there are zero findings, campaigns or assessment runs.

### Required correction

Empty states should be compact, contextual and actionable.

Example:

```text
No findings yet

Findings will appear after this assessment produces verified evidence.
[Return to assessment]
```

Global pages may retain filters and search, but explanatory governance cards should be collapsed into `How this works` rather than occupying most of the screen.

## 2.11 Reports are disconnected from the active task

The reports page showed a pilot record unrelated to the current APK while the current assessment had no visible report state.

### Required correction

Report readiness belongs to the selected assessment. The report view must first identify the assessment and then show each format truthfully:

```text
Digi Volt.apk · VH-2026-0042
Static analysis failed

HTML          Unavailable — assessment incomplete
JSON          Available — partial machine-readable activity
SARIF         Unavailable — no verified findings
Evidence ZIP  Available — preserved evidence only
PDF           Unavailable — renderer not configured
```

Demo, pilot or seeded records must be visually labelled and separated from user work. Production navigation must never make seeded data appear to be the user's active report.

## 2.12 Inspector opens without meaningful context

The inspector displayed `No active assessment` while still showing progress-like decoration and an artifact in another tab.

### Required correction

The inspector remains closed or presents a compact selection state until an assessment is selected. It must display the selected assessment name and stable ID at the top.

Desktop inspector tabs are:

- Summary;
- Activity;
- Findings;
- Evidence;
- Report.

Graph appears inside Evidence only when real graph records exist. The inspector never owns a second copy of the chat navigation.

---

# 3. Target information architecture

## 3.1 Desktop shell

```text
┌────────────────┬──────────────────────────────────────┬─────────────────────────┐
│ Sidebar        │ Conversation / active assessment     │ Contextual inspector    │
│                │                                      │                         │
│ New assessment │ Assessment title and truthful state │ Summary                 │
│ Recent work    │                                      │ Activity                │
│ Pinned         │ Messages                             │ Findings                │
│                │ Structured task card                 │ Evidence                │
│ Authorisations │ Approval cards                       │ Report                  │
│ All assessments│ Result summaries                     │                         │
│ Campaigns      │                                      │ Opens only with context │
│ Reports        │ Composer                             │                         │
│ Settings       │                                      │                         │
└────────────────┴──────────────────────────────────────┴─────────────────────────┘
```

The inspector is resizable within reviewed limits. It may be closed. Closing it never loses state.

## 3.2 Mobile shell

```text
┌─────────────────────────────────┐
│ Assessment title        Status  │
├─────────────────────────────────┤
│                                 │
│ Conversation                    │
│                                 │
│ Active task card                │
│ Static analysis · 4/8           │
│ Running JADX extraction         │
│                                 │
├─────────────────────────────────┤
│ +  Ask about this assessment  ➤ │
├─────────────────────────────────┤
│ Chat  Activity  Findings  More  │
└─────────────────────────────────┘
```

`Evidence` and `Report` are accessible from Activity, Findings, More, or the result summary. They do not require six permanent bottom tabs.

## 3.3 Sidebar and global navigation

Primary sidebar groups:

### Work

- New assessment;
- Recent assessments;
- Pinned assessments;
- Source Hunt shortcut only when it opens or creates a conversation-backed source assessment.

### Governance

- Authorisations;
- Campaigns;
- Reviews/approvals when the account has relevant work.

### Assurance

- Cross-assessment findings;
- Reports and exports;
- Audit/readiness for authorised roles.

### System

- Tools and workers;
- Providers;
- Settings;
- Account.

The sidebar must not duplicate the selected assessment's Activity, Findings, Evidence, Graph and Report controls.

---

# 4. Canonical assessment identity and state model

## 4.1 Required identity linkage

Each active or historical assessment must expose a stable identity bundle:

```text
workspace_id
conversation_id
assessment_id
assessment_type
subject_id
subject_display_name
owner_id
authorisation_id or explicit not-required reason
plan_id and plan_digest
task_graph_id
current_lifecycle_state
current_user_stage
terminal_reason when terminal
created_at
updated_at
```

Uploaded artifacts additionally bind:

```text
artifact_id
original_filename
size_bytes
sha256
validation_state
storage_reference
```

Chat messages, upload rows, cards, activity events, evidence, findings, graph nodes, reports and exports must refer to this identity bundle. A browser component may not invent its own active-assessment flag.

## 4.2 Authoritative lifecycle

The backend lifecycle may remain technically detailed. The UI projection must map it to one user-readable state.

Recommended canonical lifecycle:

```text
DRAFT
INPUT_REQUIRED
UPLOADING
VALIDATING
READY_TO_PLAN
PLANNING
CONFIRMATION_REQUIRED
APPROVAL_REQUIRED
QUEUED
RUNNING
BLOCKED
PARTIALLY_COMPLETED
FAILED
CANCELLED
COMPLETED
REVIEW_REQUIRED
REMEDIATION_REQUIRED
RETESTING
REPORT_READY
RELEASED
ARCHIVED
```

Each assessment has exactly one current lifecycle state. Task nodes have their own states, but they cannot make the assessment simultaneously appear idle, running and absent.

## 4.3 User-stage projection

The interface maps backend state to a concise user stage:

| Backend condition | User-facing stage |
|---|---|
| upload in progress | Uploading artifact |
| validation running | Validating artifact |
| plan not created | Preparing analysis |
| owner confirmation required | Waiting for your confirmation |
| independent approval required | Waiting for approval |
| queued with no lease | Queued for analysis |
| worker lease active | Running analysis |
| dependency unavailable | Blocked |
| terminal worker failure | Failed safely |
| some nodes completed and others failed | Partially completed |
| evidence correlation complete | Analysing evidence |
| candidates require verification | Verification required |
| human review outstanding | Waiting for review |
| report formats available | Report ready |
| terminal success | Complete |

The same mapping is reused by chat, header, task card, inspector, history and notifications.

## 4.4 State invariants

The following are mandatory invariants:

1. An assessment displayed in chat must appear in assessment history.
2. An artifact displayed in an assessment graph must belong to that assessment.
3. A task cannot be `running` unless the assessment is at least `RUNNING`.
4. A failed task cannot leave the assessment displayed as `Idle` without a terminal explanation.
5. A report cannot be shown as available without a report/export record tied to the assessment.
6. A finding count is derived from persisted findings tied to the assessment.
7. A zero count must not erase preserved evidence or partial completion.
8. Retry creates a new attempt or node revision without erasing the prior failure receipt.
9. Browser refresh reconstructs state from stores, not local memory.
10. A model response cannot change lifecycle state.

---

# 5. Conversation behaviour contract

## 5.1 Message response composition

Every operational response is composed from:

1. resolved user intent;
2. selected workspace and assessment;
3. authoritative state projection;
4. policy result;
5. allowed next actions;
6. optional model-generated explanation constrained by the above.

The response must answer, in ordinary language:

- what VulnHunter understood;
- what object it applies to;
- what state it is in;
- what happened since the last message;
- what is happening now;
- what the user can do next.

## 5.2 No repeated prerequisite requests

Before requesting an upload, URL, repository, authorisation, confirmation or approval, the backend must verify that it is genuinely missing for the selected assessment.

The assistant must not ask for an APK while an upload for the selected assessment is active or complete. It may ask whether the user wants to replace the artifact only through an explicit replacement flow.

## 5.3 Concise default, expandable detail

Default response:

```text
Static analysis is running. Manifest extraction completed and JADX decompilation is active.
```

Expanded activity:

```text
Attempt: 2
Worker: codespaces-mobile-static-worker
Tool: jadx 1.x
Started: 13:04:22
Receipt: ...
```

The product must not force technical metadata into every message.

## 5.4 Contextual actions

Assistant and system cards show only actions currently allowed by backend policy. Examples:

- Confirm plan;
- Request approval;
- Cancel;
- Retry failed stage;
- View activity;
- View evidence;
- Open finding;
- Generate report;
- Configure worker;
- Return to assessment.

Actions are disabled or hidden when not valid. A disabled action must explain the unmet condition.

## 5.5 Deterministic fallback presentation

When the model provider is unavailable, the product remains useful. It should state:

```text
Answered using deterministic fallback
```

It must not imply that the assessment worker failed merely because the conversation provider is unavailable. Provider health and worker health are separate dimensions.

---

# 6. Agent execution and activity timeline

## 6.1 One task card per active operation

A long-running operation has one primary task card that updates in place. Conversation history may contain milestone events, but not a new repetitive paragraph for every poll.

Example:

```text
Digi Volt.apk
Static APK analysis
████████████░░░░  68%

✓ Uploaded                    66.7 MB
✓ APK validated               SHA-256 verified
✓ Manifest extracted
● Decompiling source          JADX
○ Dependency analysis
○ Native library analysis
○ Finding verification
○ Report generation

Running for 2m 14s
[View activity] [Cancel]
```

A percentage may be shown only if derived from declared weighted stages or measurable bytes. It must not be invented from elapsed time.

## 6.2 Activity event model

The UI activity timeline should consume persisted events such as:

```text
ASSESSMENT_CREATED
UPLOAD_STARTED
UPLOAD_PROGRESS
UPLOAD_COMPLETED
ARTIFACT_VALIDATED
PLAN_CREATED
CONFIRMATION_REQUESTED
CONFIRMATION_ACCEPTED
APPROVAL_REQUESTED
APPROVAL_GRANTED
JOB_QUEUED
WORKER_CLAIMED
STAGE_STARTED
TOOL_RECEIPT_RECORDED
STAGE_COMPLETED
STAGE_FAILED
RETRY_REQUESTED
RETRY_STARTED
EVIDENCE_RECORDED
CANDIDATE_CREATED
VERIFICATION_COMPLETED
REPORT_READY
ASSESSMENT_COMPLETED
ASSESSMENT_FAILED
ASSESSMENT_CANCELLED
```

Each event includes assessment ID, task/node ID when relevant, attempt, timestamp, safe summary and references to redacted technical detail.

## 6.3 Failure and recovery

A failure card must separate:

- product failure;
- worker unavailable;
- provider unavailable;
- policy denial;
- user action required;
- dependency configuration required;
- tool-level failure;
- partial success;
- cancellation.

The system must preserve completed evidence and show whether recovery reuses it.

## 6.4 Background continuity

Uploads and workers may continue while the user browses other pages, closes the inspector, refreshes, or changes device. Returning to the workspace reconstructs the latest task card and activity timeline.

Multiple visual upload indicators may exist only when they serve distinct purposes. The product must not simultaneously show a modal, toast, banner and footer card with conflicting percentages.

Recommended rule:

- one compact global background indicator while outside the workspace;
- one full task/upload card inside the workspace;
- one optional notification on completion or failure.

---

# 7. Canonical APK workflow

## 7.1 End-to-end sequence

```text
User attaches APK in chat
→ create resumable upload session
→ show byte-accurate progress
→ final archive/size/quota/hash validation
→ create immutable artifact
→ create or bind one assessment
→ show artifact identity
→ prepare declared static/native profile
→ request only required confirmation or approval
→ enqueue fixed worker job
→ run tool stages with receipts
→ preserve partial evidence on safe tool failure
→ correlate evidence
→ create candidates only from evidence
→ verify or abstain
→ show findings/evidence/report readiness
→ remain resumable from the same chat
```

## 7.2 Artifact card

After validation:

```text
Digi Volt.apk
66.7 MB · SHA-256 2a64…
Validated
Assessment VH-2026-0042
```

The card must not display unrelated technical counts such as DEX/native counts unless those values are persisted and explained.

## 7.3 Analysis plan

The plan card lists user-readable stages and exact profile boundaries. It explains that upload does not permit execution. Dynamic analysis remains separately gated.

## 7.4 Partial-tool failure

A static assessment may become `PARTIALLY_COMPLETED` if some independent tools complete safely. The product must show:

- completed tool receipts;
- failed tool and reason;
- which conclusions are unavailable;
- whether findings from completed tools remain eligible for verification;
- whether a targeted retry is allowed.

It must not collapse all partial work into a generic `inspection failed` message.

## 7.5 Dynamic analysis boundary

When no disposable emulator/runtime is configured, the product says:

```text
Dynamic analysis unavailable
A disposable authorised Android runtime has not been configured.
[View setup requirements]
```

It does not imply that static analysis failed.

---

# 8. Website and Source Hunt workflow alignment

## 8.1 Website assessment

Website assessment follows the same task experience:

```text
URL supplied in chat
→ exact target resolution
→ authorisation lookup or permitted request
→ immutable passive plan
→ confirmation/approval
→ queue
→ worker activity
→ evidence
→ candidates
→ verification
→ review
→ report
```

The user should not need to navigate to an authorisations page merely to understand why a scan is blocked. The chat card explains the missing authorisation and opens the exact specialist action.

## 8.2 Source Hunt

Source Hunt remains a governed source-processing operation, but it starts from or creates a conversation-backed assessment.

The existing detailed form may remain as a specialist approval surface. It must return the queued job and later results to the originating conversation.

The Source Hunt overview should not present itself as an unrelated second product. Its title, activity and reports must identify the associated workspace and assessment.

## 8.3 Shared execution language

Website, APK and Source Hunt reuse the same user-facing stages where possible:

- Preparing;
- Waiting for confirmation;
- Waiting for approval;
- Queued;
- Running;
- Analysing evidence;
- Verification required;
- Waiting for review;
- Report ready;
- Blocked;
- Failed safely;
- Cancelled;
- Complete.

Assessment-specific technical stages appear only within Activity.

---

# 9. Inspector contract

## 9.1 Desktop behaviour

The inspector opens only when:

- an assessment is selected and the user opens it;
- a structured result requires attention;
- the user chooses a finding, evidence item, report or activity event.

It is not forced open on an empty workspace.

## 9.2 Header

The inspector header contains:

```text
Digi Volt.apk
VH-2026-0042 · Failed safely
```

It never says `No active assessment` while rendering assessment-owned content.

## 9.3 Tabs

- **Summary** — current stage, subject, scope, authority and next action;
- **Activity** — stages, attempts, worker/tool receipts, errors and retries;
- **Findings** — assessment-scoped findings;
- **Evidence** — artifact, evidence items and optional graph;
- **Report** — assessment-scoped formats and release readiness.

## 9.4 Mobile behaviour

The inspector becomes a route, full-screen sheet or bottom sheet. It does not remain side-by-side with the conversation. Back returns to the same scroll position in chat.

---

# 10. Findings, evidence, graph and reports

## 10.1 Findings

The selected-assessment Findings view shows:

- candidate count;
- verified count;
- review-required count;
- rejected/abstained count where useful;
- cards tied to evidence and lifecycle state.

A global Findings page is a searchable index across assessments. Opening a finding returns to or opens its owning assessment context.

## 10.2 Evidence

Evidence is grouped by stage or finding and shows provenance. The default view uses understandable labels. Hashes, tool versions and exact paths are expandable.

## 10.3 Graph

Graph is displayed only when graph records exist. A lone artifact node with zero relationships is better represented as an artifact card, not a mostly empty graph tab.

Graph must never imply a verified attack path when only artifact inventory exists.

## 10.4 Reports

Report availability is derived from actual assessment data contracts. Every unavailable format states the exact unmet requirement.

Examples:

- `Requires verified finding data`;
- `Requires evidence data`;
- `Requires attack-path data`;
- `Renderer not configured`;
- `Assessment incomplete`;
- `Release approval required`.

Rendering and publication remain separate, but the default wording should be concise. Full release policy is available under details.

---

# 11. Visual and content system

## 11.1 Preserve the current visual foundation

Keep:

- dark theme;
- current blue, cyan, violet and green accents;
- high-contrast cards;
- rounded surfaces;
- private-lab identity;
- compact iconography.

The redesign is primarily about hierarchy, state and behaviour, not replacing the colour palette.

## 11.2 Type and density

- body text must remain readable on phone without browser zoom;
- metadata may be smaller but never the only carrier of critical state;
- desktop density may be higher than mobile;
- large empty cards should not dominate zero-data pages;
- important action buttons use one clear primary style per context;
- disabled controls explain why they are disabled.

## 11.3 Terminology hierarchy

Use ordinary language in the primary layer:

| Internal concept | Primary user wording |
|---|---|
| canonical worker state | Worker status |
| persisted progress receipts | Recorded activity |
| exact snapshot | Approved source snapshot |
| source-processing approval | Approval to analyse this source |
| gated worker | Worker requires setup or approval |
| deterministic fallback | Local fallback answer |
| plan digest | Plan ID, with digest in details |
| release gate | Release approval |

Internal names remain available for audit and technical inspection.

## 11.4 Status colour rules

Colour supplements text and icons; it never replaces them.

- blue/cyan — active/informational;
- green — completed/available/verified where exact;
- amber — waiting, partial, requires action or unavailable dependency;
- red — failed, denied or integrity problem;
- neutral — not started or not applicable.

A generic decorative gradient must not resemble progress when no active work exists.

---

# 12. Backend and API requirements

## 12.1 Unified workspace projection

Create or formalise one authenticated read model/API that returns:

```text
workspace
conversation
selected assessment
subject/artifact/target/repository
authority summary
plan summary
approval summary
current lifecycle
user-stage projection
task stages and active node
recent activity
evidence counts and references
finding counts and references
report readiness
allowed next actions
provider status separately from worker status
```

Chat, header, task card, inspector and mobile navigation consume this projection.

## 12.2 Command contract

Every UI action invokes a typed command such as:

```text
AttachArtifact
CreateAssessment
ConfirmPlan
RequestApproval
CancelAssessment
RetryTaskStage
OpenEvidence
GenerateReport
RequestActiveValidation
PrepareRemediation
RetestFinding
```

The browser does not mutate lifecycle state directly.

## 12.3 Idempotency

Upload finalisation, assessment creation, plan confirmation, queueing, cancellation and retry must be idempotent under:

- double tap;
- slow network;
- browser refresh;
- Android Back/forward;
- stale page resubmission;
- reconnect after request timeout.

The interface must show the existing result rather than creating duplicate assessments or worker jobs.

## 12.4 Event projection

Worker and backend events are projected into conversation events and task-card state exactly once or deduplicated by stable event identity.

## 12.5 Error taxonomy

The frontend receives typed errors rather than one generic failure string. Minimum categories:

```text
INPUT_INVALID
AUTHENTICATION_REQUIRED
REAUTHENTICATION_REQUIRED
NOT_AUTHORISED
APPROVAL_REQUIRED
POLICY_DENIED
DEPENDENCY_UNAVAILABLE
PROVIDER_UNAVAILABLE
WORKER_UNAVAILABLE
TOOL_FAILED
INTEGRITY_FAILED
CONFLICT
STALE_REVISION
CANCELLED
TIMEOUT
PARTIAL_RESULT
INTERNAL_FAILURE
```

Each category defines user wording, retry eligibility and technical-detail visibility.

---

# 13. Mobile acceptance requirements

Every affected slice must be tested in:

- narrow Android Chrome portrait;
- Android Chrome landscape where practical;
- Android desktop-site simulation;
- desktop Chromium;
- keyboard open and closed;
- long messages and long filenames;
- slow upload progression;
- interrupted/restarted upload;
- inspector/activity open and closed;
- Android Back navigation;
- browser refresh;
- session expiry and stale CSRF recovery;
- reduced motion;
- safe-area insets;
- 200% text/zoom where supported;
- no horizontal overflow.

Specific mobile assertions:

1. Header controls remain visible and tappable.
2. Composer is not covered by keyboard or bottom navigation.
3. Latest-message control does not cover text or actions.
4. One upload progress value is authoritative.
5. Inspector is not permanently side-by-side.
6. Tables become cards.
7. Top action rows wrap, scroll intentionally, or collapse into More; they are not clipped.
8. Bottom navigation contains no duplicate destinations.
9. Task status remains understandable without opening technical details.
10. All tap targets meet the product minimum size.

---

# 14. Required tests

## 14.1 State consistency

- validated APK creates exactly one assessment;
- chat, history and inspector show the same assessment ID;
- artifact graph/evidence references belong to that assessment;
- worker failure updates the assessment terminal state;
- partial completion preserves completed evidence;
- report readiness derives from the same assessment;
- zero findings does not imply zero evidence or no assessment;
- seeded pilot data is separated from user work.

## 14.2 Conversation awareness

- assistant does not request an already uploading artifact;
- assistant does not request an already validated artifact;
- status question returns persisted current stage;
- provider fallback is not confused with worker failure;
- generic model prose cannot override backend state;
- allowed actions reflect policy and lifecycle.

## 14.3 Execution timeline

- stage start/completion/failure events update one task card;
- reconnect reconstructs the same stages;
- duplicate events do not duplicate timeline rows;
- retry creates a new attempt and retains prior receipts;
- cancel remains truthful during race conditions;
- progress percentage is absent when not measurable.

## 14.4 Responsive behaviour

- no horizontal overflow on all primary pages;
- inspector becomes mobile sheet/route;
- composer remains usable with keyboard;
- action rows do not clip;
- global tables render as cards;
- back returns to the correct context;
- desktop and phone use the same authoritative data.

## 14.5 Accessibility and content

- status is not colour-only;
- focus order is logical;
- dialogs/sheets trap and restore focus;
- errors are announced;
- disabled actions provide reason;
- technical details are expandable and labelled;
- terminology remains consistent across chat, activity, findings and report.

---

# 15. Dependency-ordered implementation programme

The implementation loop must deliver this architecture through bounded, tested pull requests. It must not perform a one-pass cosmetic rewrite.

## Slice 1 — Unified assessment projection and invariant tests

Goal:

- establish one read model for workspace, assessment, task, evidence, findings and report state;
- add stable assessment identity to all relevant UI projections;
- add regression tests for the contradictory Digi Volt-style states;
- ensure validated APK creation is visible in history immediately.

No large visual redesign should precede this slice. Visual consistency without state consistency would only hide defects.

## Slice 2 — Canonical lifecycle and error taxonomy

Goal:

- define one assessment lifecycle and user-stage projection;
- map worker, provider, policy, tool and partial-result failures separately;
- replace generic failure strings with typed actionable states;
- preserve prior attempts and evidence.

## Slice 3 — Live task card and activity timeline

Goal:

- create one updating task card;
- project persisted activity events;
- expose stages, current tool, approvals, cancellation and safe retry;
- remove repetitive polling prose and decorative progress.

## Slice 4 — APK flow end-to-end repair

Goal:

- upload → validate → create assessment → plan → queue → worker → evidence → terminal state;
- remove repeated upload requests;
- connect partial-tool failures;
- ensure findings/evidence/report are assessment-scoped;
- add phone and reconnect acceptance.

## Slice 5 — Responsive shell and inspector

Goal:

- replace compressed desktop-on-phone behaviour;
- make inspector contextual on desktop and sheet/route on mobile;
- preserve scroll and context;
- convert affected tables to mobile cards;
- eliminate horizontal clipping and overflow.

## Slice 6 — Navigation consolidation

Goal:

- remove duplicate Findings/Graph/Analysis destinations;
- make Chat, Activity, Findings and More the mobile primary set;
- make desktop sidebar assessment-aware;
- ensure global pages are indexes, not competing workflows.

## Slice 7 — Composer simplification

Goal:

- reduce primary controls;
- move provider and advanced reasoning configuration behind disclosure;
- stabilise keyboard behaviour;
- keep upload and mode selection clear;
- remove persistent infrastructure noise.

## Slice 8 — Findings, evidence, graph and report alignment

Goal:

- scope all contextual views to the selected assessment;
- show graph only with meaningful records;
- show truthful report readiness by format;
- isolate demo records;
- connect result summaries back to chat.

## Slice 9 — Website flow alignment

Goal:

- apply the same task card, lifecycle, approval and failure experience to website assessment;
- keep exact authorisation and Nuclei boundaries;
- return specialist authorisation decisions to chat.

## Slice 10 — Source Hunt alignment

Goal:

- bind Source Hunt jobs and reports to a conversation-backed assessment;
- return approval, queue, progress, falsification, evidence and report state to chat;
- retain exact snapshot and data-retention controls under progressive disclosure.

## Slice 11 — Empty states and content-language pass

Goal:

- reduce oversized zero-data dashboards;
- standardise ordinary-language labels;
- retain audit terminology in details;
- improve actions and explanations without weakening policy.

## Slice 12 — Cross-workflow acceptance and cleanup

Goal:

- run complete desktop/phone/browser lifecycle acceptance;
- remove duplicate components and obsolete state sources;
- confirm one source of truth;
- update all authoritative documents;
- record remaining real limitations.

Each slice must include regression tests, responsive acceptance, documentation and exact evidence. The loop must not claim the programme complete while any supported workflow still has contradictory state, duplicate primary navigation, compressed mobile layout, or generic unactionable failures.

---

# 16. Pull-request quality gates

Every implementation pull request in this programme must:

1. begin from current `main` and re-check active work;
2. identify the state invariant or experience contract being changed;
3. include success, failure and regression tests;
4. preserve authorisation, evidence, verification, review and publication boundaries;
5. avoid fabricated progress or capabilities;
6. run the repository-required Python matrix, lint, formatting, compile and audit;
7. run relevant conversational browser lifecycle tests;
8. run responsive phone acceptance and desktop-site simulation;
9. verify no horizontal overflow on affected pages;
10. update this document and related current-state/failure notes when classification changes;
11. merge only when green, reviewed and free of unresolved threads.

---

# 17. Non-goals

This redesign must not:

- enable arbitrary public scanning;
- remove exact authorisation or approval requirements;
- allow the browser or model to activate a restricted worker directly;
- make model output authoritative;
- fabricate progress percentages, findings, evidence, metrics or reports;
- add dynamic APK execution without a disposable approved runtime;
- merge, publish, release or deploy automatically through chat;
- replace the dark visual identity solely for novelty;
- create duplicate onboarding, assessment, findings, report or source-hunt state machines;
- hide genuine security boundaries when the user needs to make a decision.

---

# 18. Definition of done

The AI-first assessment workspace programme is complete only when:

- every supported operation begins from or is bound to a conversation workspace;
- one assessment ID connects chat, activity, inspector, history, findings, evidence, graph and reports;
- state cannot contradict across surfaces;
- validated uploads create durable visible assessments;
- long-running work has a genuine persisted task timeline;
- failures identify the stage, reason, preserved work and safe next action;
- provider status is separate from worker and assessment status;
- desktop inspector is contextual and mobile inspector is not compressed side-by-side;
- navigation contains no competing duplicates;
- the composer is simple and keyboard-safe;
- empty pages are concise and useful;
- reports are tied to the selected assessment;
- demo records are separated from user records;
- mobile and desktop acceptance passes without horizontal overflow;
- browser refresh, disconnect, session recovery and duplicate submission preserve truth;
- all backend security and human-authority boundaries remain intact;
- documentation, tests and current-state classification agree with the implementation.

Until these conditions are met, VulnHunter may have strong backend foundations, but it must not be described as a finished AI-first product experience.
