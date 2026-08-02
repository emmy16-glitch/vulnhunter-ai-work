# VulnHunter AI-First Assessment Workspace Implementation Standard

**Status:** Binding implementation, migration, product-quality and acceptance standard  
**Owner:** Emmanuel Okunlola  
**Repository:** `emmy16-glitch/vulnhunter-ai-work`  
**Created:** 2026-08-02  
**Applies to:** authenticated web workspace, website assessments, APK assessments, Source Hunt, activity, inspector, findings, evidence, graph, reports, responsive behaviour and frontend architecture

---

## 0. Authority, scope and non-duplication rule

This document is the implementation companion to
`docs/product/AI_FIRST_ASSESSMENT_WORKSPACE_ARCHITECTURE.md`.

The architecture document owns the required product behaviour, information
architecture, lifecycle meaning and definition of done. This document owns the
code-level diagnosis, migration boundaries, implementation contracts, quality
gates, responsive thresholds, frontend cleanup rules and evidence required to
prove that behaviour has been implemented correctly.

Agents must not create another competing AI-first workspace specification. When
new product behaviour is required, update the architecture document. When the
behaviour is already defined but the implementation method, acceptance criteria
or migration sequence needs clarification, update this implementation standard.

Read and apply the following in this order:

1. `AGENTS.md`;
2. `docs/intelligence/VULNHUNTER_MASTER_ARCHITECTURE.md`;
3. `docs/product/CHAT_FIRST_WORKSPACE.md`;
4. `docs/product/AI_FIRST_ASSESSMENT_WORKSPACE_ARCHITECTURE.md`;
5. this implementation standard;
6. `docs/product/UI_QUALITY_ASSURANCE.md`;
7. `docs/intelligence/CURRENT_STATE.md`;
8. `docs/intelligence/KNOWN_FAILURES.md`;
9. the relevant subsystem, worker, testing and deployment documents.

This programme is not a visual reskin. It is a state, lifecycle, navigation,
recovery and responsive-product correction. Colour, spacing and card polishing
must not be used to conceal contradictory backend state.

---

# 1. Mandatory execution order

## 1.1 Finish active bounded work before starting a later slice

On every implementation run, inspect current `main`, open pull requests, active
branches, CI, review threads and recent merges. Never assume a branch or pull
request mentioned by an earlier run still exists or remains current.

When a real bounded implementation pull request is active:

1. finish that pull request first;
2. bring it up to date with current `main` when required;
3. resolve real failures and review comments;
4. run every required gate;
5. merge only when green, reviewed, accurately documented and free of unresolved
   threads;
6. do not add unrelated later-slice work merely because the files are nearby.

After the active bounded work is safely merged, continue with the next unmet
slice in the dependency order defined by the architecture document and this
standard.

A doc-only clarification may be prepared separately, but it must not rewrite,
replace or silently broaden the active implementation pull request. Code changes
for later slices remain separate.

## 1.2 Re-check implementation status rather than trusting documents alone

A requirement written in a document is not implemented. A route, template,
model, card, endpoint or test token is also not enough by itself.

Before declaring a slice complete, verify the actual end-to-end user path in the
running product and inspect the persisted records that drive it. Documentation
must describe the implementation that exists after merge, not the intended
future state.

## 1.3 Dependency order is binding

The programme order is:

1. authoritative assessment identity and projection;
2. canonical lifecycle and typed errors;
3. persisted live task experience;
4. complete APK path repair;
5. responsive shell and contextual inspector;
6. navigation consolidation;
7. composer simplification;
8. findings, evidence, graph and report alignment;
9. website-flow alignment;
10. Source Hunt alignment;
11. empty-state, content-language and role-based entry pass;
12. frontend consolidation, cross-workflow acceptance and obsolete-code removal.

Do not start broad cosmetic cleanup before the authoritative projection and
lifecycle are stable. Later visual work must consume the real projection rather
than introduce another browser-owned state source.

---

# 2. Current implementation baseline

## 2.1 Valuable foundations that must be retained

The current product already contains important production-oriented foundations:

- authenticated private-lab sign-in;
- role-aware navigation and protected routes;
- consistent dark security-product styling;
- a real conversational workspace;
- exact website target, authorisation, port, profile and approval checks;
- resumable APK upload with byte-level progress;
- immutable/content-hash-oriented artifact ingestion;
- persisted worker queues and activity records;
- deterministic fallback when a model provider is unavailable;
- evidence-first findings and human-governance boundaries;
- a live task-card concept;
- a contextual inspector concept;
- mobile-specific layout code;
- responsive browser and phone audit tooling.

These foundations must be reused. Do not replace them with a second framework,
second workspace, second assessment model, second upload system or browser-only
progress simulation.

## 2.2 Current product classification

The implementation is a strong controlled-lab prototype with substantial backend
security and governance, but the complete AI-first product experience remains
partial until all supported surfaces share one assessment identity and lifecycle.

The most serious defect is not visual appearance. It is cross-surface state
contradiction. A product that looks polished but cannot reliably answer whether
an assessment exists, is running, failed, preserved evidence or produced a
report is not ready.

## 2.3 Review baseline scorecard

The following heuristic scorecard records the August 2, 2026 audit baseline. It
is not a substitute for tests and must not be presented as a production metric.
It exists to prevent agents from treating visual polish as proof of product
completion.

| Area | Baseline | Main interpretation |
|---|---:|---|
| Visual foundation | 7.5/10 | Professional and appropriate for a security workspace |
| Desktop conversation | 7/10 | Good structure, overloaded secondary controls |
| Mobile experience | 5.5/10 | Deliberate mobile code exists, but behaviour is inconsistent |
| Website assessment flow | 7.5/10 | Properly governed and mostly coherent |
| APK assessment flow | 4/10 | Upload and worker paths exist but are not one assessment lifecycle |
| Information architecture | 5/10 | Too many competing destinations and state surfaces |
| State consistency | 4/10 | Critical product weakness |
| Failure and recovery | 4.5/10 | Failure is visible but not sufficiently actionable |
| Accessibility | 6.5/10 | Good foundations, very small meaningful text remains |
| Frontend maintainability | 5/10 | Excessive corrective CSS/JS layering |
| Overall product experience | 5.8/10 | Strong lab foundation, not a finished unified workspace |

A later audit may replace this baseline only with direct product evidence and a
clear description of what changed.

---

# 3. Root-cause implementation diagnosis

## 3.1 Website assessments already use the canonical run architecture

The website conversation path in
`vulnhunter/web/conversational_views.py` resolves authorisation, target, port and
profile, creates an assessment through `AssessmentWorkflowService`, persists a
run identity and reconstructs status through the product service and activity
projection.

The important website state includes:

```text
run_id
target
profile
authorization_id
graph_id
```

This enables conversation status, history, approval, cancellation and results to
refer to the same run. The implementation may need product-language and UI
alignment, but its basic ownership model is the correct direction.

## 3.2 APK assessments currently use a parallel state architecture

The APK path in `vulnhunter/web/conversation_mobile_views.py` currently follows
a different ownership chain:

```text
resumable upload
→ artifact ingestion
→ conversation attachment
→ mobile chat plan
→ mobile static job
→ session-backed mobile context
→ mobile job status endpoint
```

This path can successfully validate an artifact and queue work without creating
or binding the same durable assessment record used by website assessments.
Consequently, separate surfaces may know different parts of the operation:

- upload code knows the staged bytes;
- artifact storage knows the APK and hash;
- mobile session state knows the plan;
- the mobile worker store knows the job;
- the graph may know the artifact;
- standard assessment history may have no run;
- the inspector may have no `active_run`;
- global findings and reports may have no owning assessment.

This split is the main source of the observed state contradiction. Agents must
not attempt to solve it with JavaScript synchronisation, copied session flags or
more status banners.

## 3.3 Browser session state is selection, not authority

Session or browser state may remember:

```text
selected_workspace_id
selected_assessment_id
open_inspector_tab
conversation_scroll_anchor
unsent_composer_text
```

It must not own:

```text
whether an assessment exists
assessment lifecycle
worker lifecycle
approval state
finding count
evidence count
report readiness
retry eligibility
```

Refresh, reconnect, a second device or cleared local storage must reconstruct the
same product state from persisted backend records.

## 3.4 Multiple renderers currently calculate overlapping status

Conversation messages, upload indicators, task cards, state strips, inspector,
history, findings, graph and reports can each derive status separately. This
creates drift even when every individual component appears internally correct.

The correction is one authenticated read model, not another event listener.
Every user-facing status component must receive the same projection or a scoped
view derived from it.

---

# 4. Canonical persisted assessment model

## 4.1 Required ownership graph

After final input validation, every supported workflow must have the following
ownership shape:

```text
Workspace / conversation
└── Assessment
    ├── Subject
    │   ├── website target, or
    │   ├── Android artifact, or
    │   └── source repository snapshot
    ├── Authority binding
    ├── Plan
    ├── Task graph
    │   └── Task attempts and tool stages
    ├── Activity events
    ├── Evidence
    ├── Candidate findings
    ├── Verification and review state
    └── Report readiness and exports
```

No task, evidence item, graph node, finding or report may become product-visible
without an owning assessment identity or an explicit non-assessment specialist
classification that cannot be mistaken for user assessment work.

## 4.2 Assessment projection contract

Create one immutable authenticated read model comparable to:

```text
AssessmentProjection
├── schema_version
├── workspace
│   ├── workspace_id
│   ├── conversation_id
│   └── title
├── assessment
│   ├── assessment_id
│   ├── assessment_type
│   ├── owner_id
│   ├── lifecycle_state
│   ├── user_stage
│   ├── terminal_reason
│   ├── created_at
│   └── updated_at
├── subject
│   ├── subject_id
│   ├── type
│   ├── display_name
│   ├── target_or_repository
│   └── artifact identity when applicable
├── authority
│   ├── authorization_id
│   ├── authorization_state
│   ├── approval_state
│   └── exact unmet requirement
├── plan
│   ├── plan_id
│   ├── plan_digest
│   ├── profile
│   └── confirmation state
├── execution
│   ├── active_task_id
│   ├── task_graph_id
│   ├── current_node
│   ├── current_attempt
│   ├── worker_state
│   ├── provider_state separately
│   ├── completed_stages
│   ├── waiting_stage
│   └── failed_stage
├── activity
│   ├── last_sequence
│   └── recent safe events
├── results
│   ├── evidence_count
│   ├── candidate_count
│   ├── verified_finding_count
│   ├── review_required_count
│   └── partial_result state
├── reports
│   └── format-specific readiness
└── allowed_actions
    ├── command
    ├── enabled
    ├── reason
    └── idempotency requirements
```

The projection must be derived from persisted stores and must fail closed when
required identity links are incomplete. It must not fabricate an assessment from
an artifact card or infer completion from a successful HTTP response alone.

## 4.3 APK creation boundary

For APK workflows, the exact boundary is:

```text
upload start
→ temporary upload identity only
→ byte completion
→ archive, quota, size and integrity validation
→ immutable artifact creation
→ durable assessment create-or-bind
→ artifact attached to assessment
→ task graph and plan creation
→ worker queueing when permitted
```

Before artifact validation, a temporary upload may exist without an assessment.
After validation, assessment creation or binding is mandatory and idempotent.
A validated artifact must never be shown as active user work while the product
reports that no assessment exists.

## 4.4 Create-or-bind idempotency

The create-or-bind operation must use a stable idempotency basis including the
workspace, owner, artifact identity and intended workflow. Repeated finalisation
from double tap, retry, reconnect or request timeout must return the same
assessment rather than creating duplicate runs.

A safe conceptual response is:

```json
{
  "assessment_id": "VH-2026-0042",
  "workspace_id": "workspace-...",
  "artifact_id": "artifact-...",
  "active_task_id": "task-...",
  "projection_url": "/assessments/VH-2026-0042/projection/",
  "created": false,
  "lifecycle_state": "PLANNING"
}
```

`created: false` means the operation returned an existing correctly bound
assessment. It must not be treated as an error.

## 4.5 Recommended read endpoints

Existing routes may be adapted rather than duplicated, but the product should
have one clear assessment-scoped contract equivalent to:

```text
GET /assessments/<assessment_id>/projection/
GET /assessments/<assessment_id>/activity/
GET /assessments/<assessment_id>/findings/
GET /assessments/<assessment_id>/evidence/
GET /assessments/<assessment_id>/reports/
```

Global index routes remain cross-assessment indexes. Contextual navigation from a
workspace must include the selected assessment and must not silently discard the
context.

---

# 5. Lifecycle, error and retry implementation

## 5.1 One assessment lifecycle, many task-node states

An assessment has one current lifecycle. Individual tasks and tool stages may
have their own states, but those states are projected into one product meaning.
The UI must never independently infer that the assessment is absent, idle,
running and failed at the same time.

## 5.2 Minimum typed error taxonomy

Use stable machine-readable categories at the product boundary. The minimum
implementation set is:

```text
INPUT_INVALID
AUTHENTICATION_REQUIRED
REAUTHENTICATION_REQUIRED
NOT_AUTHORISED
AUTHORIZATION_EXPIRED
APPROVAL_REQUIRED
APPROVAL_EXPIRED
POLICY_DENIED
DEPENDENCY_UNAVAILABLE
PROVIDER_UNAVAILABLE
WORKER_UNAVAILABLE
WORKER_LOST
TOOL_NOT_INSTALLED
TOOL_VERSION_MISMATCH
TOOL_TIMEOUT
TOOL_FAILED
TOOL_OUTPUT_INVALID
STORAGE_FAILURE
INTEGRITY_FAILED
CONFLICT
STALE_REVISION
CANCELLED
TIMEOUT
PARTIAL_RESULT
PROJECTION_INCOMPLETE
INTERNAL_FAILURE
```

Each category defines:

- ordinary-language title;
- safe explanation;
- owning stage;
- whether user action is required;
- whether operator configuration is required;
- whether retry is allowed;
- retry scope;
- which evidence was preserved;
- whether technical detail is available;
- stable redacted reference ID.

## 5.3 Failure payload

A safe failure projection should be comparable to:

```json
{
  "error": {
    "category": "TOOL_OUTPUT_INVALID",
    "reference_id": "VH-ERR-8F42A",
    "stage_id": "jadx-decompile",
    "stage_label": "Decompiling source",
    "tool": "jadx",
    "attempt": 2,
    "title": "Static analysis stopped",
    "message": "JADX exited before producing the expected source directory.",
    "completed_stages": [
      "upload",
      "artifact-validation",
      "manifest-extraction"
    ],
    "preserved_evidence": [
      "apk",
      "sha256",
      "package-metadata",
      "manifest"
    ],
    "user_action_required": false,
    "operator_action_required": false
  },
  "retry": {
    "allowed": true,
    "scope": "failed_node",
    "node_id": "jadx-decompile",
    "idempotency_key": "...",
    "preserves_prior_attempt": true
  }
}
```

The browser must not generate this structure itself.

## 5.4 Failure card content order

The primary failure card displays:

1. what stopped;
2. failed stage;
3. understandable reason;
4. completed work;
5. preserved evidence;
6. exact next action;
7. safe retry when available;
8. reference ID;
9. expandable technical detail.

Do not lead with queue envelopes, canonical receipts or stack traces.

## 5.5 Retry rules

A retry action is rendered only when the backend returns an explicit allowed
retry contract. Retry must:

- be idempotent;
- identify whether it retries a node, stage, task or complete assessment;
- preserve previous attempt records and receipts;
- reuse valid preserved inputs where safe;
- create a new attempt identity;
- not erase the failure that motivated the retry;
- remain subject to current authorisation, approval and policy.

A decorative Retry button that merely resubmits the original form is forbidden.

## 5.6 Provider, worker and assessment health are independent

The product must separately represent:

```text
conversation provider health
assessment lifecycle health
worker readiness and execution health
```

A provider outage may produce a deterministic answer while the assessment
continues normally. A worker failure must not be described as a model/provider
failure. A policy denial must not be presented as infrastructure failure.

---

# 6. Detailed flow implementation

## 6.1 Role-based entry and landing

The authenticated landing experience must reflect the user's actual role and
work state.

### Assessment operator or analyst

Show:

- open selected or most recent workspace;
- new assessment;
- recent assessments;
- pending confirmations;
- blocked or failed work requiring attention.

Do not force the user through a campaign-and-release operations dashboard before
they can begin an assessment.

### Reviewer

Show:

- assigned reviews;
- evidence awaiting review;
- disputes requiring attention;
- recently completed decisions.

### Administrator or auditor

Show:

- operational health;
- worker and provider readiness;
- audit activity;
- pending governance actions;
- cross-assessment summaries.

The existing operations dashboard may remain for authorised roles, but it must
not be the universal product entry point.

## 6.2 Website assessment flow

Retain the current governed sequence:

```text
URL supplied
→ canonical target and port resolved
→ authorisation checked or requested
→ approved profile selected
→ durable assessment created
→ exact plan prepared
→ confirmation or approval requested
→ queue and worker execution
→ evidence and candidate findings
→ verification and review
→ report readiness
```

Improve the primary language without weakening the exact implementation.
For example, show `Preparing the authorised checks` by default and expose
scanner, template manifest and plan digest under technical details.

The conversation must prevent accidental duplicate runs. `Scan again` or another
explicit repeat action is required to create a new assessment when a suitable
existing one is already active or complete.

## 6.3 APK assessment flow

The corrected sequence is:

```text
attach APK
→ resumable byte upload
→ validate archive, size, quota and hash
→ create immutable artifact
→ create or bind durable assessment
→ show artifact and assessment identity
→ create declared static/native plan
→ request only necessary confirmation/approval
→ enqueue fixed worker task
→ record tool stages and receipts
→ preserve partial evidence on safe tool failure
→ correlate evidence
→ create candidates only from evidence
→ verify or abstain
→ show assessment-scoped findings, evidence and report readiness
```

The assistant must not ask for an APK that is uploading, validated or already
bound to the selected assessment. Replacement is a separate explicit command
that explains the impact on the existing assessment.

Dynamic analysis availability is separate. Missing emulator/runtime setup must
not make static analysis look failed.

## 6.4 Long-running execution

Inside the workspace, render one primary task card from the authoritative
projection and persisted events. It should answer:

- current stage;
- active worker or tool in ordinary language;
- completed stages;
- waiting or blocked reason;
- elapsed time;
- whether user action is required;
- evidence already preserved;
- safe actions.

Outside the workspace, one compact background indicator may summarise active
work. Do not show a modal, toast, banner, state strip, inspector progress and task
card with competing values for one operation.

Use byte percentages for uploads. For analysis, prefer `stage 4 of 8` unless the
backend defines reviewed measurable stage weights. Never convert elapsed time
into a completion percentage.

## 6.5 Findings and evidence

A contextual Findings or Evidence view always identifies its owning assessment.
It must distinguish:

- candidate;
- verified;
- review required;
- rejected;
- abstained;
- partial result.

Zero findings does not mean no assessment and does not erase preserved evidence.
A failed assessment may still have useful preserved artifacts and activity.

## 6.6 Graph

Graph is contextual evidence presentation, not permanent primary navigation.
Show it only when meaningful relationships exist. A lone artifact node is an
artifact card, not an attack graph. Never imply an attack path when the data only
represents inventory or unverified correlation.

## 6.7 Reports

Assessment report readiness is format-specific and derived from actual records.
A contextual report view first shows assessment identity and lifecycle, then
states the exact requirement for every format.

Example:

```text
Digi Volt.apk · VH-2026-0042
Static analysis failed

HTML          Unavailable — assessment incomplete
JSON          Available — partial activity and metadata
SARIF         Unavailable — no verified findings
Evidence ZIP  Available — preserved evidence only
PDF           Unavailable — renderer not configured
```

Pilot, demo and seeded records belong in a clearly labelled separate area and
must never resemble the selected user's assessment output.

---

# 7. Information architecture and interaction hierarchy

## 7.1 Desktop ownership

The desktop shell should have three clear ownership zones:

```text
left: workspace/global navigation
centre: conversation and active task
right: optional selected-assessment inspector
```

The inspector is contextual and may close without losing selection or state. It
is not a second dashboard with its own independent lifecycle.

## 7.2 Mobile primary navigation

Use:

```text
Chat
Activity
Findings
More
```

`More` may expose Evidence, Report, Authorization, Assessment details, All
assessments and Settings according to role.

Do not reserve a permanent bottom-navigation slot for Graph. Do not expose both
Analysis and Activity as competing names for the same operation.

## 7.3 Global versus contextual pages

Global pages are cross-assessment indexes:

- All assessments;
- Findings;
- Reports;
- Campaigns;
- Authorisations;
- Audit.

Contextual pages are selected-assessment views:

- Activity;
- Findings;
- Evidence;
- Report;
- optional Graph.

Opening a global record returns to or opens its owning assessment context.
Opening a contextual page from chat must preserve the selected assessment filter.

## 7.4 Composer hierarchy

Primary controls are only:

```text
Attach
Text input
Mode
Send
```

Move provider selection, provider health, detailed reasoning effort, prompt
history, diagnostics and low-value metadata behind progressive disclosure or
Settings.

The default message provenance may say `Answered using deterministic fallback`.
Requested provider, requested model, resolved provider and technical reason are
expandable details, not permanent message furniture.

## 7.5 Inspector hierarchy

The inspector header shows subject, assessment ID and truthful state. Tabs are:

```text
Summary
Activity
Findings
Evidence
Report
```

Graph appears inside Evidence when meaningful graph records exist.

When no assessment is selected, keep the inspector closed or show one compact
selection state with `New assessment` and `Open history`. Do not show progress
decoration, pending identity fields or worker sections for a nonexistent
selection.

## 7.6 Empty states

A zero-data page uses one concise explanation and one useful action. Large grids
of governance metrics must not be used merely to explain that the count is zero.

A contextual empty state references the selected assessment and explains the
next producing stage. A global empty state explains how records enter that index.

---

# 8. Design system and frontend consolidation

## 8.1 One token source

`config/product_interface/design_tokens.json` is the intended product token
source. Runtime CSS must not silently drift from it.

Known drift classes to remove include:

- body text size differing from the configured body scale;
- card and control radii differing across global files;
- multiple focus colours;
- old hardcoded teal values after the main accent moved to blue;
- component gradients and borders bypassing tokens;
- meaningful text below the approved readable scale.

Generate or validate CSS custom properties from the token source. CI should fail
when critical runtime values disagree with the configured design system without
an explicit documented exception.

## 8.2 CSS ownership

Files named as temporary correction layers such as `polish`, `final-fixes` or
multiple overlapping mobile overrides are not permanent architecture.

Move toward ownership comparable to:

```text
static/web/
├── tokens.css
├── reset.css
├── shell.css
├── components/
│   ├── buttons.css
│   ├── cards.css
│   ├── status.css
│   ├── tables.css
│   └── dialogs.css
├── features/
│   ├── conversation.css
│   ├── assessment-task.css
│   ├── inspector.css
│   ├── findings.css
│   └── reports.css
└── responsive.css
```

The exact file names may differ, but every component must have one clear owner.
After migration, remove obsolete corrective files rather than leaving both old
and new rules active.

## 8.3 JavaScript state ownership

Conversation, upload, task card, inspector, history and mobile navigation should
consume one frontend assessment store backed by the server projection.

A conceptual store is:

```text
assessmentStore
├── selectedAssessmentId
├── projection
├── upload state
├── connection state
├── active view
└── ephemeral UI state
```

The store coordinates rendering; it does not become lifecycle authority. Avoid
multiple scripts independently polling and translating the same backend state.

## 8.4 Compatibility and cleanup

Do not indefinitely add new compatibility, bridge, polish or final-fix files.
Every slice must identify obsolete state sources, selectors and assets made
unnecessary by the change and remove them after regression coverage exists.

No cleanup may remove a security gate or discard compatibility without an
explicit migration decision.

---

# 9. Responsive and accessibility implementation thresholds

## 9.1 Readable typography

Use these minimum product expectations unless a stricter token applies:

- normal primary content: 14–16 CSS pixels;
- important mobile message content: at least 14 CSS pixels;
- supporting metadata: at least 12 CSS pixels;
- labels: 11–12 CSS pixels only when secondary;
- 8–10 CSS pixel text must not carry meaningful status, instruction, identity or
  action information.

Do not solve density by shrinking critical text.

## 9.2 Touch and control behaviour

- primary touch targets are at least 44 by 44 CSS pixels;
- enabled actions must not look disabled;
- destructive actions require clear wording and appropriate confirmation;
- status never relies on colour alone;
- long action rows wrap, intentionally scroll or collapse into More;
- controls must not be horizontally clipped.

## 9.3 Keyboard and navigation

Test:

- keyboard-only desktop use;
- focus trap in dialogs and full-screen sheets;
- Escape where appropriate;
- Android/browser Back closes the topmost temporary surface before navigation;
- previous focus is restored;
- chat scroll position is restored after inspector close;
- composer remains visible with the virtual keyboard open;
- latest-message controls do not cover content.

## 9.4 Zoom and assistive technology

Verify:

- 200% browser zoom;
- reduced motion;
- screen-reader labels and status announcements;
- Android TalkBack for primary mobile tasks;
- long translated or user-supplied text;
- unbroken URLs, hashes and filenames;
- bright-screen contrast for muted text;
- safe-area insets;
- portrait and short-height landscape;
- Android desktop-site simulation.

Add automated axe checks to the browser audit where practical, but do not treat
automated accessibility scans as a replacement for keyboard, TalkBack and zoom
review.

## 9.5 Tables

At phone width, normal task completion must not require horizontal table
scrolling. Convert assessment, finding, evidence, history and report tables into
stacked cards or labelled rows. Technical tables may use intentional contained
scrolling only when a card transformation would destroy meaning.

---

# 10. Acceptance and regression matrix

Every affected pull request includes the tests relevant to its slice. The final
programme acceptance includes all rows below.

## 10.1 Identity and consistency

- validated APK creates or returns exactly one durable assessment;
- conversation, task card, inspector and history show the same assessment ID;
- artifact, graph, evidence, findings and reports reference that assessment;
- a queued or running task cannot coexist with `No active assessment`;
- worker failure updates the assessment terminal or partial state;
- zero findings does not remove evidence or history;
- seeded records are separated from user work;
- a second device reconstructs the same assessment state.

## 10.2 Idempotency and recovery

- upload finalisation survives duplicate submission;
- assessment create-or-bind returns an existing assessment safely;
- approval double submission does not duplicate transitions;
- queue double submission does not duplicate jobs;
- cancellation remains truthful during completion races;
- retry creates a new attempt and preserves old receipts;
- refresh after request timeout shows the real result;
- stale CSRF or session recovery does not create duplicate work.

## 10.3 Conversation awareness

- assistant does not request an artifact already uploading;
- assistant does not request an artifact already validated;
- replacement is explicit;
- provider fallback is not confused with worker failure;
- a model answer cannot override lifecycle or allowed actions;
- status and result questions use persisted current state;
- ordinary-language response and technical detail remain consistent.

## 10.4 Failure quality

- every terminal failure has category, stage and reference ID;
- completed stages are shown;
- preserved evidence is shown;
- retry eligibility is backend-owned;
- operator-action-required and user-action-required are distinct;
- partial-tool success remains visible;
- missing dynamic runtime remains separate from static-analysis failure.

## 10.5 Navigation and context

- no duplicate primary destinations;
- mobile uses Chat, Activity, Findings and More;
- Graph appears only with meaningful data;
- global Findings and Reports are cross-assessment indexes;
- contextual links preserve assessment identity;
- browser Back restores prior surface and chat position;
- one active navigation item is shown.

## 10.6 Responsive and accessibility

- no body-level horizontal overflow at every supported viewport;
- no clipped action rows;
- inspector is full-screen/sheet/route on phone;
- tables become cards where required;
- composer works with keyboard open and closed;
- touch targets meet minimum size;
- focus is contained and restored;
- errors and stage changes are announced without noisy repetition;
- 200% zoom remains usable;
- reduced motion removes nonessential animation;
- long filenames and messages do not break the layout.

## 10.7 Browser evidence

Retain:

- machine-readable audit report;
- screenshots for all required viewports;
- console and page-error report;
- failed asset report;
- server log;
- exact seeded test persona and state description;
- evidence for keyboard-open mobile behaviour when changed;
- evidence for Android Chrome and desktop-site simulation when changed.

A screenshot alone does not prove correct state. Browser evidence must be paired
with assertions against persisted records or the authoritative projection.

---

# 11. Product quality measurements

These measurements are not allowed to fabricate analytics. Add them only when
they can be derived truthfully from real product events.

Useful programme measurements include:

- time from artifact validation to durable assessment binding;
- number of cross-surface projection mismatches, which must remain zero;
- percentage of terminal failures with an actionable next step;
- retry success rate by typed category and node;
- assessment completion and partial-completion rate;
- time required to locate findings after completion;
- number of navigation backtracks during one assessment task;
- mobile keyboard-overlap defects;
- reconnect/session-recovery success rate;
- duplicate-submission suppression count.

Do not display zero, sample or simulated values as real product metrics. Until a
measurement source is trustworthy, keep the metric absent and document the
missing instrumentation.

---

# 12. Pull-request implementation evidence

Every programme pull request description must state:

1. the architecture requirement being implemented;
2. the exact state invariant or flow defect addressed;
3. affected persisted stores and read models;
4. affected routes, templates, scripts and styles;
5. security and authority boundaries preserved;
6. idempotency and failure behaviour;
7. tests added;
8. browser/phone evidence run;
9. obsolete code removed;
10. remaining limitations and next dependency slice.

Do not use a checklist as a substitute for evidence. Link or name the exact test,
workflow, screenshot artifact or command result.

A pull request remains incomplete when:

- its new projection is not consumed by every affected surface;
- it leaves duplicate browser-local lifecycle state;
- tests assert only tokens or strings rather than user behaviour;
- mobile acceptance is deferred without a recorded blocker;
- documentation claims a later slice;
- seeded/demo data can still appear as current user work;
- the user receives a generic failure where a typed stage failure is available.

---

# 13. Agent anti-regression rules

Agents working on this programme must not:

- create a second assessment model instead of extending the canonical one;
- solve backend contradiction with local storage or session flags;
- copy forms, routes or business logic into a new workspace page;
- add another permanent navigation system;
- add another status banner for the same operation;
- use fake percentages or decorative progress;
- treat a successful upload as a completed assessment;
- treat a provider response as evidence that a worker ran;
- present a lone artifact as an attack graph;
- expose Retry without backend idempotency;
- erase previous failures after retry;
- make eight-to-ten-pixel text carry critical meaning;
- introduce more `final-fixes`, `polish`, `bridge` or compatibility files without
  a removal plan;
- weaken authorisation, approval, evidence, verification, review, release or
  publication gates to simplify the UI;
- claim completion from documentation, templates or unit tests alone;
- merge an unreviewed or failing slice;
- abandon active bounded work to start a visually attractive later slice.

The correct response to an unexpected architectural conflict is to stop the
slice, document the conflict and resolve ownership before continuing. Do not hide
it behind an adapter that becomes another source of truth.

---

# 14. Documentation reconciliation

After every merged slice:

1. update `docs/intelligence/CURRENT_STATE.md` with only implemented status;
2. update `docs/intelligence/KNOWN_FAILURES.md` when a failure is resolved,
   narrowed or newly discovered;
3. update the architecture document only when product behaviour changes;
4. update this standard when implementation mechanics or acceptance evidence
   changes;
5. update `docs/product/UI_QUALITY_ASSURANCE.md` when browser or accessibility
   gates change;
6. remove stale milestone language and obsolete instructions;
7. never leave two documents claiming different owners for the same lifecycle.

The implementation loop must read the current repository rather than relying on
a stale status paragraph. Documentation records truth; it does not create truth.

---

# 15. Complete programme definition of done

The detailed programme is complete only when all of the following are true in
running product evidence:

- every validated APK is bound idempotently to one durable assessment;
- website, APK and Source Hunt use the same assessment ownership pattern;
- one projection drives chat, task card, inspector, history, findings, evidence,
  graph and reports;
- refresh, reconnect, session recovery and device switching reconstruct the same
  state;
- long-running work uses one persisted task experience;
- every failure identifies category, stage, preserved work and safe next action;
- retry is typed, targeted, idempotent and preserves prior attempts;
- provider, worker and assessment health are separate;
- role-based landing sends users to their real work rather than one universal
  governance dashboard;
- mobile primary navigation is consolidated;
- the inspector is contextual on desktop and not compressed beside chat on phone;
- the composer exposes only primary controls by default;
- findings, evidence and reports identify their owning assessment;
- graph appears only for meaningful relationships;
- demo and pilot records cannot be mistaken for user work;
- design tokens and runtime CSS agree or have reviewed exceptions;
- obsolete corrective CSS/JS and duplicate state sources are removed;
- critical text remains readable and all primary mobile controls remain usable;
- keyboard, focus, TalkBack, zoom, reduced motion, safe areas, portrait,
  landscape and desktop-site acceptance pass;
- no supported primary page has body-level horizontal overflow;
- all repository-required code, security, worker, browser and private-lab gates
  pass;
- current-state, known-failure, architecture and QA documents agree with the
  implementation.

Until this evidence exists, agents must describe the programme as partial and
continue with the next unmet dependency-ordered slice.