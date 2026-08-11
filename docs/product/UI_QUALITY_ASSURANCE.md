# VulnHunter UI Quality Assurance

**Status:** Binding browser, responsive, accessibility, product-truth and visual-conformance gate  
**Canonical design:** `docs/design/VULNHUNTER_UI_CONTRACT.md`  
**Agent standard:** `docs/design/AI_AGENT_UI_IMPLEMENTATION_STANDARD.md`

Companion documents:

- `docs/design/references/manifest.json`;
- `docs/design/DEPRECATIONS.md`;
- `docs/product/CHAT_FIRST_WORKSPACE.md`;
- `docs/product/UI_ACCEPTANCE_CRITERIA.md`;
- `docs/product/RESPONSIVE_AND_ACCESSIBILITY.md`;
- `docs/product/AI_FIRST_ASSESSMENT_WORKSPACE_ARCHITECTURE.md`;
- `docs/product/AI_FIRST_ASSESSMENT_WORKSPACE_IMPLEMENTATION_STANDARD.md`.

VulnHunter treats the browser interface as a governed product surface, not a decorative shell. A page is not ready merely because its URL resolves, a template compiles, a screenshot looks attractive, or an expected string exists.

A browser change is ready only when it presents one truthful backend state, follows the canonical chat/task-first product composition, remains readable and usable on supported phone/desktop layouts, and provides reproducible evidence.

---

## 1. Quality ownership

The locked UI contract owns visual/product interaction. The AI agent implementation standard owns implementation/rejection discipline. The chat-first contract owns workflow semantics. The AI-first architecture owns non-conflicting state/lifecycle architecture. This file owns browser/interaction evidence before a product-facing slice may merge.

A green UI audit does not override a failed security, authorization, evidence, worker, repository or test gate. Passing backend tests does not excuse a contradictory, unreadable or dashboard-first UI.

---

## 2. Required pull-request gate levels

Every product-facing pull request is validated at the following levels.

### 2.1 Static and application correctness

Required repository checks include the gates defined by `AGENTS.md`, including relevant formatting, lint, compilation, tests, scanner/repository validation and `git diff --check`.

No UI test may weaken or bypass a backend invariant to obtain a green result.

### 2.2 Backend-connected browser behavior

Browser validation must exercise the real route, view, permission, projection and command path rather than only a static mock page.

When a slice affects an assessment lifecycle, browser evidence must be paired with assertions against the persisted stores or authoritative assessment projection. A screenshot that appears correct while the underlying record disagrees is a failure.

Required browser defect checks include:

- HTTP/Django errors;
- JavaScript console errors;
- uncaught page errors;
- failed static assets;
- duplicate IDs;
- unnamed controls;
- broken/dead actions;
- missing/duplicate active navigation;
- body-level horizontal overflow;
- clipped primary controls;
- dialogs/drawers outside the viewport;
- mobile sidebar visible by default;
- missing mobile drawer/menu control;
- composer unreachable/covered;
- unreadable message copy;
- unintended permanent context panel;
- multiple competing navigation systems.

### 2.3 State truth and cross-surface consistency

When an assessment is involved, verify:

- one workspace/assessment ID is used consistently;
- a validated artifact is bound to durable state where required;
- queued/running work is not displayed under contradictory “no active assessment” state;
- chat/task projection and specialist deep views agree on lifecycle;
- findings/evidence/reports identify the owning assessment;
- worker failure updates the same state model;
- zero findings does not erase evidence/history/partial work;
- provider health is not confused with worker/assessment health;
- demo/pilot/seeded records are separated from current user work;
- refresh/reconnect reconstructs the same state;
- browser code does not invent missing status to make screenshots look consistent.

### 2.4 Canonical visual/product conformance

Every affected UI slice must be checked against these invariants:

- conversation/task-first hierarchy remains dominant;
- MonkeyCode is used only for task/workspace structure/behavior;
- Beautiful UI is used only for AI-native component/microinteraction patterns;
- VulnHunter retains warm cream/off-white dotted canvas, dusty-pink accents, compact dark task/sidebar, near-black technical text/borders, square geometry and hard black offset shadows;
- assistant/body copy remains readable;
- contextual detail is closed until opened;
- utilities do not become a wide toolbar competing with the task;
- the UI does not resurrect explicitly deprecated dashboard patterns;
- no hidden chain-of-thought/private reasoning is exposed.

A screenshot that looks polished but violates these invariants fails.

---

## 3. Responsive visual evidence

Capture purpose-specific screenshots at representative viewports. The standard matrix includes approximately:

- desktop `1440×900`;
- desktop `1280×800` where practical;
- tablet landscape `1024×768`;
- tablet portrait `768×1024`;
- mobile `412×915` or similar;
- mobile `390×844`;
- narrow mobile `360×800`.

Affected mobile work should also be checked in Android Chrome when practical. Short-height landscape is required for changes involving sticky headers, composer, dialogs, sheets or keyboard behavior.

Screenshots are evidence, not authority. They are compared against the locked design contract rather than against the previous implementation.

---

## 4. Mobile shell gate

At phone width:

- the desktop sidebar becomes an overlay task/chat drawer;
- the base workspace is one column;
- there is no permanent desktop inspector beside chat;
- contextual detail opens as a full-width sheet/drawer/deep view;
- primary task state remains visible and readable;
- normal use requires no body-level horizontal scrolling;
- no desktop toolbar row is squeezed into the header/page;
- primary actions are not clipped/truncated;
- safe-area/browser/system insets are respected;
- the composer remains usable with the virtual keyboard open;
- meaningful copy is not shrunk below the readable scale;
- desktop KPI/state grids are restructured, not miniaturized.

### Mobile navigation

The canonical everyday mobile navigation is the **MonkeyCode-style task/chat drawer**, not a permanent bottom-tab dashboard.

The drawer prioritizes:

```text
VULNHUNTER
+ New assessment
Chats / Tasks
current task
recent tasks
Task history
Manage
Settings
user / role
```

Evidence, findings, reports, Source Hunt and other specialist areas open contextually or through progressive disclosure. They are not all permanent bottom tabs.

A pull request fails when duplicate `Analysis`, `Findings`, `Graph`, `Chat` or similar destination systems compete with the task drawer/workspace hierarchy.

---

## 5. Composer gate

The primary composer remains simple and persistent.

Core composition:

```text
Attach / add
Text input
Send
```

A compact mode/detail control may exist where repository-backed, but provider selection, provider health, detailed reasoning, prompt management and diagnostics remain behind progressive disclosure/settings.

Validate:

- approximately 16px mobile input text where needed to avoid browser zoom;
- send/attachment targets meet critical touch size;
- composer remains reachable with keyboard open;
- latest content is not permanently covered;
- attachment/upload state is understandable;
- one authoritative upload progress source;
- disabled state explains the reason;
- composer remains available during supported running work and approval waits;
- queued follow-up behavior is visible where supported.

---

## 6. AI-native component gate

When used, AI-native primitives must reflect real state:

### Task rows

Use one coherent visible state system for pending/running/blocked/recovering/failed/cancelled/completed.

### Tool chips

Show only real tool/receipt/provenance information. Do not imply execution from a decorative chip.

### Approval cards

Show exact object/action/scope and real backend-supported decisions. Authorization, owner confirmation, independent approval, review and adjudication are distinct.

### Context cards

Show concise evidence/source/provenance and allow a deeper view. Do not dump huge technical detail into the base conversation.

### Recommendation cards

Advisory only. Never imply that a recommendation has been applied or verified unless authoritative state says so.

### Thinking/activity

Allowed: safe activity such as `Checking authorization…`. Forbidden: hidden chain-of-thought/private model reasoning.

---

## 7. Product-truth scenarios

Every affected slice includes expected success, blocked/failure and motivating regression scenarios.

Cover relevant states from:

- no selected assessment;
- temporary upload before validation;
- validated artifact/new assessment binding;
- planning;
- authorization missing;
- confirmation required;
- independent approval required;
- queued;
- worker claimed/running;
- follow-up queued;
- dependency blocked;
- tool failure;
- worker unavailable;
- recovering;
- partial completion;
- cancellation requested;
- cancellation race with completion;
- terminal failure;
- complete with zero findings and preserved evidence;
- complete with findings;
- review required;
- report ready;
- archived/historical assessment.

A page must not use one generic fixture for every lifecycle state.

---

## 8. Idempotency and recovery scenarios

Cover relevant commands under:

- double tap/duplicate submission;
- slow network;
- request timeout after backend success;
- refresh;
- disconnect/reconnect;
- stale page resubmission;
- stale CSRF/session recovery;
- Android Back/forward;
- opening the same assessment on another device;
- clearing browser-local state.

The browser must show the existing authoritative result rather than creating duplicate assessment, approval, worker job, cancellation or retry state.

---

## 9. Failure and retry scenarios

When failure UI changes, verify where available:

- machine-readable error category;
- stable reference ID;
- exact failed stage;
- understandable reason;
- completed stages;
- preserved evidence;
- user-action-required vs operator-action-required;
- backend-owned retry eligibility;
- targeted retry scope;
- new attempt identity;
- prior attempt/receipts retained;
- no Retry control when safe idempotent retry is unavailable.

Generic `worker did not complete` copy is insufficient when typed failure information exists.

---

## 10. Accessibility and interaction evidence

When the affected surface contains interactive controls, dialogs, sheets, navigation or live status, verify:

- keyboard-only desktop completion;
- logical focus order;
- visible focus state;
- dialog/sheet focus containment;
- Escape handling where appropriate;
- Android/browser Back handling;
- previous-focus restoration;
- status/error announcements;
- no color-only state;
- reduced-motion behavior;
- 200% browser zoom;
- readable long text, filenames, URLs and hashes;
- TalkBack path for major mobile changes when practical.

Automated accessibility checks may assist but do not replace manual interaction review.

---

## 11. Typography, contrast and touch thresholds

Use the approved design tokens unless a reviewed exception exists.

Minimum expectations:

- desktop primary content: generally `14–16px`;
- meaningful mobile conversation content: generally `15–17px`;
- supporting metadata: generally at least `12px` where practical;
- `8–10px` text must not carry critical status/instruction/identity/action meaning;
- primary/critical touch targets: approximately `44×44px` minimum;
- focus remains visible on cream and dark sidebar surfaces;
- muted text remains readable on bright mobile screens;
- enabled primary actions use clear near-black/high-contrast text appropriate to the dusty-pink system;
- destructive actions use text/icon semantics, not color alone.

When density is too high, remove repetition or use progressive disclosure. Do not shrink meaningful text first.

---

## 12. CSS/design-system maintainability

### Token consistency

`vulnhunter/web/static/web/tokens.css` is the runtime canonical token expression. Related config tokens must stay consistent with it.

Review affected CSS for drift in:

- canvas/surface colors;
- dusty-pink accent/focus language;
- dark sidebar colors;
- body/label sizes;
- square radius system;
- hard offset shadows;
- spacing scale;
- minimum control height.

### CSS ownership

A pull request must not add another permanent `polish`, `final-fixes`, `bridge`, `override` or overlapping mobile file without a documented necessity and consolidation plan.

Prefer one component owner and remove obsolete corrective layers after migration.

Routine `!important` use to force the design is a failure of ownership unless a narrowly justified edge case is documented.

### JavaScript state ownership

Conversation, upload, task state, history and responsive/context behavior should consume the same authoritative assessment projection. Reject:

- independent lifecycle inference in multiple scripts;
- copied status translation tables;
- local-storage ownership of assessment lifecycle;
- multiple polling loops for one operation;
- duplicate event rendering;
- browser-generated allowed actions;
- reload-only fixes for stale state.

---

## 13. Explicit visual anti-regression gate

A browser audit fails if the affected ordinary workspace contains any of these without a separately approved contract change:

1. four large top cards for `Authorization / Scope / Approval / Active`;
2. a default `Source Hunt / Search / Export / History / New workspace` toolbar row;
3. `Runs / Scanner / Execution / Entry point` KPI cards as the main workspace/history presentation;
4. giant dark Source Hunt/admin panels in the conversational workflow;
5. a giant Source Hunt form as the primary source-analysis entry;
6. low-contrast/tiny assistant message text;
7. giant blank areas while task state is microscopic;
8. blue-glow identity drift;
9. desktop controls clipped/squeezed on phone;
10. multiple competing navigation systems;
11. a permanent context/detail panel when nothing is selected;
12. a new CSS patch layer whose only purpose is to beat previous CSS.

These items are also recorded in `docs/design/DEPRECATIONS.md`.

---

## 14. Navigation/content checks

Every concept has one primary owner and at most one contextual shortcut.

Global pages are indexes across assessments. Contextual deep views preserve the selected assessment. Opening a finding, evidence item or report must provide a clear path back to its owning assessment/workspace.

Primary task copy uses ordinary language. Governance, provider, worker, hash and receipt detail remains exact under technical/audit disclosure.

Empty states are concise and actionable; do not use a metric-card grid merely to communicate zero records.

---

## 15. Activation policy

An interface may report that a capability is gated, but it must not pretend an unavailable backend action succeeded.

Scanner enqueue, active validation, repository graph generation, remote advisory routing, mobile subprocess execution, report rendering, retry and publication require explicit backend contracts and prerequisites.

Provider health, worker readiness and assessment lifecycle are separate dimensions.

---

## 16. Report/export gate

Assessment-scoped report UI must:

- identify owning assessment;
- show lifecycle state;
- list supported formats truthfully;
- state unmet requirements for unavailable formats;
- distinguish rendering from publication;
- separate pilot/demo data from user work;
- avoid dead download controls;
- preserve protected-data constraints.

Rendering never publishes a finding or changes governance state.

---

## 17. Browser artifact requirements

Retain appropriate evidence such as:

- screenshots for required viewports/states;
- machine-readable validation report;
- server log;
- console/page errors;
- failed static-asset responses;
- dialog/drawer audit results;
- exact page/persona/state manifest;
- relevant Android/keyboard evidence.

Artifact names should identify route, viewport and state. Empty/default screenshots alone are insufficient for lifecycle-changing work.

---

## 18. Manual review questions

Before a major product-facing change merges, reviewers should answer:

- Is the selected object/task obvious?
- Is current stage understandable?
- Is there one clear primary next action?
- Does failure explain preserved work/recovery?
- Can the user return to conversation without losing context?
- Are global and contextual views clearly different?
- Is provider/governance detail progressively disclosed?
- Does phone feel intentionally designed rather than compressed desktop?
- Does the UI agree with persisted projection?
- Does the surface still look unmistakably like the cream/dotted/dusty-pink VulnHunter product?
- Did the change reduce rather than add CSS/presentation debt?

If any answer is uncertain, the slice remains incomplete.

---

## 19. Pull-request completion checklist

A product-facing pull request may merge only when:

1. motivating product defect/invariant is stated;
2. success, blocked/failure and regression tests exist;
3. persisted-state assertions accompany browser assertions where relevant;
4. idempotency/recovery are tested where relevant;
5. required viewport evidence is retained;
6. no essential body-level horizontal overflow exists;
7. keyboard/focus/Back/safe-area/virtual-keyboard behavior is verified where relevant;
8. critical text/touch targets meet thresholds;
9. navigation has one owner per concept;
10. no fabricated progress/findings/evidence/metrics/capability is shown;
11. enabled/loading/disabled/destructive controls are distinct;
12. design-token/CSS ownership drift is reviewed;
13. obsolete duplicate styles/scripts/state sources are removed when made unnecessary;
14. the explicit anti-regression gate passes;
15. documentation reflects implemented truth;
16. repository/security/worker/browser gates pass;
17. review threads are resolved.

A UI remains incomplete when it contains contradictory state, generic unactionable failure, dashboard-first composition, duplicate navigation, compressed phone layout, dead action, seeded-data confusion, hidden reasoning exposure, or stylesheet-patch accumulation.
