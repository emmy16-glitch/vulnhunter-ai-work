# VulnHunter UI quality assurance

**Status:** Binding browser, responsive, accessibility and product-truth gate  
**Companion documents:**

- `docs/product/AI_FIRST_ASSESSMENT_WORKSPACE_ARCHITECTURE.md`;
- `docs/product/AI_FIRST_ASSESSMENT_WORKSPACE_IMPLEMENTATION_STANDARD.md`;
- `docs/product/CHAT_FIRST_WORKSPACE.md`;
- `docs/intelligence/CURRENT_STATE.md`;
- `docs/intelligence/KNOWN_FAILURES.md`.

VulnHunter treats the browser interface as a governed product surface, not a
decorative shell. A page is not ready merely because its URL resolves, a
template compiles, a screenshot looks attractive or an expected string exists.

A browser change is ready only when the interface presents one truthful backend
state, enables only valid actions, remains usable on supported phone and desktop
configurations, and provides enough evidence for another reviewer to reproduce
the result.

---

## 1. Quality ownership

The AI-first architecture document owns required product behaviour. The
implementation standard owns technical migration and acceptance details. This
file owns the browser and interaction evidence required before a product-facing
slice may merge.

Do not create a second UI QA checklist in a milestone document. Add new permanent
browser gates here and reference them from pull requests and workflows.

A green UI audit does not override a failed security, authorisation, evidence,
worker, repository or test gate. Similarly, passing backend tests does not excuse
an unusable or contradictory interface.

---

## 2. Required pull-request gate levels

Every product-facing pull request is validated at the following levels.

### 2.1 Static and application correctness

Required repository checks include:

- canonical Ruff formatting;
- Ruff lint;
- Python compilation;
- complete unit and integration test suite;
- scanner compatibility validation;
- restricted-worker validation where affected;
- strict repository audit;
- `git diff --check`;
- clean expected Git state.

No UI test may weaken or bypass a backend invariant to obtain a green result.

### 2.2 Backend-connected browser behaviour

The browser audit uses authenticated local-only personas and deterministic
seeded records. It must exercise the real route, view, permission, projection
and command path rather than a static mock page.

When a slice affects an assessment lifecycle, browser evidence must be paired
with assertions against the persisted stores or authoritative assessment
projection. A screenshot that appears correct while the underlying assessment
record disagrees is a failure.

Required browser defect checks include:

- HTTP or Django errors;
- JavaScript console errors;
- uncaught page errors;
- failed static assets;
- duplicate IDs;
- unnamed controls;
- broken in-page anchors;
- empty links or dead actions;
- missing or duplicate active navigation;
- clipped sidebar navigation;
- body-level horizontal overflow;
- long pages that cannot scroll;
- open dialogs outside the viewport;
- dialogs without headings, controls or scrollable content;
- mobile sidebar visible by default;
- missing mobile navigation control.

### 2.3 State-truth and cross-surface consistency

When an assessment is involved, the audit must verify:

- one assessment ID is shown by every affected surface;
- a validated artifact is bound to a durable assessment;
- a queued or running task is not displayed under `No active assessment`;
- chat, task card, inspector and history agree on lifecycle;
- findings, evidence, graph and reports identify the owning assessment;
- worker failure updates terminal or partial state everywhere;
- zero findings does not erase evidence, history or partial work;
- provider health is not confused with worker or assessment health;
- demo, pilot and seeded records are separated from current user work;
- refresh and reconnect reconstruct the same state.

The audit must fail closed when a projection is incomplete. It must not create
browser-only state to make the screenshot appear consistent.

### 2.4 Responsive visual evidence

Capture and retain full-page or purpose-specific screenshots at the supported
viewports. The standard matrix includes:

- reference desktop: 1672 by 941;
- common desktop: 1440 by 900;
- tablet landscape: 1024 by 768;
- tablet portrait: 768 by 1024;
- mobile: 390 by 844;
- narrow mobile: 360 by 800.

Affected mobile work must also be checked in Android Chrome and Android
desktop-site simulation when the environment permits. Short-height landscape is
required for changes involving sticky headers, bottom navigation, composer,
dialogs, sheets or keyboard behaviour.

Screenshots, machine-readable report, server log and console/page-error evidence
must be retained as workflow artifacts.

### 2.5 Accessibility and interaction evidence

The following are required when the affected surface contains interactive
controls, dialogs, sheets, navigation or live status:

- keyboard-only desktop completion;
- logical focus order;
- visible focus state;
- dialog or sheet focus containment;
- Escape handling where appropriate;
- Android/browser Back handling;
- previous-focus restoration;
- status and error announcements;
- no colour-only state;
- reduced-motion behaviour;
- 200% browser zoom;
- readable long text, filenames, URLs and hashes;
- primary Android TalkBack path for major mobile changes when practical.

Automated axe checks should be added to the Playwright audit where practical,
but automated accessibility output does not replace manual keyboard, TalkBack
and zoom review.

---

## 3. Product-truth scenarios

Every affected slice includes expected success, blocked/failure and motivating
regression scenarios.

### 3.1 Identity and lifecycle scenarios

At minimum, cover relevant cases from this set:

- no selected assessment;
- temporary upload before validation;
- validated artifact and newly bound assessment;
- planning;
- confirmation required;
- approval required;
- queued;
- worker claimed;
- running;
- dependency blocked;
- tool failure;
- worker unavailable;
- partial completion;
- cancellation requested;
- cancellation race with completion;
- terminal failure;
- complete with zero findings and preserved evidence;
- complete with candidate findings;
- review required;
- report ready;
- archived/historical assessment.

A page must not use one generic fixture for every lifecycle state.

### 3.2 Idempotency and recovery scenarios

Cover the commands relevant to the slice under:

- double tap or duplicate submission;
- slow network;
- request timeout after backend success;
- browser refresh;
- disconnect and reconnect;
- stale page resubmission;
- stale CSRF/session recovery;
- Android Back/forward;
- opening the same assessment on another device;
- clearing browser-local state.

The browser must show the existing authoritative result rather than creating a
duplicate assessment, approval transition, worker job, cancellation or retry.

### 3.3 Failure and retry scenarios

When failure UI changes, verify:

- machine-readable error category;
- stable reference ID;
- exact failed stage;
- understandable reason;
- completed stages;
- preserved evidence;
- user-action-required versus operator-action-required;
- backend-owned retry eligibility;
- targeted retry scope;
- new attempt identity;
- prior attempt and receipts retained;
- no Retry control when the backend cannot perform a safe idempotent retry.

Generic `worker did not complete` copy is not sufficient when typed failure
information exists.

---

## 4. Responsive workspace requirements

### 4.1 Mobile shell

At phone width:

- the desktop inspector must not remain compressed beside chat;
- the inspector opens as a full-screen route, sheet or appropriate bottom sheet;
- Android/browser Back closes the topmost temporary surface first;
- closing the inspector returns to the exact conversation context and scroll
  position;
- global tables become cards or labelled rows;
- normal task completion requires no body-level horizontal scrolling;
- sticky header, composer, latest-message control and bottom navigation do not
  overlap;
- safe-area insets are respected;
- primary actions remain reachable with the virtual keyboard open;
- long action rows wrap, intentionally scroll or collapse into More;
- text is not reduced below the product readable scale to make the layout fit.

### 4.2 Mobile primary navigation

The assessment workspace primary set is:

```text
Chat
Activity
Findings
More
```

Evidence and Report are contextual destinations. Graph appears only when
meaningful graph records exist. The audit must fail when competing duplicate
Analysis, Findings or Graph destinations are presented as primary navigation.

### 4.3 Composer

The primary composer exposes:

```text
Attach
Text input
Mode
Send
```

Provider selection, provider health, detailed reasoning, prompt management and
diagnostics belong behind progressive disclosure or Settings.

Validate:

- 16-pixel mobile input text where needed to avoid browser zoom;
- send and attachment targets meet the minimum touch size;
- composer remains visible with keyboard open;
- latest-message affordance does not cover content;
- attachment/upload state remains understandable;
- one authoritative upload progress value;
- character count appears only when useful;
- disabled state explains its reason.

### 4.4 Tables and dense technical content

Assessment history, findings, evidence and reports become mobile cards or
labelled rows. Contained horizontal scrolling is allowed only for technical data
where transforming the table would destroy meaning. The scroll container must be
obvious, keyboard reachable and must not force the complete page to overflow.

---

## 5. Typography, contrast and touch thresholds

Use the approved design tokens unless a reviewed exception exists.

Minimum expectations:

- primary content: 14–16 CSS pixels;
- meaningful mobile message content: at least 14 CSS pixels;
- supporting metadata: at least 12 CSS pixels;
- secondary labels: 11–12 CSS pixels;
- 8–10 CSS pixel text must not carry critical status, instruction, identity or
  action meaning;
- primary touch targets: at least 44 by 44 CSS pixels;
- focus state remains visible against every surface;
- muted text remains readable on bright mobile screens;
- enabled green or blue primary actions must not use muted text that resembles a
  disabled control;
- destructive actions use text and iconography, not colour alone.

When density is too high, remove repetition or use progressive disclosure. Do
not shrink meaningful text as the first response.

---

## 6. Design-system and frontend-maintainability checks

### 6.1 Token consistency

`config/product_interface/design_tokens.json` is the intended token source.
Review affected runtime CSS for drift in:

- background and surface colours;
- accent and focus colours;
- body and label sizes;
- control and card radii;
- border and shadow values;
- spacing scale;
- minimum control height.

A deliberate exception must be documented. Silent drift is a defect.

### 6.2 CSS ownership

A pull request must not add another permanent `polish`, `final-fixes`, `bridge`
or overlapping mobile override file without documenting:

- the existing owner that cannot safely contain the change;
- the migration plan;
- the obsolete file/rules that will be removed;
- regression evidence preventing future consolidation.

Prefer one component owner and remove obsolete corrective layers after migration.

### 6.3 JavaScript state ownership

Conversation, upload, task card, inspector, history and mobile navigation should
consume the same assessment projection through one coordinated frontend state
layer. The audit must detect or reviewers must reject:

- independent lifecycle inference in multiple scripts;
- copied status translation tables;
- local-storage ownership of assessment lifecycle;
- multiple polling loops for one operation;
- duplicate event rendering;
- browser-generated allowed actions;
- reload-only fixes for stale state.

---

## 7. Navigation and content checks

### 7.1 One owner per destination

Every concept has one primary owner and at most one contextual shortcut. The
browser audit checks duplicate primary destinations by URL and label, but manual
review must also catch conceptual duplicates that use different labels.

Global pages are indexes across assessments. Contextual pages preserve the
selected assessment. Opening a finding, evidence item or report must provide a
clear path back to its owning assessment.

### 7.2 Ordinary language first

Primary task copy uses understandable language. Governance, provider, worker,
hash and receipt details remain exact under expandable technical or audit views.

Reviewers must reject interfaces where labels such as `canonical worker state`,
`persisted receipts`, `exact snapshot` or queue-envelope terminology appear
before the user understands what is happening and what action is required.

### 7.3 Empty states

An empty state is concise, contextual and actionable. It must not use a large
metric-card grid merely to explain zero records.

Contextual empty states identify the selected assessment. Global empty states
explain how records enter the index. Seeded or pilot records are explicitly
labelled and separated.

---

## 8. Activation policy

An interface element may report that a capability is gated, but it must not
pretend that an unavailable backend action succeeded.

Scanner enqueue, active validation, repository graph generation, remote advisory
routing, mobile subprocess execution, report rendering, retry and publication
require explicit reviewed backend contracts and local prerequisites.

The Settings surface reports activation gates truthfully. It does not expose
secrets and does not provide decorative toggles that bypass server-side policy.

Provider health, worker readiness and assessment lifecycle are displayed as
separate dimensions.

---

## 9. Report exports

Pilot-plan HTML and JSON downloads use the existing protected-data-safe
`ReportExporter`. Other formats remain unavailable until their required finding,
evidence, attack-path or renderer context exists.

Assessment-scoped report UI must:

- identify the owning assessment;
- show lifecycle state;
- list every supported format;
- state the exact unmet requirement for unavailable formats;
- distinguish rendering from publication;
- separate pilot/demo data from user work;
- avoid dead download controls;
- reject protected payloads, unsafe filenames, oversized artifacts and evidence
  outside approved roots.

Rendering a report never publishes a finding or changes governance state.

---

## 10. Browser artifact requirements

The responsive workflow retains:

- screenshots for every required viewport;
- machine-readable validation report;
- server log;
- console errors;
- page errors;
- failed static asset responses;
- modal audit results;
- exact page/persona/state manifest;
- failure list;
- relevant Android/keyboard evidence.

Artifact names must identify route, viewport and state. A set of screenshots that
contains only empty/default states is insufficient for a lifecycle-changing pull
request.

Reviewers should compare affected states side by side and verify:

- hierarchy;
- density;
- typography;
- contrast;
- alignment;
- state consistency;
- action clarity;
- mobile reachability;
- absence of demo data confusion.

---

## 11. Manual review

A green browser audit establishes that the rendered pages are operational and
free from the automated defect classes it covers. It does not establish that the
product flow is understandable or that the displayed state is the correct state.

Before a major product-facing change merges, reviewers must manually inspect the
running journey from start through success, blocked/failure and recovery. The
review must answer:

- Can a non-technical authorised user identify what object is selected?
- Is the assessment identity visible where needed?
- Is the current stage unambiguous?
- Is there exactly one primary next action?
- Does failure explain preserved work and recovery?
- Can the user return to the conversation without losing context?
- Are global and contextual pages clearly different?
- Is provider or governance detail progressively disclosed?
- Does phone use feel intentionally designed rather than compressed desktop?
- Does the UI agree with the persisted projection?

If any answer is uncertain, the slice remains incomplete.

---

## 12. Pull-request completion checklist

A product-facing pull request may merge only when:

1. the motivating product defect and invariant are stated;
2. success, blocked/failure and regression tests exist;
3. persisted state or projection assertions accompany browser assertions;
4. idempotency and recovery are tested where relevant;
5. required viewport evidence is retained;
6. no body-level horizontal overflow exists;
7. keyboard, focus, Back, safe-area and virtual-keyboard behaviour is verified
   where relevant;
8. critical text and touch targets meet thresholds;
9. navigation has one owner per concept;
10. no fabricated progress, findings, evidence, metrics or capability is shown;
11. enabled, loading, disabled and destructive controls are visually distinct;
12. token drift and frontend ownership are reviewed;
13. obsolete duplicate styles, scripts or state sources are removed when made
    unnecessary;
14. documentation reflects implemented truth;
15. all repository, security, worker and browser gates pass;
16. review threads are resolved.

The interface remains partial when a supported workflow still contains
contradictory state, generic unactionable failure, duplicate primary navigation,
compressed phone layout, dead action or seeded data that appears to be user
work.