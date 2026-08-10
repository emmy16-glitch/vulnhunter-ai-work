# VulnHunter UI Contract

**STATUS: LOCKED — CANONICAL PRODUCT UI CONTRACT**  
**Applies to:** every authenticated and unauthenticated VulnHunter browser surface, desktop and mobile  
**Change policy:** deliberate product-design change only; incidental frontend work must not reinterpret this contract

## 0. Authority

This file is the visual and interaction source of truth for VulnHunter.

When sources disagree, use this order:

1. `AGENTS.md` and backend security/authorization contracts for security truth;
2. this UI contract for product interaction and visual language;
3. `docs/design/references/manifest.json` and its approved reference images;
4. `docs/product/CHAT_FIRST_WORKSPACE.md` and the AI-first workspace architecture for workflow meaning;
5. shared VulnHunter design tokens/components;
6. existing page implementation;
7. agent or developer preference — **never authoritative**.

A visual reference is not permission to invent product functionality. The repository remains the source of truth for routes, actions, fields, providers, models, roles, approvals and capabilities.

### Reference interpretation

- **MonkeyCode is an interaction reference only:** task/chat workspace, compact task history, running-operation timeline, queued messages, reconnect behaviour, contextual controls and mobile drawer patterns.
- **The cream/dotted editorial reference is a visual-language reference only:** warm paper surface, dotted grid, dusty pink, square geometry, technical type, hard offset shadows and generous whitespace.
- **VulnHunter is the product:** only VulnHunter branding, repository-backed terminology and repository-backed actions may ship.

Never copy reference-product branding, account tiers, model names, project concepts, wording or unsupported controls.

---

## 1. Product principle

> **VulnHunter is a security workspace controlled through conversation. It is not an admin dashboard with a chatbot attached.**

The conversation/task workspace is the primary operating surface. Findings, evidence, reports, approvals, authorization requirements, Source Hunt setup, APK uploads, failure/recovery and review status should appear contextually in the conversation first.

Dedicated pages remain valid when more room or identity-bound governance is genuinely required. They are **deep views of the same persisted state**, not competing workflows.

Do not turn every backend subsystem into permanent top-level navigation.

---

## 2. Locked visual language

### 2.1 Core palette

These are the default design tokens. Small implementation adjustments for contrast are allowed only when the semantic role is preserved.

```css
--vh-canvas: #f5f2ec;
--vh-surface: #fbf9f4;
--vh-ink: #17171b;
--vh-muted: #626169;
--vh-line: rgba(23, 23, 27, 0.22);
--vh-dot: rgba(23, 23, 27, 0.09);
--vh-pink: #d99a9f;
--vh-pink-soft: #f1dadb;
--vh-sidebar: #10151b;
--vh-sidebar-surface: #182028;
--vh-success: #3f8c63;
--vh-warning: #a66e63;
--vh-danger: #a6535b;
```

Rules:

- cream/off-white is the main working canvas;
- near-black is the dominant text and border colour;
- dusty pink is the primary active/accent colour;
- green is restrained and reserved for genuine success/completion;
- warnings/errors use muted rose/earth tones rather than neon red;
- no blue-and-white generic SaaS theme;
- no neon cyberpunk palette.

### 2.2 Dotted canvas

The working surface uses one subtle graph-paper/dotted texture:

```css
background-color: var(--vh-canvas);
background-image: radial-gradient(circle, var(--vh-dot) 1px, transparent 1px);
background-size: 22px 22px;
```

Do not create page-specific dot scales, high-contrast dots or decorative grid variants.

### 2.3 Geometry

- Default cards and controls are square or nearly square.
- Default radius: `0–3px`.
- Status chips may use a small pill radius when compact status semantics benefit from it.
- Large rounded SaaS cards, bubbly chat balloons and excessive pills are prohibited.

### 2.4 Shadows

Important controls use **hard, zero-blur, offset shadows**.

```css
--vh-shadow-control: 3px 3px 0 #17171b;
--vh-shadow-primary: 5px 5px 0 #17171b;
```

Forbidden by default:

- soft `0 12px 30px rgba(...)` SaaS shadows;
- glow;
- glassmorphism;
- frosted blur;
- gradients used as decoration.

Overlays may dim the background, but the overlay panel itself remains crisp and square.

---

## 3. Typography contract

VulnHunter has three typography roles.

### 3.1 Grotesk / heavy sans

Use for:

- product/page titles;
- major assessment/finding/report headings;
- strong outcome statements.

Typical weight: `700–900`.

### 3.2 Monospace / typewriter

This is the dominant technical UI voice. Use for:

- navigation secondary text;
- task/tool rows;
- buttons;
- timestamps and durations;
- state labels;
- form labels;
- metadata;
- code and hashes;
- system/status text;
- composer helper text.

Do not replace this with generic rounded UI typography during local redesigns.

### 3.3 Editorial italic serif

Use sparingly for expressive, high-level statements only, such as an empty-state or assessment-summary line.

Never use it for buttons, fields, tables, status labels, task rows or navigation.

---

## 4. Spacing and density

Use an 8px-oriented scale with 4px for micro-spacing:

```text
4   micro
8   xs
12  compact
16  sm
24  md
32  lg
48  xl
64  section
96  major editorial separation
```

Required defaults:

- normal control gap: `8–12px`;
- standard card padding: `20–24px`;
- large contextual card padding: `28–32px`;
- task/timeline row gap: `12–16px`;
- major conversation-block gap: `24–32px`;
- major section gap: `48–64px`;
- hero/editorial separation: `64–96px` when appropriate.

**Whitespace is intentional.** An agent must not compact the product merely because unused space exists. Prefer one clear idea at a time over simultaneous metrics, filters, tables and secondary panels.

---

## 5. Canonical shell and navigation

### 5.1 Everyday sidebar

The default authenticated sidebar is conversation/task-first:

```text
VULNHUNTER
AI SECURITY ASSESSMENT

[ + New assessment ]

CHATS / TASKS
● current assessment
  Running · 02m 41s
  recent conversation
  recent conversation

Task history
Manage ▸
Settings

User identity / role
```

Rules:

- current/recent chats and tasks are the dominant content;
- `Manage` progressively discloses specialist/governance areas that the current role may access;
- specialist areas may also open contextually from chat;
- role filtering remains backend-backed;
- do not permanently dump every product subsystem into the everyday sidebar.

Repository-backed specialist capabilities may include Authorizations, Findings, Review Queue, Adjudications, Campaigns, Releases, Datasets, Analysis Services, Audit Log and Reports. Their existence does **not** require equal permanent sidebar prominence.

### 5.2 Top bar

The workspace header follows a compact task structure:

- sidebar/menu trigger;
- breadcrumb/current task title;
- Refresh/reconnect action;
- truthful runtime/status indicator when available;
- compact overflow menu.

Do not add fictional model selectors, account tiers or providers merely because a visual reference contains them.

### 5.3 Login

Use the repository-backed local authentication contract. Current canonical controls are username, password and **`Sign in securely`**. Do not add GitHub SSO or other login methods without backend support and an explicit product decision.

---

## 6. Chat-first contextual surfaces

Render product state in the conversation before forcing navigation elsewhere.

Examples:

- finding → in-chat finding card → optional `Open full finding`;
- report → in-chat report-ready card → optional deep view/download;
- authorization required → inline authorization requirement/action;
- plan approval required → inline approval card or governed specialist decision surface;
- Source Hunt → inline exact setup/approval requirements, with specialist view only when needed;
- APK upload → inline upload/integrity/task state;
- worker recovery/failure → inline persisted state and safe action;
- evidence → summary in chat; large evidence may open a contextual drawer/deep view.

Cards display backend state. They never own authority.

---

## 7. Task execution state system

Use one coherent state language across website, source, APK and specialist workflows.

Canonical visible states:

```text
✓  completed
◌  running
○  pending
Ⅱ  blocked / approval required
↻  recovering
!  failed
×  cancelled
```

Equivalent accessible icons are allowed; semantics must remain consistent.

A task row normally contains:

- state icon;
- concise action label;
- one short technical/status line when useful;
- truthful elapsed time/duration when persisted or derivable from authoritative timestamps;
- expand/collapse control for details.

Do not invent multiple unrelated spinner, progress or completion systems.

### 7.1 Running behaviour

While a task runs:

- the composer remains enabled;
- the user may type and submit a next instruction;
- the submitted follow-up is visibly marked `Queued` until it can be processed;
- refresh means **reconnect/reconstruct**, never restart;
- leaving the page does not imply cancellation;
- returning reconstructs persisted state from authoritative stores;
- Cancel is visible only when the backend supports it;
- **Pause must not appear unless an operator-pause backend contract is implemented.**

Never display a browser-only timer or progress percentage as if it were authoritative worker progress.

### 7.2 Recovery

Worker interruption is not automatically terminal. When persisted state supports recovery, show a calm recovery state such as:

```text
Worker interrupted — recovering task
Persisted state preserved
Restoring execution context…
```

If recovery is impossible, preserve completed steps and show a terminal failure with the safe repository-backed next actions.

---

## 8. Approvals, authorization and confirmation

Required human decisions must be impossible to miss but should remain within the task flow.

Inline decision cards use:

- exact target/object identity;
- exact scope/action summary;
- reason the decision is required;
- backend-supported actions only;
- clear terminal result after the decision.

Approval completion should update the same card/timeline and allow execution to continue automatically when the backend permits.

Authorization, confirmation, approval, review and adjudication are distinct concepts. Do not merge them into one generic `Approve` interaction.

---

## 9. Findings, evidence and reports

### Findings

Prefer spacious stacked cards over dense dashboard grids. A finding card should prioritize:

1. severity/state;
2. finding title;
3. concise explanation;
4. evidence/confidence/provenance summary;
5. one or two relevant next actions.

### Evidence

Large evidence opens in a contextual drawer or specialist view. Preserve request/response, file/line, artifact, provenance, timestamp and integrity information without dumping all technical detail into the base conversation.

### Reports

A generated report first appears as an in-chat result with its assessment identity and integrity/provenance summary. A separate report page is a deep view, not a competing workflow.

---

## 10. Dropdowns, dialogs and overlays

Canonical overlay geometry:

- cream surface;
- `1px` technical border;
- radius `0–3px`;
- `4–6px` hard black offset shadow;
- `24px` standard internal padding;
- monospace controls and labels;
- dusty pink primary/destructive action where appropriate;
- simple backdrop dimming only.

Menus originate from their trigger. Dialogs preserve focus and support keyboard/Back/Escape behaviour defined by the accessibility contract.

---

## 11. Responsive contract

Desktop and mobile are the **same product system**.

### Desktop

- sidebar target width: approximately `260–300px`;
- conversation/workspace owns the remaining width;
- keep the main reading column comfortable rather than stretching every card edge-to-edge;
- contextual evidence/details may open beside the conversation.

### Mobile

- sidebar becomes a MonkeyCode-style overlay drawer;
- the workspace remains chat/task-first;
- cards stack vertically and approach full available width;
- do not shrink desktop tables into unreadable miniatures;
- approvals/authorization/evidence convert to full-width cards, sheets or deep views;
- composer remains reachable during running work;
- 44px minimum touch targets;
- dotted surface, square geometry, hard shadows and typography remain intact.

Do not redesign mobile as a separate bottom-tab dashboard unless an explicit product change approves it.

---

## 12. Motion and feedback

Motion is subordinate to state truth.

- use restrained motion for acknowledgement, disclosure and spatial continuity;
- never animate to imply work that the backend has not confirmed;
- no perpetual decorative motion;
- respect `prefers-reduced-motion`;
- loading should preserve layout rather than cause jumping;
- queued/running/recovering states should update stable components in place.

`docs/product/PREMIUM_INTERACTION_MOTION_AND_CONVERSATION_EXPERIENCE.md` owns detailed motion semantics but may not override this visual contract.

---

## 13. Explicit prohibitions

Agents and developers must not introduce, without an explicit approved product change:

- generic blue/white SaaS styling;
- glassmorphism, glow or decorative gradients;
- large rounded cards as the default language;
- random local spacing/radius/shadow systems;
- dashboard KPI walls in the primary workspace;
- every backend module as permanent navigation;
- unsupported SSO;
- fictional model/provider selectors;
- fictional `Pause` controls;
- fake task percentages or browser-owned operational truth;
- reference-product branding such as MonkeyCode/Threxa;
- `Projects` or account-tier concepts copied from references when not repository-backed;
- hidden reasoning or chain-of-thought display;
- page-local design variants that bypass shared tokens/components.

---

## 14. Agent implementation requirement

Before modifying frontend code, every agent must:

1. read this entire file;
2. read `docs/design/references/manifest.json`;
3. read `docs/product/CHAT_FIRST_WORKSPACE.md`;
4. inspect the existing shared tokens/components before adding CSS or markup;
5. inspect the repository-backed route/action/state contract for the affected surface;
6. preserve backend behaviour, authorization and state truth;
7. reuse shared tokens/primitives instead of inventing local variants;
8. implement loading, blocked, failure, recovery, empty and mobile states where affected;
9. verify desktop and mobile behaviour;
10. report any required deviation before implementing it.

A UI change that violates this contract is a **regression even if it is functionally correct**.

---

## 15. Reference-image rule

Only images marked `CANONICAL` or `PARTIAL_REFERENCE` in `docs/design/references/manifest.json` may guide implementation.

For `PARTIAL_REFERENCE` images, agents must obey every `ignore` entry. A visual reference containing sample branding, model names, project concepts, account tiers or unsupported controls must never override repository truth.

The reference images demonstrate composition and interaction states. This document defines the invariant rules behind them.
