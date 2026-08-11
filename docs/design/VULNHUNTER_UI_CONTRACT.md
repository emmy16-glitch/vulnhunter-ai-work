# VulnHunter UI Contract

**STATUS: LOCKED — CANONICAL PRODUCT UI CONTRACT (V2)**  
**Applies to:** every authenticated and unauthenticated VulnHunter browser surface, desktop and mobile  
**Change policy:** deliberate product-design change only; incidental frontend work must not reinterpret this contract  
**Agent implementation standard:** `docs/design/AI_AGENT_UI_IMPLEMENTATION_STANDARD.md`

---

## 0. Authority

This file is the visual and interaction source of truth for VulnHunter.

When sources disagree, use this order:

1. `AGENTS.md` and backend security/authorization contracts for security truth;
2. this UI contract for product interaction and visual language;
3. `docs/design/AI_AGENT_UI_IMPLEMENTATION_STANDARD.md` for implementation discipline and rejection criteria;
4. `docs/design/references/manifest.json` and its approved references;
5. `docs/design/DEPRECATIONS.md` for retired/currently rejected presentation patterns;
6. `docs/product/CHAT_FIRST_WORKSPACE.md` for workflow meaning;
7. `docs/product/UI_ACCEPTANCE_CRITERIA.md` and responsive/accessibility requirements;
8. shared VulnHunter tokens/components;
9. existing page implementation and tests;
10. agent or developer preference — **never authoritative**.

A visual reference is not permission to invent product functionality. The repository remains authoritative for routes, actions, fields, providers, models, roles, authorization, approval, review, evidence and execution capability.

### Existing implementation is not design authority

Current templates, CSS, JavaScript and tests may contain known UI debt. When they conflict with this contract, preserve functional/security behavior and replace the contradictory presentation. Do not weaken this contract to preserve old markup or a stale visual test.

---

## 1. Product principle

> **VulnHunter is a security workspace controlled through conversation. It is not an admin dashboard with a chatbot attached.**

The conversation/task workspace is the primary operating surface. Findings, evidence, reports, approvals, authorization requirements, Source Hunt setup, APK uploads, tool receipts, failure/recovery and review status appear contextually in the task/conversation first when practical.

Dedicated pages remain valid when more room, complex inspection, step-up authentication or identity-bound governance is genuinely required. They are **deep views of the same persisted state**, not competing workflows.

Do not turn every backend subsystem into permanent top-level navigation.

---

## 2. Reference hierarchy

The references have deliberately separate roles.

### 2.1 MonkeyCode — structure and task interaction

MonkeyCode is the primary interaction/layout reference for:

- task/chat-first sidebar composition;
- `+ New assessment` hierarchy;
- current running task prominence;
- recent chats/tasks;
- task history;
- running-operation timeline;
- queued follow-up instructions;
- reconnect/restoration behavior;
- persistent composer during running work;
- contextual task controls;
- mobile overlay drawer.

MonkeyCode does **not** define VulnHunter branding, colors, account tiers, provider/model names, Projects terminology or security capability.

### 2.2 Beautiful UI — AI-native component behavior

`https://beautiful-ui-five.vercel.app/` is the component/microinteraction reference for:

- loading states;
- safe user-facing activity / “thinking” indication;
- streaming assistant text;
- approval-card hierarchy;
- tool chips;
- task rows;
- chat presentation;
- prompt/composer ergonomics;
- recommendation cards;
- context/evidence cards;
- code blocks and diffs;
- search;
- specialist records/filtering patterns;
- selection actions when supported.

Beautiful UI does **not** define VulnHunter colors, radius system, branding, sample data, providers/models or supported functionality.

“Thinking” never means hidden chain-of-thought. VulnHunter may show safe activity such as `Checking authorization…`; private reasoning is never rendered.

### 2.3 VulnHunter — product identity and actual truth

VulnHunter owns:

- security and authorization boundaries;
- actual product capability;
- terminology;
- routes/actions;
- persisted state;
- evidence/findings;
- all human authority;
- the warm cream/dotted/dusty-pink/dark-sidebar visual identity defined below.

Reference interpretation details and mandatory ignore rules live in `docs/design/references/manifest.json`.

---

## 3. Locked visual language

### 3.1 Core palette

Canonical design tokens:

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

The earlier approved warm editorial reference used a cream around `#F7F3EE`; this is supporting visual provenance, not permission for page-local palette drift. Implementation must consume the canonical token system.

Rules:

- cream/off-white is the main working canvas;
- near-black is the dominant text and border color;
- dusty pink is the primary active/accent color;
- the compact sidebar is dark and task-focused;
- green is restrained and reserved for genuine success/completion;
- warnings/errors use muted earth/rose tones rather than neon red;
- no generic blue-and-white SaaS theme;
- no neon cyberpunk palette;
- blue glow is not a VulnHunter identity device.

### 3.2 Dotted canvas

The working surface uses one subtle graph-paper/dotted texture:

```css
background-color: var(--vh-canvas);
background-image: radial-gradient(circle, var(--vh-dot) 1px, transparent 1px);
background-size: 22px 22px;
```

Do not create page-specific dot scales, high-contrast dots or decorative grid variants.

### 3.3 Geometry

- Default cards and controls are square or nearly square.
- Default radius: `0–3px`.
- Status chips may use a small pill radius only when compact status semantics benefit from it.
- Large rounded SaaS cards, bubbly chat balloons and excessive pills are prohibited.

### 3.4 Shadows

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
- decorative gradients.

Overlays may dim the background, but the overlay panel remains crisp and square.

---

## 4. Typography contract

VulnHunter has three typography roles.

### 4.1 Grotesk / heavy sans

Use for:

- product/page titles;
- major assessment/finding/report headings;
- strong outcome statements.

Typical weight: `700–900`.

### 4.2 Monospace / typewriter

This is the dominant technical UI voice. Use for:

- navigation secondary text;
- task/tool rows;
- buttons where the technical/editorial system calls for it;
- timestamps and durations;
- state labels;
- form labels;
- metadata;
- code and hashes;
- system/status text;
- composer helper text.

Do not replace this with generic rounded UI typography during local redesigns.

### 4.3 Editorial italic serif

Use sparingly for expressive, high-level statements only, such as an empty-state or assessment-summary line.

Never use it for buttons, fields, tables, task rows or navigation.

### 4.4 Readability floor

The design is technical but not microscopic.

- ordinary desktop body copy should generally remain around `14–16px`;
- ordinary phone body copy should generally remain around `15–17px`;
- secondary metadata may be smaller but must remain clearly legible;
- assistant text on the cream canvas must have strong contrast;
- do not use extreme light opacity for ordinary message content.

---

## 5. Spacing and density

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
- major section gap: `48–64px`.

**Whitespace is intentional, but whitespace must be purposeful.** Do not compact the product merely because unused space exists. Equally, do not create giant empty vertical regions while task state and assistant content are tiny. Prefer one clear idea at a time.

---

## 6. Canonical shell and navigation

### 6.1 Everyday desktop sidebar

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

- current/recent chats and tasks dominate;
- `Manage` progressively discloses specialist/governance areas the current role may access;
- specialist areas may also open contextually from chat;
- role filtering remains backend-backed;
- do not permanently dump every subsystem into the everyday sidebar.

Repository-backed specialist capabilities may include Source Hunt, Authorizations, Findings, Review Queue, Adjudications, Campaigns, Releases, Datasets, Analysis Services, Audit and Reports. Their existence does **not** require equal permanent sidebar prominence.

### 6.2 Top bar

The workspace header follows a compact task structure:

- sidebar/menu trigger where required;
- current task/breadcrumb title;
- truthful compact runtime/reconnect status when useful;
- compact overflow/menu trigger.

Search may be a compact utility control when repository-backed.

Do not create a default wide action strip competing with the task.

### 6.3 Login

Use the repository-backed local authentication contract. Current canonical controls are username, password and **`Sign in securely`**. Do not add unsupported SSO because a reference contains it.

---

## 7. Canonical desktop workspace composition

Conceptual layout:

```text
┌──────────────────┬──────────────────────────────────────────┬───────────────────┐
│ task/chat sidebar│ current task / conversation              │ contextual detail │
│                  │                                          │ only when opened  │
│ + New assessment │ user and assistant messages              │                   │
│ current task     │ task rows                                │ evidence          │
│ recent tasks     │ tool chips                               │ finding           │
│ history          │ contextual cards                        │ tool receipt      │
│ Manage/Settings  │                                          │ source/code       │
│ user/role        │ persistent composer                      │                   │
└──────────────────┴──────────────────────────────────────────┴───────────────────┘
```

Rules:

- conversation owns the main width;
- right contextual detail is closed by default;
- no permanent metrics rail;
- no four-card state strip merely restating backend nouns;
- no wide utility-button row under the title;
- reading width remains comfortable rather than every card stretching edge-to-edge;
- the composer is visually anchored and reachable.

---

## 8. Canonical mobile workspace composition

Mobile is a **one-column AI task workspace**, not a shrunken desktop dashboard.

```text
☰  current assessment / task                   ⋯

Running · 02:41

✓ Authorization verified
✓ Passive plan prepared
◌ Nuclei assessment
○ Evidence normalization
○ Verification

VulnHunter
Readable assistant response…

[Nuclei ✓] [HTTP ✓] [Evidence]

context / approval / finding when relevant

+  Ask VulnHunter…                           ➜
```

The hamburger opens the task/chat drawer.

Required:

- no essential horizontal page scrolling;
- no desktop toolbar squeezed into one row;
- no clipped `New workspace` or other primary controls;
- no tiny four-card desktop grids;
- body text remains readable;
- critical touch targets are at least approximately `44px`;
- composer remains reachable during running/queued/approval/recovery states;
- evidence/details become full-width cards, drawers, sheets or deep views;
- the desktop sidebar becomes an overlay drawer rather than remaining permanently visible.

Do not redesign mobile as a separate bottom-tab dashboard unless an explicit product change approves it.

---

## 9. Chat-first contextual surfaces

Render product state in the conversation before forcing navigation elsewhere.

Examples:

- finding → in-chat finding card → optional `Open full finding`;
- report → in-chat report-ready card → optional deep view/download;
- authorization required → inline authorization requirement/action;
- plan confirmation → inline exact plan card;
- independent approval → clearly distinct governed decision card/deep view;
- Source Hunt → inline exact setup/approval state;
- APK upload → inline upload/integrity/task state;
- worker recovery/failure → inline persisted state and safe action;
- evidence → summary/context card; large evidence opens a drawer/deep view.

Cards display backend state. They never own authority.

---

## 10. AI-native component contract

VulnHunter adapts AI-native components while preserving its visual system.

### 10.1 Task rows

Use one coherent state language:

```text
✓  completed
◌  running
○  pending
Ⅱ  blocked / approval required
↻  recovering
!  failed
×  cancelled
```

A task row normally contains:

- state icon;
- concise action label;
- one short status/technical line where useful;
- truthful duration only when authoritative/derivable;
- optional disclosure for details.

Do not invent multiple unrelated spinner/progress systems.

### 10.2 Tool chips

Tool chips summarize real execution/provenance, e.g.:

```text
[Nuclei ✓ 14.2s] [HTTP probe ✓] [Evidence normalizer ◌]
```

Expand only to real fields such as tool version, worker, duration, receipt, policy, digest or evidence count.

### 10.3 Context cards

Use for evidence, source references, request/response material, proof capsules and provenance. Show a concise summary first and allow a deeper view.

### 10.4 Finding cards

Prioritize:

1. severity/state;
2. finding title;
3. concise explanation;
4. evidence/provenance/confidence summary where real;
5. one or two relevant actions.

### 10.5 Recommendation cards

May show remediation or a safe next step. They are advisory and may never imply execution/verification authority.

### 10.6 Approval/confirmation cards

Required human decisions must be impossible to miss but remain within the task flow. Show exact object identity, exact action/scope, why the decision is required, and backend-supported actions only.

Authorization, plan confirmation, independent approval, review and adjudication remain distinct concepts.

### 10.7 Safe activity / “Thinking”

Allowed:

```text
Checking authorization…
Preparing bounded passive plan…
Waiting for worker receipt…
Reviewing persisted evidence…
```

Forbidden:

- hidden chain-of-thought;
- private reasoning traces;
- fabricated internal deliberation;
- animation implying work the backend has not confirmed.

### 10.8 Streaming

Where supported, stream user-facing assistant answer text. Do not expose hidden reasoning tokens.

---

## 11. Running task behavior

While a task runs:

- the composer remains enabled unless a real backend restriction requires otherwise;
- the user may type and submit a next instruction;
- a follow-up that cannot execute immediately is visibly marked `Queued` where the backend supports queued follow-ups;
- refresh means **reconnect/reconstruct**, never restart;
- leaving the page does not imply cancellation;
- returning reconstructs persisted state;
- Cancel is visible only when backend cancellation exists;
- **Pause must not appear unless an explicit operator-pause backend contract exists.**

Never display a browser-only progress percentage as authoritative worker progress.

---

## 12. Recovery and failure

Worker interruption is not automatically terminal. When persisted state supports recovery, update the same task surface calmly:

```text
Worker interrupted — recovering task
Persisted state preserved
Restoring execution context…
```

If recovery is impossible:

- preserve completed stages;
- preserve valid evidence;
- show a terminal failure state;
- expose only safe repository-backed next actions.

Cancellation is distinct from failure.

---

## 13. Source Hunt contract

Source Hunt begins in the conversation/task product.

Preferred first-class representation:

```text
Source Hunt
Repository: /workspaces/project
Revision: abc123…

✓ Snapshot created
Ⅱ Exact source-processing approval required

[Review approval]
```

A specialist Source Hunt deep view may collect exact root/revision/permitted paths, re-authentication and attestations when required. It is a focused continuation of the same task, not a giant separate dashboard product.

The result projects back into the originating conversation.

---

## 14. APK/mobile analysis contract

APK analysis begins from conversation attachment.

Expected task projection, only where backed by real state:

```text
✓ Upload complete
✓ SHA-256 verified
◌ Static analysis
  [AAPT ✓] [JADX ✓] [Apktool ✓]
○ Evidence normalization
○ Verification
```

Uploading an APK never means executing it. Dynamic execution remains separately governed.

---

## 15. Search, history, export and utilities

Utilities are subordinate to the active task.

Preferred placement:

- Search → compact top-bar utility or dedicated search interaction;
- History → task sidebar/drawer/history surface;
- Export/report → contextual action only when relevant persisted result exists;
- Source Hunt → initiated in chat/task flow or progressively disclosed;
- New workspace → `+ New assessment` in sidebar/drawer and optional compact task-menu action.

The default UI must **not** render a horizontal row of `Source Hunt / Search / Export / History / New workspace` below the workspace title.

---

## 16. Explicit anti-regression rules

The following patterns are rejected presentation debt and must not be treated as precedent:

1. four large top state cards for `Authorization`, `Scope`, `Approval`, `Active` on the ordinary conversation page;
2. a wide page-level utility-button row below the title;
3. `Runs / Scanner / Execution / Entry point` KPI cards as the primary workspace/history experience;
4. giant dark Source Hunt/admin panels inside the normal conversation flow;
5. a giant Source Hunt form as the primary source-analysis entry point;
6. huge blank vertical regions while task information/message text is tiny;
7. low-contrast assistant text on cream;
8. blue-glow shield/orb decoration that contradicts the warm editorial identity;
9. desktop composition mechanically squeezed onto phone;
10. clipped phone controls or essential horizontal overflow;
11. multiple simultaneously visible competing navigation systems;
12. permanent detail/context panels when nothing is open;
13. dashboard cards that merely expose backend nouns without helping the task;
14. page-local design variants that bypass shared tokens;
15. another late-loaded global CSS file added solely to override prior contradictory UI.

A test or selector asserting one of these patterns does not make it canonical.

---

## 17. CSS/presentation architecture contract

The design system must become simpler over time, not more layered.

- use `tokens.css` as the canonical token source;
- identify the shared component/style owner before adding CSS;
- consolidate contradictory selectors rather than append override layers;
- routine `!important` is not an acceptable design-repair strategy;
- page-specific CSS may arrange domain content but must not redefine palette/radius/shadow/type systems;
- remove dead/deprecated presentation rules when safely replacing a surface;
- avoid duplicating responsive behavior for the same component across many files;
- preserve CSP/no-inline-script requirements.

A new global stylesheet whose only purpose is to “win” cascade order is a regression.

---

## 18. Dropdowns, dialogs, drawers and overlays

Canonical overlay geometry:

- cream surface;
- `1px` technical border;
- radius `0–3px`;
- `4–6px` hard black offset shadow;
- `24px` standard internal padding;
- strong readable technical typography;
- dusty pink primary action where appropriate;
- simple backdrop dimming only.

Menus originate from their trigger. Dialogs/drawers preserve focus and support keyboard/Back/Escape behavior defined by accessibility requirements.

---

## 19. Responsive contract

Desktop and mobile are the **same product system**.

### Desktop

- sidebar target width approximately `260–300px`;
- conversation owns remaining working width;
- keep a comfortable reading column rather than stretching every object edge-to-edge;
- contextual evidence/details may open beside the conversation.

### Mobile

- sidebar becomes a MonkeyCode-style overlay drawer;
- workspace remains chat/task-first;
- cards stack vertically;
- do not shrink desktop tables into unreadable miniatures;
- approvals/authorization/evidence become full-width cards, sheets or deep views;
- composer remains reachable;
- 44px minimum critical touch targets;
- no essential horizontal page scroll;
- the cream dotted surface, square geometry, hard shadows and type hierarchy remain intact.

Representative acceptance widths should include phones near `360`, `390`, `412`, tablet `768`, and desktop `1024`, `1280`, `1440` CSS pixels.

---

## 20. Motion and feedback

Motion is subordinate to state truth.

- use restrained motion for acknowledgement, disclosure and spatial continuity;
- never animate to imply work the backend has not confirmed;
- no perpetual decorative motion;
- respect `prefers-reduced-motion`;
- loading should preserve layout;
- queued/running/recovering states update stable components in place.

Detailed motion documentation may refine timing but may not override this contract.

---

## 21. Explicit prohibitions

Agents and developers must not introduce, without explicit approved product change:

- generic blue/white SaaS styling;
- glassmorphism, glow or decorative gradients;
- large rounded cards as the default;
- random local spacing/radius/shadow systems;
- dashboard KPI walls in the primary workspace;
- every backend module as permanent navigation;
- unsupported SSO;
- fictional provider/model selectors;
- unsupported Fine-tune/dictation controls;
- fictional Pause controls;
- fake percentages or browser-owned operational truth;
- reference-product branding such as MonkeyCode/Threxa/Beautiful UI;
- Projects/account-tier concepts copied from references when not repository-backed;
- hidden reasoning or chain-of-thought display;
- page-local design variants bypassing shared tokens/components;
- CSS patch layers created only to override prior patch layers.

---

## 22. Agent implementation requirement

Before modifying frontend code, every agent must:

1. read this file in full;
2. read `docs/design/AI_AGENT_UI_IMPLEMENTATION_STANDARD.md`;
3. read `docs/design/references/manifest.json`;
4. read `docs/design/DEPRECATIONS.md`;
5. read `docs/product/CHAT_FIRST_WORKSPACE.md`;
6. inspect shared tokens/components before adding CSS or markup;
7. inspect the repository-backed route/action/state contract for the affected surface;
8. identify which MonkeyCode structural pattern applies;
9. identify which Beautiful UI primitive applies, if any;
10. identify deprecated current presentation that should be removed rather than preserved;
11. preserve backend behavior, authorization and state truth;
12. implement affected non-happy-path and mobile states;
13. verify real desktop and phone behavior;
14. report any required deviation before implementing it.

A UI change that violates this contract is a **regression even if it is functionally correct**.

---

## 23. Reference rule

Only references registered in `docs/design/references/manifest.json` may guide implementation as canonical/partial references.

For `PARTIAL_REFERENCE` items, every `ignore` entry is binding. A reference containing sample branding, model names, business concepts, account tiers, unsupported controls or contradictory styling must never override VulnHunter truth.

The manifest describes what may be borrowed. This document defines the invariant product system.

---

## 24. Definition of visual done

A UI change is not complete unless all applicable statements hold:

- the product is still conversation/task-first;
- the shell follows the compact task/chat model;
- MonkeyCode influenced structure, not branding/functionality;
- Beautiful UI primitives were adapted, not copied wholesale;
- VulnHunter cream/dotted/dusty-pink/dark-sidebar identity remains intact;
- current deprecated dashboard patterns were not preserved/reintroduced;
- assistant/body text is readable;
- no essential phone overflow/clipping exists;
- the composer remains reachable and truthful;
- state comes from backend/persisted truth;
- details progressively disclose rather than crowd the base workspace;
- CSS override debt did not increase;
- real browser desktop + phone checks were performed for meaningful UI work;
- relevant acceptance criteria pass.

A generic dashboard result is **not done**. A reference-looking UI with invented functionality is **not done**. A desktop-only result is **not done**.
