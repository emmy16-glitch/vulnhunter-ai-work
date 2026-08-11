# VulnHunter AI Agent UI Implementation Standard

**STATUS: BINDING — AGENT EXECUTION STANDARD**  
**Applies to:** Codex, Cline, Claude Code, Copilot, Cursor, ChatGPT coding agents, local coding agents, human developers, and any automated process that changes VulnHunter browser UI  
**Canonical visual contract:** `docs/design/VULNHUNTER_UI_CONTRACT.md`  
**Canonical workflow contract:** `docs/product/CHAT_FIRST_WORKSPACE.md`

This document exists because a correct backend can still be presented through a poor, contradictory, dashboard-first UI. That is a product regression. Agents are not allowed to improvise the product's interface from existing markup, old screenshots, generic dashboard instincts, or whichever CSS file happens to be easiest to patch.

---

## 1. Non-negotiable product model

VulnHunter is an **AI-first, conversation-controlled security workspace**.

It is **not**:

- an admin dashboard with a chatbot added;
- a KPI wall;
- a collection of independent backend-module pages;
- a generic SOC console;
- a cyberpunk terminal UI;
- a blue-and-white SaaS dashboard;
- a desktop dashboard squeezed into a phone viewport.

The default experience is:

```text
conversation / attachment
→ exact governed interpretation
→ required authorization / confirmation / approval
→ persisted task execution
→ live truthful task state
→ tool receipts / evidence / findings / recommendations
→ contextual deep view only when more room or identity-bound action is required
```

The conversation and its task timeline are the centre of gravity. Specialist pages are supporting deep views of the same persisted state.

---

## 2. Mandatory authority order

Before any UI change, read and obey these sources in this exact order:

1. repository-root `AGENTS.md` — security, authorization and engineering truth;
2. `vulnhunter/web/AGENTS.md` — web-specific agent rules;
3. `docs/design/VULNHUNTER_UI_CONTRACT.md` — canonical visual and interaction contract;
4. **this file** — exact implementation discipline and rejection criteria;
5. `docs/design/references/manifest.json` — approved reference usage and mandatory ignore rules;
6. `docs/design/DEPRECATIONS.md` — patterns that must not be revived;
7. `docs/product/CHAT_FIRST_WORKSPACE.md` — workflow semantics;
8. `docs/product/UI_ACCEPTANCE_CRITERIA.md`;
9. `docs/product/RESPONSIVE_AND_ACCESSIBILITY.md`;
10. repository-backed routes, actions, persisted states, permissions, tests and shared primitives.

When another document disagrees with this order, the higher source wins.

### Existing implementation is never design authority

Current templates, CSS, JavaScript and tests may encode implementation debt. They are evidence of what exists, not permission to preserve a bad composition.

If existing code conflicts with the locked contract:

- preserve backend behavior and security boundaries;
- replace or refactor the contradictory presentation;
- update tests that encode the deprecated presentation;
- do **not** weaken the contract to make the old markup easier to keep.

---

## 3. Reference hierarchy — exact roles

The three design influences have different jobs. Agents must not blend their responsibilities arbitrarily.

### 3.1 MonkeyCode — structural interaction reference

MonkeyCode is the primary reference for **workspace structure and task behavior**, including:

- compact chat/task sidebar;
- `+ New assessment` entry point;
- current running task prominence;
- recent chats/tasks;
- task history;
- task title + status + elapsed duration;
- running-operation timeline;
- queued follow-up instructions;
- reconnect / restore behavior;
- contextual task controls;
- mobile overlay drawer;
- task-oriented rather than dashboard-oriented navigation;
- persistent composer while work is running.

Do not copy MonkeyCode branding, account tiers, provider names, model names, Projects terminology, unsupported controls, or sample content.

### 3.2 Beautiful UI — AI-native component and microinteraction reference

`https://beautiful-ui-five.vercel.app/` is the component-interaction reference for making VulnHunter feel like a polished AI product.

Use the patterns below only when backed by real VulnHunter state:

| Beautiful UI pattern | VulnHunter use |
|---|---|
| Loading State | bounded preparation, upload verification, worker startup, state restoration |
| Thinking | safe user-facing activity summary only; never hidden chain-of-thought |
| Streaming Text | assistant response streaming where supported |
| Approval Card | immutable plan confirmation, source-processing approval, controlled-validation decisions |
| Tool Chips | tool receipts, provenance, tool state, duration and evidence links |
| Task Rows | persisted assessment stages and task graph projection |
| Chat | primary assessment workspace |
| Prompt Bar | primary persistent composer |
| Recommendation Card | remediation recommendation or safe next action |
| Context Cards | evidence, file/line source references, request/response, proof capsule, provenance |
| Diff Table | proposed remediation/source changes when repository-backed |
| Records Table | specialist/deep views such as findings or authorization records |
| Filter Table | deep-view filtering, never a replacement for the conversation |
| Sidebar Nav | compact task/chat shell patterns |
| Search | task/history/finding/evidence search when backed by existing capability |
| Insight Cards | only real persisted insights; never decorative KPI cards |
| Code Block | source evidence, bounded code excerpts, remediation snippets |
| Selection Actions | only actions actually supported for selected evidence/code/text |

Do **not** implement a Fine-tune Card, fictional model selector, provider selector, dictation control, command palette action, or sample Beautiful UI function merely because the reference contains it. Product capability must already exist and be authorized by repository contracts.

### 3.3 VulnHunter visual language — identity and styling

The canonical VulnHunter visual language is the warm editorial system:

- warm cream/off-white canvas; historical approved reference around `#F7F3EE`, repository canonical token `--vh-canvas: #f5f2ec`;
- subtle dotted/graph-paper texture;
- dusty pink primary/accent state;
- near-black text and technical borders;
- compact dark sidebar;
- bold grotesk headings;
- monospace/typewriter technical metadata and controls;
- square or nearly-square geometry;
- hard black zero-blur offset shadows;
- generous whitespace;
- restrained semantic green/warning/danger colors only for truthful state.

Beautiful UI does **not** override this palette, geometry, typography or shadow system.

---

## 4. Canonical desktop composition

The everyday desktop Assessment Workspace must follow this conceptual composition:

```text
┌──────────────────┬──────────────────────────────────────────┬───────────────────┐
│ VULNHUNTER       │ current task / breadcrumb          ⋯     │ contextual detail │
│ AI SECURITY      ├──────────────────────────────────────────┤ drawer             │
│                  │                                          │                   │
│ + New assessment │ conversation                             │ only when opened   │
│                  │                                          │                   │
│ CHATS / TASKS    │ user request                             │ evidence           │
│ ● current target │                                          │ finding            │
│   Running · 02:41│ VulnHunter response                      │ approval detail    │
│   recent task    │                                          │ tool receipt       │
│   recent task    │ ✓ Authorization                          │ source file        │
│                  │ ✓ Plan                                   │                   │
│ Task history     │ ◌ Nuclei assessment                      │                   │
│ Manage ▸         │ ○ Verification                           │                   │
│ Settings         │                                          │                   │
│                  │ [Nuclei ✓] [HTTP ✓] [Evidence 3]        │                   │
│ user / role      │                                          │                   │
│                  │ ┌──────────────────────────────────────┐ │                   │
│                  │ │ Ask VulnHunter…                  ➜   │ │                   │
│                  │ └──────────────────────────────────────┘ │                   │
└──────────────────┴──────────────────────────────────────────┴───────────────────┘
```

Rules:

- sidebar is the stable everyday navigation surface;
- conversation owns the main width;
- a right-hand contextual drawer is **closed by default** and opens only for detail;
- do not create a permanent metrics rail;
- do not create a permanent row of global action buttons below the page title;
- do not display four large state cards merely to repeat Authorization / Scope / Approval / Active;
- state belongs in the task flow and compact task header where relevant;
- the composer remains visually anchored and reachable.

---

## 5. Canonical mobile composition

Mobile is not a compressed desktop dashboard. It is a one-column AI task workspace.

```text
┌─────────────────────────────────┐
│ ☰   target / task title      ⋯  │
├─────────────────────────────────┤
│ Running · 02:41                 │
│                                 │
│ ✓ Authorization verified        │
│ ✓ Passive plan prepared         │
│ ◌ Nuclei assessment             │
│ ○ Evidence normalization        │
│ ○ Verification                  │
│                                 │
│ VulnHunter                      │
│ I found two candidate issues…   │
│                                 │
│ [Nuclei ✓] [HTTP ✓]             │
│                                 │
│ finding / approval / context    │
│ card when relevant              │
│                                 │
├─────────────────────────────────┤
│ +  Ask VulnHunter…          ➜   │
└─────────────────────────────────┘
```

The hamburger opens the task drawer:

```text
VULNHUNTER

+ New assessment

CHATS / TASKS
● current target
  Running · 02:41

APK assessment
Completed

Source Hunt
Blocked · approval

Task history
Manage ▸
Settings

user / Security Analyst
```

Mobile requirements:

- no horizontal page scrolling at supported phone widths;
- no desktop toolbar squeezed into one line;
- no clipped buttons such as `New wo…`;
- no four-column/four-card desktop grids reduced to tiny cards;
- no unreadably small body copy;
- primary body copy should normally render at approximately `15–17px` on phone;
- critical controls use at least `44px` touch targets;
- the composer must remain usable without obscuring the active content;
- details become full-width cards, drawers, sheets or dedicated deep views;
- sidebar becomes an overlay drawer rather than a narrow permanent desktop rail;
- phone screenshots are a required acceptance artifact for meaningful UI changes.

---

## 6. Canonical conversation anatomy

A healthy VulnHunter conversation uses a small set of durable primitives rather than arbitrary cards.

### User message

Clean text block with optional attachment reference. Avoid oversized rounded chat bubbles.

### Assistant message

Readable prose with optional structured objects below it. Assistant text must remain high-contrast and readable; do not use near-white text on a cream background.

### Task group

A single stage list projects persisted task state:

```text
✓ Check authorization
✓ Prepare immutable plan
Ⅱ Waiting for confirmation
○ Queue worker
○ Normalize evidence
○ Deterministic verification
```

Only one visual state system is allowed.

### Tool receipts

Tool chips summarize real execution/provenance:

```text
[Nuclei ✓ 14.2s] [HTTP probe ✓] [Evidence normalizer ◌]
```

Expanding a chip may show version, start/end, worker identity, policy, exit state, evidence count and digest if those values are actually available.

### Context/evidence card

Shows the minimum useful evidence and provenance, then allows a deeper view.

### Finding card

Prioritizes severity/state, finding title, concise explanation, evidence/provenance count and one or two relevant actions.

### Approval/confirmation card

Shows the exact object, exact requested action, reason the decision is needed, and backend-supported decision controls. Do not reduce all decision types to a generic `Approve` button.

### Recommendation card

May show a remediation or safe next step. It is advisory, not authority.

---

## 7. Safe “Thinking” and streaming behavior

VulnHunter may show **user-facing activity**, not private reasoning.

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
- fake percentages;
- animated “thinking” that implies backend work not actually occurring.

If streaming is supported, stream the answer text. Do not expose hidden reasoning tokens.

---

## 8. Source Hunt interaction contract

Source Hunt must not default to a giant standalone admin form.

Preferred flow:

```text
User: Review this repository.

VulnHunter
Source Hunt
Repository: /workspaces/project
Revision: abc123…

✓ Repository root resolved
✓ Eligible snapshot created
Ⅱ Exact source-processing approval required

[Review source-processing approval]
```

A specialist Source Hunt deep view may collect exact root/revision/permitted paths, re-authentication and attestations when required. It should feel like a focused continuation of the same task, not a separate dark dashboard product.

The result must project back into the originating conversation.

---

## 9. APK/mobile-analysis interaction contract

APK analysis begins from the conversation attachment flow.

Expected stages may include, only where backed by real state:

```text
✓ Upload complete
✓ SHA-256 verified
◌ Static analysis
  [AAPT ✓] [JADX ✓] [Apktool ✓]
○ Evidence normalization
○ Verification
```

Never imply that uploading an APK executed it. Dynamic execution remains separately governed.

---

## 10. Approval and authorization interaction contract

The interface must distinguish:

- authorization existence/scope;
- owner confirmation of an immutable low-risk plan;
- independent approval;
- step-up authentication;
- human review;
- adjudication.

Example exact-plan confirmation:

```text
Confirmation required

Passive assessment plan
Target       10.0.0.12
Port         443
Scanner      Nuclei
Profile      Passive
Rate limit   1
Concurrency  1
Plan digest  abcd…

[Cancel]                         [Confirm and continue]
```

An independent approval may require a separate governed actor and must not be visually mislabeled as the same kind of confirmation.

---

## 11. Search, history and utility controls

Utility actions must not become a giant toolbar competing with the task.

Preferred placement:

- search: compact top-bar icon or command/search surface;
- history: sidebar/task history or compact drawer trigger;
- export/report: contextual action after a relevant persisted result exists;
- Source Hunt: contextually initiated from chat or available through progressive disclosure;
- new workspace: prominent `+ New assessment` in sidebar/drawer and an optional compact task-menu action.

Do not render a horizontal page-header row containing `Source Hunt / Search / Export / History / New workspace` as the default mobile or desktop composition.

---

## 12. Explicitly rejected current-implementation patterns

The following patterns are implementation debt and must **not** be preserved merely because they currently exist:

1. four large top state cards for `Authorization`, `Scope`, `Approval`, `Active` on the ordinary conversation page;
2. a wide row of page-level utility buttons directly below the workspace title;
3. giant empty conversation canvases caused by sparse content being vertically detached from the composer;
4. tiny, low-contrast assistant text on cream backgrounds;
5. blue-glow shield/orb decoration that contradicts the locked warm editorial identity;
6. dark dashboard panels used for ordinary Source Hunt/workspace composition;
7. `Runs / Scanner / Execution / Entry point` KPI-style cards as the primary assessment history experience;
8. a giant Source Hunt form as the primary way a user starts source analysis;
9. multiple competing navigation systems simultaneously visible;
10. desktop layouts mechanically squeezed onto phones;
11. clipped or horizontally overflowing header controls;
12. giant areas of unused space while essential task state is tiny;
13. dashboard cards that merely restate backend fields without helping the current task;
14. page-specific style overrides that fight the canonical tokens;
15. adding another stylesheet at the end of the cascade simply to override earlier contradictory styles.

An agent seeing these patterns should treat them as candidates for removal/refactor, not visual precedent.

---

## 13. CSS and presentation architecture

The repository currently contains several historical UI stylesheets. Agents must reduce drift rather than add more override layers.

Rules:

- prefer canonical tokens from `tokens.css`;
- prefer a small set of shared workspace primitives;
- consolidate contradictory selectors rather than append `!important` patches;
- do not create a new global stylesheet solely to override an existing global stylesheet;
- avoid route-specific color/radius/shadow systems;
- page-specific CSS may arrange product-specific content but must consume shared design tokens/primitives;
- remove dead/deprecated styles when safely replacing a surface;
- preserve CSP requirements and no-inline-script rules;
- use shared DOM/state contracts instead of duplicate browser state machines;
- avoid duplicated responsive rules scattered across many files for the same component.

Before adding CSS, the agent must identify which existing stylesheet owns the component and explain why a new rule belongs there.

---

## 14. Readability and density requirements

The visual direction is spacious, but “spacious” does not mean “empty and tiny.”

- readable conversation column: approximately `680–900px` depending on surrounding panels;
- ordinary desktop body text: generally `14–16px`;
- ordinary phone body text: generally `15–17px`;
- metadata may be smaller but must remain legible and high contrast;
- avoid long lines stretching across the entire browser;
- do not create huge blank vertical regions between a short message and the composer;
- use whitespace to separate ideas, not to hide low information density;
- technical data should progressively disclose rather than shrink.

---

## 15. State truth requirements

Every visible status must be derived from persisted/backend truth or an explicitly non-authoritative local interaction state.

Never fabricate:

- scan progress percentage;
- finding count;
- evidence count;
- approval state;
- authorization state;
- worker readiness;
- tool success;
- provider readiness;
- elapsed execution data that cannot be derived reliably;
- completion;
- recovery success.

Unknown is displayed as unknown/unavailable, not replaced with a pleasant-looking number.

---

## 16. Required visual states

When the affected feature can reach these states, design and test them:

- initial/empty;
- composing;
- uploading;
- validating upload integrity;
- understanding request;
- authorization missing;
- authorization found;
- confirmation required;
- independent approval required;
- queued;
- running;
- follow-up queued;
- tool running;
- evidence available;
- finding available;
- recovering;
- failed safely;
- cancelled;
- completed;
- provider unavailable / deterministic fallback;
- permission denied;
- reconnect/restored state.

Do not build only the ideal screenshot.

---

## 17. Required responsive viewports

At minimum, meaningful workspace changes must be checked at representative widths close to:

- `360px` phone;
- `390px` phone;
- `412px` phone;
- `768px` tablet;
- `1024px` compact desktop/tablet landscape;
- `1280px` desktop;
- `1440px` desktop.

Acceptance does not require pixel-identical screenshots, but it requires the same product hierarchy and no broken layout.

Immediate failure conditions include:

- any essential horizontal page scroll on phone;
- clipped primary controls;
- unreadable text;
- composer outside the viewport/reachability contract;
- desktop sidebar permanently occupying phone width;
- approval controls inaccessible without horizontal scrolling;
- evidence/code causing uncontrolled viewport overflow;
- a header action row wider than the phone.

---

## 18. Required screenshot / browser evidence

For significant UI work, the agent must provide browser evidence for applicable states, not merely unit tests.

Minimum recommended evidence set:

1. login on phone;
2. empty/new workspace on phone;
3. mobile drawer open;
4. running assessment on phone;
5. approval/confirmation required on phone;
6. finding/evidence context on phone;
7. empty/new workspace desktop;
8. running task desktop;
9. contextual drawer desktop;
10. Source Hunt initiation;
11. APK attachment state when changed;
12. recovery/failure state when changed.

The agent must compare the result against the canonical contract, not merely verify that the browser rendered without exceptions.

---

## 19. Agent pre-edit checklist

Before editing, an agent must be able to answer:

- What is the current user task?
- Does this belong in conversation, sidebar, contextual drawer, or specialist deep view?
- Which MonkeyCode structural pattern applies?
- Which Beautiful UI primitive applies, if any?
- Which VulnHunter backend state powers it?
- Which existing shared primitive/style owner should be changed?
- What must disappear from the current UI rather than be preserved?
- What happens on a 360–412px phone?
- What are the blocked/error/recovery states?
- What security/authority boundary must remain backend-owned?

If these questions cannot be answered, the agent should inspect more code/docs before writing UI code.

---

## 20. Agent definition of done

UI work is not complete until all applicable statements are true:

- the primary experience is still conversation/task-first;
- no deprecated dashboard pattern was reintroduced;
- MonkeyCode structural rules were followed where relevant;
- Beautiful UI primitives were adapted rather than visually copied wholesale;
- VulnHunter cream/dotted/pink/dark-sidebar identity remains intact;
- desktop and phone have the same hierarchy;
- no horizontal phone overflow exists;
- text remains legible;
- the composer remains usable during running work;
- queued follow-ups behave truthfully where supported;
- contextual detail opens only when needed;
- state is backend-derived;
- security/authorization/approval authority was not moved into browser code;
- shared tokens/primitives were used;
- CSS override debt was not increased;
- real browser checks were performed for changed critical flows;
- relevant automated tests pass;
- remaining limitations are reported explicitly.

A result that technically works but looks like a generic dashboard is **not done**.

A result that resembles a reference screenshot but invents unsupported product behavior is **not done**.

A result that looks good on desktop but is clipped, tiny or horizontally scrolling on phone is **not done**.
