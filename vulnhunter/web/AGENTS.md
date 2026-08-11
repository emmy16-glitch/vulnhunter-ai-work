# VulnHunter Web — Frontend Agent Rules

**STATUS: BINDING FOR EVERY FILE UNDER `vulnhunter/web/`**

These rules apply to Codex, Cline, Claude Code, Copilot, Cursor, ChatGPT coding agents, local agents, automated refactoring tools and human developers.

The purpose of this file is to prevent a functionally correct backend from being wrapped in a contradictory, dashboard-first, unreadable or generic UI.

## 1. Mandatory read order

Before changing templates, CSS, JavaScript, navigation, forms, dialogs, responsive layout, copy, task state, conversation rendering or browser interaction, read in this exact order:

1. repository-root `AGENTS.md` for security/authorization/engineering boundaries;
2. `docs/design/VULNHUNTER_UI_CONTRACT.md` in full;
3. `docs/design/AI_AGENT_UI_IMPLEMENTATION_STANDARD.md` in full;
4. `docs/design/references/manifest.json`;
5. `docs/design/DEPRECATIONS.md`;
6. `docs/product/CHAT_FIRST_WORKSPACE.md`;
7. `docs/product/UI_ACCEPTANCE_CRITERIA.md`;
8. `docs/product/RESPONSIVE_AND_ACCESSIBILITY.md`;
9. relevant backend routes/actions/persisted states/permissions;
10. the existing shared tokens and component/style owner for the affected surface.

Do not start from the current screenshot or current CSS and work backwards. Current implementation may contain known presentation debt.

## 2. Binding product model

VulnHunter is a **conversation/task-first AI security workspace**.

It is not an admin dashboard with a chatbot attached.

The default product hierarchy is:

```text
compact task/chat sidebar or mobile drawer
→ main conversation + task timeline
→ persistent composer
→ optional contextual detail drawer/deep view
```

Findings, evidence, approvals, authorization requirements, Source Hunt setup, APK uploads, tool receipts, recovery/failure and report readiness should appear contextually in the conversation/task flow before forcing the user to a separate page.

Specialist pages are deep views of the same persisted state, not competing workflows.

## 3. Reference hierarchy — do not mix responsibilities

### MonkeyCode = structure and task behavior

Use MonkeyCode for:

- task/chat-first sidebar composition;
- current task prominence;
- recent chats/tasks;
- task history;
- running task timeline;
- queued follow-up behavior;
- reconnect/restoration behavior;
- persistent composer;
- compact task controls;
- mobile overlay drawer.

Do not copy MonkeyCode branding, account tiers, provider/model names, Projects terminology or unsupported actions.

### Beautiful UI = AI-native components and microinteractions

Use `https://beautiful-ui-five.vercel.app/` for component patterns such as:

- Loading State;
- safe user-facing Thinking/activity state;
- Streaming Text;
- Approval Card;
- Tool Chips;
- Task Rows;
- Chat;
- Prompt Bar;
- Recommendation Card;
- Context Cards;
- Diff Table;
- Records/Filter Table for deep views;
- Sidebar Nav;
- Search;
- Code Block;
- Selection Actions when repository-backed.

Never expose hidden chain-of-thought. A Beautiful UI “Thinking” pattern means safe activity text such as `Checking authorization…` or `Preparing bounded plan…`, not model private reasoning.

Do not copy Beautiful UI colors, rounding, branding, sample app content, provider/model selectors, dictation, Fine-tune controls or unsupported actions.

### VulnHunter = identity, product truth and authority

VulnHunter owns:

- all branding and terminology;
- routes/actions;
- security and authorization boundaries;
- actual persisted state;
- tool/provider availability;
- findings/evidence;
- approval/review/adjudication authority;
- visual palette and geometry.

## 4. Visual lock

The canonical identity is:

- warm cream/off-white working canvas; historical approved reference around `#F7F3EE`, canonical token `--vh-canvas: #f5f2ec`;
- subtle dotted graph-paper texture;
- compact dark task/chat sidebar;
- dusty-pink primary/active accent;
- near-black text and technical borders;
- bold grotesk headings;
- monospace/typewriter technical metadata and controls;
- square or nearly-square geometry (`0–3px` normal radius);
- hard black zero-blur offset shadows;
- generous but purposeful whitespace;
- restrained semantic success/warning/danger colors.

Forbidden without explicit product-design approval:

- generic blue-and-white SaaS styling;
- blue glow/orb decoration as the dominant identity;
- glassmorphism;
- frosted blur;
- decorative gradients;
- neon cyberpunk styling;
- soft floating-card shadows;
- large rounded cards as the default;
- bubbly chat balloons;
- excessive pills;
- page-local color/radius/shadow systems;
- dashboard KPI walls.

## 5. Explicitly rejected current-UI patterns

Do not preserve these patterns merely because they exist in current templates/styles/tests:

- four large top cards for `Authorization / Scope / Approval / Active` on the ordinary chat page;
- a horizontal page toolbar containing `Source Hunt / Search / Export / History / New workspace`;
- `Runs / Scanner / Execution / Entry point` KPI cards as the primary workspace/history experience;
- a giant Source Hunt form as the main way to begin source analysis;
- giant dark admin panels for ordinary chat-first flows;
- huge empty content areas while task state and assistant text are tiny;
- low-contrast assistant copy on the cream canvas;
- desktop controls squeezed/clipped on phone;
- horizontal phone overflow;
- multiple simultaneously competing navigation systems;
- persistent context panels when no context has been opened;
- adding one more late-loaded stylesheet merely to override earlier contradictory CSS.

If a test asserts one of these deprecated presentation details, update the test to the canonical contract while preserving functional/security assertions.

## 6. Canonical desktop structure

```text
┌──────────────────┬─────────────────────────────────────────┬──────────────────┐
│ task/chat sidebar│ conversation + task timeline            │ contextual detail│
│                  │                                         │ only when opened │
│ + New assessment │ user / assistant messages               │ evidence/finding │
│ current task     │ task rows / tool chips / cards          │ tool/source/etc. │
│ recent tasks     │                                         │                  │
│ history          │ persistent composer                     │                  │
│ Manage / Settings│                                         │                  │
└──────────────────┴─────────────────────────────────────────┴──────────────────┘
```

The right context area is closed by default.

## 7. Canonical mobile structure

Mobile is a one-column task workspace:

```text
☰  current task / title                      ⋯

Running · 02:41

✓ Authorization verified
✓ Passive plan prepared
◌ Nuclei assessment
○ Verification

assistant response
[tool chips]
[context/finding/approval card when relevant]

+  Ask VulnHunter…                         ➜
```

The hamburger opens the task/chat drawer. The desktop sidebar must not remain permanently visible.

Requirements:

- no essential horizontal page scroll;
- no clipped primary controls;
- no desktop toolbar row squeezed onto phone;
- primary phone body copy normally around `15–17px`;
- at least `44px` touch targets for critical controls;
- composer remains reachable during running/queued/approval/recovery states;
- evidence/details become full-width cards, sheets, drawers or deep views;
- desktop and mobile keep the same product semantics.

## 8. Interaction lock

- Chat/task workspace is the primary surface.
- Running work does not disable the composer unless a real backend constraint requires it.
- Follow-up instructions that cannot run immediately are persisted and visibly marked `Queued` where supported.
- Refresh/reconnect reconstructs persisted state; it does not restart work.
- Leaving the page does not imply cancellation.
- Cancel appears only where backend cancellation exists.
- **Do not add Pause unless an explicit backend operator-pause contract exists.**
- Never invent progress, findings, evidence, readiness, approval or completion in browser code.
- Unknown/unavailable values remain unknown/unavailable.
- Authorization, confirmation, approval, review and adjudication remain distinct concepts.

## 9. Component adaptation rules

Prefer a small set of shared primitives:

- `TaskRow` concept for stages;
- `ToolChip` concept for provenance/tool receipts;
- `ApprovalCard` / `ConfirmationCard` for exact decisions;
- `ContextCard` for evidence/source/provenance;
- `FindingCard` for candidate/persisted findings;
- `RecommendationCard` for advisory remediation/next steps;
- `PromptBar` for the persistent composer;
- contextual drawer/sheet/deep view for large details.

Do not create a new decorative card type for every backend object.

## 10. Source Hunt rule

Source Hunt begins in or is initiated from the conversation/task system. The first-class experience is a compact task card/state such as:

```text
Source Hunt
Repository: /workspaces/project
Revision: abc123…

✓ Snapshot created
Ⅱ Exact source-processing approval required

[Review approval]
```

A specialist Source Hunt view may collect exact root/revision/path/reauthentication/attestation fields when required, but it is a focused continuation rather than a second product.

## 11. APK rule

APK analysis begins from the conversation attachment flow. Upload, hash verification, static tool receipts, evidence and blockers return to the task/conversation. Uploading an APK never implies dynamic execution.

## 12. CSS architecture discipline

Before adding CSS, identify which existing stylesheet/shared primitive owns the component.

- use canonical variables from `tokens.css`;
- consolidate contradictory selectors instead of stacking overrides;
- avoid `!important` as a design-repair strategy;
- do not create another global patch stylesheet just to beat cascade order;
- route-specific CSS may arrange domain content but may not redefine palette/geometry/type/shadows;
- remove dead/deprecated selectors when safely replacing a surface;
- avoid duplicate mobile rules for the same component across multiple files;
- preserve CSP/no-inline-script constraints.

Reducing presentation debt is preferred over preserving stylesheet count.

## 13. Required states

For each affected workflow, implement/test the applicable states:

- empty/new;
- composing;
- upload / integrity verification;
- authorization missing/found;
- confirmation required;
- independent approval required;
- queued;
- running;
- follow-up queued;
- tool running/completed/failed;
- evidence/finding available;
- recovering;
- failed safely;
- cancelled;
- completed;
- permission denied;
- provider unavailable/deterministic fallback;
- reconnect/restored.

## 14. Responsive verification

Meaningful workspace changes must be checked at representative widths near:

`360`, `390`, `412`, `768`, `1024`, `1280`, and `1440` CSS pixels.

A phone implementation fails immediately if it has essential horizontal page scrolling, clipped core actions, unreadable text, unreachable composer, or desktop-only grids/toolbars squeezed into the viewport.

## 15. Browser evidence requirement

Do not claim UI completion because templates render or backend tests pass.

For meaningful UI work, use real browser checks and capture applicable states such as:

- phone login;
- empty/new phone workspace;
- mobile drawer;
- running phone task;
- phone approval/confirmation;
- phone evidence/finding;
- desktop empty/running workspace;
- contextual drawer;
- Source Hunt initiation;
- APK attachment state;
- recovery/failure state.

Compare against the canonical contract and approved references, not merely against the previous implementation.

## 16. Change discipline and stop condition

A frontend change that violates `docs/design/VULNHUNTER_UI_CONTRACT.md` or `docs/design/AI_AGENT_UI_IMPLEMENTATION_STANDARD.md` is a regression even if it functions.

If a requested implementation appears to require breaking the contract, stop and report the exact conflict instead of silently reinterpreting the design.

A generic dashboard result is not “close enough.” A desktop-only result is not done. A reference-looking result with invented functionality is not done.
