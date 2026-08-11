# VulnHunter Web — Frontend Agent Rules

**STATUS: BINDING FOR EVERY FILE UNDER `vulnhunter/web/`**

These rules apply to Codex, Cline, Claude Code, Copilot, Cursor, ChatGPT coding agents, local agents, automated refactoring tools and human developers.

The purpose of this file is to stop agents from producing a functionally correct but contradictory, dashboard-first, unreadable, unsafe or state-fabricating browser product.

---

## 1. Mandatory read order

Before changing templates, CSS, JavaScript, navigation, forms, dialogs, responsive layout, copy, task state, conversation rendering, website authorization, Source Hunt entry, live task presentation or browser interaction, read in this exact order:

1. repository-root `AGENTS.md`;
2. `docs/design/VULNHUNTER_UI_CONTRACT.md`;
3. `docs/design/AI_AGENT_UI_IMPLEMENTATION_STANDARD.md`;
4. `docs/design/references/manifest.json`;
5. `docs/design/DEPRECATIONS.md`;
6. `docs/product/CHAT_FIRST_WORKSPACE.md`;
7. `docs/product/LIVE_EXECUTION_ACTIVITY.md`;
8. `docs/product/PUBLIC_TARGET_ASSESSMENT.md` when website/public-target state is affected;
9. `docs/product/UI_ACCEPTANCE_CRITERIA.md`;
10. `docs/product/RESPONSIVE_AND_ACCESSIBILITY.md`;
11. relevant backend routes/actions/projections/persisted state/permissions/tests;
12. the existing shared tokens and component/style owner for the affected surface.

Do not start from the current screenshot/current CSS and work backwards. Current implementation may contain known presentation debt.

---

## 2. Binding product model

VulnHunter is a **conversation/task-first AI security workspace**.

The default hierarchy is:

```text
compact task/chat sidebar or mobile drawer
→ main conversation + persisted task timeline
→ persistent composer
→ optional contextual detail drawer/sheet/deep view
```

Findings, evidence, authorizations, plan decisions, Source Hunt, APK state, worker activity, failures/recovery and report readiness appear contextually in the task/conversation first when practical.

Specialist pages are deep views of the same persisted state, not competing products.

---

## 3. Reference hierarchy

### MonkeyCode

Use only for:

- task/chat sidebar structure;
- current/recent tasks;
- task history;
- running timeline;
- queued follow-ups;
- reconnect/restoration;
- persistent composer;
- mobile overlay drawer.

Do not copy branding, Projects/account tiers, provider names or unsupported controls.

### Beautiful UI

Use only for AI-native component/microinteraction patterns such as:

- loading/activity states;
- assistant streaming text;
- approval/confirmation cards;
- task rows;
- tool chips;
- prompt bar;
- context/evidence cards;
- finding/recommendation cards;
- code/diff presentation;
- search/deep-view records.

Do not copy its colors, rounding, branding, sample actions, Fine-tune controls, dictation, provider/model selectors or hidden reasoning.

### VulnHunter

VulnHunter owns:

- actual routes/actions/capabilities;
- all authorization/security authority;
- persisted state/evidence/findings;
- terminology;
- warm cream/off-white dotted canvas;
- dusty-pink accent;
- compact dark sidebar;
- near-black technical type/borders;
- square/nearly-square geometry;
- hard zero-blur offset shadows.

---

## 4. Public-target UI rule

The browser may support authorised public targets. It must never imply that entering a public URL itself grants permission.

Public-target flow should remain contextual:

```text
URL supplied
→ classify target
→ resolve/select exact authorization
→ show authorization-required card if absent
→ create/select authorization only through backend-supported workflow
→ show exact immutable plan
→ required confirmation/approval
→ queue
→ persisted live task activity
```

The UI must distinguish:

- target class: public/private;
- authorization state;
- exact host/port/path;
- authorization basis/evidence reference where appropriate;
- plan state;
- worker capability/readiness.

A public-target control may never:

- bypass backend authorization;
- set `allow_public` in browser state and treat it as permission;
- switch a private-only worker to public mode;
- hide that a public-capable execution path is unavailable;
- suggest the scan started when the worker rejected the target class.

See `docs/product/PUBLIC_TARGET_ASSESSMENT.md`.

---

## 5. Live execution rule

When backend state is `queued`, `claimed`, `running`, `recovering` or equivalent, the workspace must show truthful persisted activity.

The user should be able to see, when available:

- current stage;
- completed and next stages;
- current worker/tool;
- safe current subject (target/file/artifact);
- receipts/evidence/candidate counts;
- latest persisted activity;
- blocker/failure/recovery state;
- preserved work;
- supported action.

A generic assistant message saying “the backend is running it; check another page” is not acceptable as the primary experience.

Do not expose hidden chain-of-thought. Show operational telemetry only.

The browser may derive concise summaries from the authoritative projection, but must not fabricate events, percentages, tool identity, evidence counts or timing.

See `docs/product/LIVE_EXECUTION_ACTIVITY.md`.

---

## 6. Canonical desktop structure

```text
┌──────────────────┬─────────────────────────────────────────┬──────────────────┐
│ task/chat sidebar│ conversation + task timeline            │ contextual detail│
│ + New assessment │ user/assistant messages                 │ only when opened │
│ current task     │ task rows/tool chips/cards              │ evidence/finding │
│ recent tasks     │ live activity                           │ receipt/source   │
│ task history     │ persistent composer                     │                  │
│ Manage/Settings  │                                         │                  │
└──────────────────┴─────────────────────────────────────────┴──────────────────┘
```

The context drawer is closed by default.

Do not create a permanent metrics rail or a wide page-level utility toolbar competing with the task.

---

## 7. Canonical mobile structure

Phone is a one-column task workspace:

```text
☰  current task                              ⋯

Running · truthful duration when derivable

✓ Authorization verified
✓ Plan confirmed
◌ Nuclei assessment
○ Verification

assistant response
[tool chips]
[context/finding/approval card]

+ Ask VulnHunter…                         ➜
```

Requirements:

- no essential horizontal page scroll;
- no clipped primary actions;
- no desktop toolbar/grid squeezed onto phone;
- readable body copy;
- approximately 44px critical touch targets;
- composer reachable during running/queued/approval/recovery;
- contextual detail becomes a full-width sheet/drawer/deep view;
- long URLs/hashes/file paths wrap or use deliberate truncation/detail affordances.

---

## 8. Explicitly rejected patterns

Do not preserve these merely because current markup/tests contain them:

- four large `Authorization / Scope / Approval / Active` cards;
- `Source Hunt / Search / Export / History / New workspace` horizontal toolbar;
- KPI-card walls such as `Runs / Scanner / Execution / Entry point`;
- giant dark Source Hunt/admin panels in ordinary conversation;
- giant standalone Source Hunt form as the main entry point;
- tiny low-contrast assistant text;
- blue-glow/cyberpunk identity;
- desktop UI mechanically squeezed onto phone;
- horizontal phone overflow/clipped primary controls;
- multiple competing navigation systems;
- permanent context panel when nothing is opened;
- fake progress or browser-owned worker state;
- another late-loaded global CSS override file used only to beat old CSS.

A stale test asserting deprecated presentation must be updated to preserve semantic/security assertions while adopting the canonical UI.

---

## 9. Component roles

Prefer a small shared primitive set:

- task header;
- task row;
- tool chip;
- user/assistant message;
- prompt bar;
- authorization card;
- plan confirmation card;
- independent approval card;
- context/evidence card;
- finding card;
- recommendation/remediation card;
- live activity disclosure;
- contextual drawer/sheet/deep view;
- compact empty/error/recovery state;
- specialist list/table where genuinely needed.

Do not create one decorative card type per backend object.

---

## 10. Source Hunt UI rule

Source Hunt begins conversationally or from task context.

Preferred shape:

```text
Source Hunt
Repository: /workspaces/project
Revision: abc123…

✓ Repository resolved
✓ Snapshot preflight passed
Ⅱ Exact source-processing approval required

[Review approval]
```

The specialist setup view may collect exact root/revision/permitted paths/password/attestations, but it is a focused continuation.

Before queueing, surface real preflight information where available:

- eligible file count vs limit;
- eligible byte count vs limit;
- unsupported file/language exclusions;
- exact snapshot root/revision;
- permitted path effect.

Do not let a user discover a predictable file-count/byte-limit failure only after submission when the backend can preflight it safely.

Once queued/running, project Source Hunt stages/activity in the original workspace.

---

## 11. Running/composer behavior

While supported work runs:

- composer remains enabled unless backend policy truly forbids input;
- follow-up instructions may be visibly queued where supported;
- refresh/reconnect reconstructs state and never restarts work;
- leaving the page does not imply cancellation;
- Cancel appears only when safe backend cancellation exists;
- Pause never appears unless a real pause/resume backend contract exists;
- progress is shown only from measurable persisted data.

---

## 12. Failure/recovery behavior

Failure must show useful typed state when available:

- failed stage;
- safe reason;
- reference ID;
- completed work;
- preserved evidence;
- user-vs-operator action required;
- retry availability/scope.

Recovery updates the same task identity. Do not replace it with a new fake task.

---

## 13. CSS/presentation architecture

Before adding CSS:

1. identify the shared token/component owner;
2. remove/consolidate contradictory rules;
3. keep responsive behavior with the component owner;
4. avoid `!important` as a repair strategy;
5. do not introduce page-local palette/radius/shadow/type systems;
6. preserve CSP/no-inline-script constraints;
7. remove dead deprecated selectors when safe.

A successful UI migration should reduce presentation debt.

---

## 14. Browser evidence requirement

Do not claim UI completion because templates render or unit tests pass.

Meaningful UI work requires real browser verification against backend-connected state, including applicable scenarios:

- empty/new workspace;
- authorization required/verified;
- public target card/plan when affected;
- queued/running live activity;
- approval/confirmation;
- Source Hunt setup/running;
- APK upload/tool activity;
- evidence/finding;
- failure/recovery/cancellation;
- reconnect/restored state;
- phone drawer/composer/keyboard behavior;
- desktop contextual detail.

Verify representative widths near `360`, `390`, `412`, `768`, `1024`, `1280`, `1440` CSS pixels.

---

## 15. Stop condition

Stop and report instead of improvising when:

- backend state cannot support the requested UI truthfully;
- public-target UI would imply execution while the worker is private-only;
- activity data does not exist and the only alternative is fake progress;
- an external reference suggests unsupported functionality;
- a proposed layout contradicts the canonical UI contract;
- a test can pass only by weakening security/state truth.

A generic dashboard result, an unsafe public-target shortcut or a fake live-execution experience is not “close enough.”
