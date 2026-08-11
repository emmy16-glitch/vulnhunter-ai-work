# Codex UI/UX Skills Memory

**Project:** VulnHunter AI  
**Purpose:** durable instructions for Codex and other AI-assisted frontend work.

---

## Mandatory source-of-truth order

Every Codex UI task starts by reading:

1. `AGENTS.md`;
2. `vulnhunter/web/AGENTS.md`;
3. `docs/design/VULNHUNTER_UI_CONTRACT.md`;
4. `docs/design/AI_AGENT_UI_IMPLEMENTATION_STANDARD.md`;
5. `docs/design/references/manifest.json`;
6. `docs/design/DEPRECATIONS.md`;
7. `docs/product/CHAT_FIRST_WORKSPACE.md`;
8. `docs/product/LIVE_EXECUTION_ACTIVITY.md`;
9. `docs/product/PUBLIC_TARGET_ASSESSMENT.md` when website/public-target behavior is affected;
10. `docs/product/UI_ACCEPTANCE_CRITERIA.md`;
11. `docs/product/RESPONSIVE_AND_ACCESSIBILITY.md`;
12. relevant backend routes/actions/projections/state/tests/shared components.

Skills guide implementation. They never override repository contracts.

---

## Fixed reference hierarchy

### MonkeyCode

Use for task/workspace structure only:

- compact task/chat sidebar;
- current/recent tasks;
- task history;
- running timeline;
- queued follow-ups;
- reconnect/restoration;
- persistent composer;
- mobile overlay drawer.

Do not copy MonkeyCode branding, account tiers, Projects terminology, model/provider names or unsupported controls.

### Beautiful UI

Use for AI-native component/microinteraction patterns only:

- loading/activity;
- assistant streaming text;
- approval/confirmation cards;
- task rows;
- tool chips;
- chat/prompt bar;
- recommendation/context/finding cards;
- code/diff presentation;
- search/deep-view records.

Do not copy Beautiful UI branding, colors, rounding, Fine-tune controls, dictation, sample commands, model/provider selectors or hidden model reasoning.

### VulnHunter

VulnHunter owns:

- actual routes/actions/capabilities;
- authorization/security authority;
- persisted state/evidence/findings;
- terminology;
- warm cream/off-white dotted canvas;
- dusty-pink accent;
- compact dark sidebar;
- near-black technical type/borders;
- square/nearly-square geometry;
- hard zero-blur offset shadows.

---

## Existing implementation is not authority

Current templates, CSS, JS, selectors, tests and screenshots may contain deprecated presentation.

When they conflict with the locked contract:

- preserve backend/security behavior;
- replace/refactor presentation;
- update stale presentation tests;
- remove dead contradictory CSS when safe;
- do not add another late override layer.

---

## Public-target rules for Codex

Authorised public targets are a supported product class.

Codex must **not** implement them by:

- globally changing `allow_public=False` to `True`;
- deleting private-target worker assertions;
- trusting a URL or chat message as permission;
- allowing uncontrolled DNS re-resolution;
- allowing public-to-private/metadata pivot;
- scanning a raw IP if doing so breaks Host/SNI/certificate semantics;
- letting browser input switch worker target class.

Before public-target implementation, read `docs/product/PUBLIC_TARGET_ASSESSMENT.md` and inspect:

- authorization model/service/store;
- scope validator;
- Nuclei activation target classification;
- worker policy;
- worker transport/process runner;
- target Host/TLS semantics;
- redirect handling;
- relevant tests/acceptance.

A private-only worker remains private-only until a reviewed public-capable execution boundary exists.

UI must show a truthful blocker when public runtime is unavailable.

---

## Live execution rules for Codex

Running work must not remain a black box.

Before editing a running-task surface, inspect:

- worker/service events;
- append-only activity store;
- assessment/task graph;
- selected-assessment projection;
- browser polling/reconnect behavior;
- task-card/activity rendering.

Implement from persisted state:

- current stage;
- completed/pending stages;
- active worker/tool when known;
- safe current subject;
- real receipt/evidence/candidate counts;
- latest event;
- blocker/failure/recovery/preserved state;
- safe action.

Do not invent progress or expose hidden chain-of-thought.

See `docs/product/LIVE_EXECUTION_ACTIVITY.md`.

---

## Source Hunt rules

Source Hunt must:

- begin conversationally/contextually;
- use deterministic preflight before full submission where possible;
- show file/byte/path blockers before queueing;
- keep exact snapshot/revision/path/approval identity;
- return queued/running state to the originating workspace;
- expose persisted snapshot/inventory/hunt/falsification/capability/remediation activity;
- never imply `permitted_paths` constrained snapshot construction unless runtime actually enforces that.

See `docs/product/SOURCE_HUNT.md`.

---

## Approved skills

Use the smallest relevant set.

### `$fixing-accessibility`

Use for semantics, labels, keyboard/focus, dialogs/sheets, contrast, reduced motion and screen-reader status behavior.

### `$make-interfaces-feel-better`

Use for optical polish **inside the locked design contract**. It may not redefine palette, radii, navigation hierarchy or product architecture.

### `$playwright-cli`

High priority for real browser verification of:

- phone/desktop;
- login;
- conversation;
- authorization/public-target blocker;
- plan/approval;
- queued/running live activity;
- Source Hunt;
- APK;
- evidence/findings;
- failure/recovery/cancellation;
- reconnect;
- accessibility interactions.

### React/Vitest/etc.

Use only when the existing implementation actually requires them. Do not introduce a framework merely because a skill exists.

---

## Mandatory implementation steps

Before editing:

1. inspect current `main`, open PRs, recent commits and CI;
2. read the authority chain above;
3. inspect backend state/actions powering the surface;
4. identify existing tokens/component/style owner;
5. state the applicable MonkeyCode structure;
6. state the applicable Beautiful UI primitive, if any;
7. identify deprecated presentation to remove;
8. define phone behavior;
9. define truthful loading/blocked/running/failure/recovery states;
10. define tests and browser evidence.

During implementation:

- preserve routes/API/auth/security/state truth;
- reuse shared components/tokens;
- avoid new global CSS patch layers;
- keep desktop/mobile one product system;
- preserve running composer/queued messages where applicable;
- treat reconnect as reconstruction, never restart;
- do not add unsupported Pause/SSO/provider/model/Fine-tune/dictation/account-tier controls;
- never expose hidden chain-of-thought;
- never fabricate activity/progress/findings/evidence.

After implementation:

- run focused tests;
- run repository gates from `AGENTS.md`;
- run real browser checks at representative widths;
- compare rendered live/public state with persisted backend state;
- report limitations honestly.

---

## Mandatory fail conditions

Reject the result if it contains:

- four large Authorization/Scope/Approval/Active cards;
- wide Source Hunt/Search/Export/History/New workspace toolbar;
- KPI-card workspace/history walls;
- giant dark Source Hunt/admin panels;
- giant Source Hunt form as main entry;
- tiny/low-contrast conversation text;
- desktop UI squeezed onto phone;
- clipped phone actions/horizontal page overflow;
- competing navigation systems;
- permanent context panel when not opened;
- new CSS patch layer only to beat cascade order;
- public scanning enabled by weakening scope/worker controls;
- public URL treated as permission;
- a running spinner with no persisted activity when backend events exist;
- hidden chain-of-thought/private reasoning.

---

## Prompt template

```text
Read in order:
- AGENTS.md
- vulnhunter/web/AGENTS.md
- docs/design/VULNHUNTER_UI_CONTRACT.md
- docs/design/AI_AGENT_UI_IMPLEMENTATION_STANDARD.md
- docs/design/references/manifest.json
- docs/design/DEPRECATIONS.md
- docs/product/CHAT_FIRST_WORKSPACE.md
- docs/product/LIVE_EXECUTION_ACTIVITY.md
- docs/product/PUBLIC_TARGET_ASSESSMENT.md if website/public-target work
- docs/product/UI_ACCEPTANCE_CRITERIA.md
- docs/product/RESPONSIVE_AND_ACCESSIBILITY.md

Task:
[exact task]

Before editing:
1. Inspect current runtime state, relevant backend contracts/tests and existing shared UI owners.
2. Identify the MonkeyCode structural pattern and Beautiful UI primitive, if any.
3. Identify deprecated presentation to remove.
4. Explain how public/private authorization and worker capability remain truthful if affected.
5. Explain which persisted events drive running activity if affected.
6. Present a short implementation/test/phone plan.
```
