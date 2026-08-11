# VulnHunter Design Documentation

This directory contains the **binding product-design source of truth**. It is intentionally structured so coding agents cannot choose whichever historical design document or current screenshot is easiest to follow.

## Mandatory read order

For any frontend, template, CSS, JavaScript, responsive, accessibility, navigation, conversation, live-task or interaction change, read:

1. repository-root `AGENTS.md`;
2. `vulnhunter/web/AGENTS.md`;
3. [`VULNHUNTER_UI_CONTRACT.md`](VULNHUNTER_UI_CONTRACT.md) — locked visual/interaction contract;
4. [`AI_AGENT_UI_IMPLEMENTATION_STANDARD.md`](AI_AGENT_UI_IMPLEMENTATION_STANDARD.md) — binding implementation/rejection standard;
5. [`references/manifest.json`](references/manifest.json) — approved references with `use_for`/`ignore` rules;
6. [`DEPRECATIONS.md`](DEPRECATIONS.md) — retired presentation that must not be revived;
7. [`../product/CHAT_FIRST_WORKSPACE.md`](../product/CHAT_FIRST_WORKSPACE.md) — task/workflow semantics;
8. [`../product/LIVE_EXECUTION_ACTIVITY.md`](../product/LIVE_EXECUTION_ACTIVITY.md) — persisted running-task/activity semantics;
9. [`../product/PUBLIC_TARGET_ASSESSMENT.md`](../product/PUBLIC_TARGET_ASSESSMENT.md) when website/public-target UX is affected;
10. [`../product/UI_ACCEPTANCE_CRITERIA.md`](../product/UI_ACCEPTANCE_CRITERIA.md) — hard acceptance/fail gates;
11. [`../product/RESPONSIVE_AND_ACCESSIBILITY.md`](../product/RESPONSIVE_AND_ACCESSIBILITY.md);
12. shared tokens/primitives and repository-backed route/action/projection/state/security contracts.

## Permanent reference hierarchy

### MonkeyCode = product structure and task interaction

Use MonkeyCode for:

- task/chat-first shell;
- current/recent tasks;
- task history;
- running-operation timeline;
- queued follow-up behavior;
- reconnect/restoration;
- persistent composer;
- contextual task controls;
- mobile overlay drawer.

MonkeyCode is not VulnHunter branding, palette, account model, provider list or product terminology.

### Beautiful UI = AI-native components and microinteractions

Use `https://beautiful-ui-five.vercel.app/` for appropriate patterns such as:

- loading/safe activity;
- assistant streaming text;
- task rows/tool chips;
- approval/confirmation cards;
- chat/prompt bar;
- recommendation/context/finding cards;
- code/diff presentation;
- search/deep-view tables.

Beautiful UI is not permission to copy its branding, colors, rounding, provider/model selectors, Fine-tune controls, dictation, sample business data or unsupported actions.

A “Thinking” pattern means safe user-facing operational activity only. Hidden chain-of-thought/private reasoning is prohibited.

### VulnHunter = identity, functionality and authority

VulnHunter owns:

- actual product capabilities;
- authorization/security boundaries;
- persisted state/evidence/findings;
- terminology;
- warm cream/off-white dotted canvas;
- dusty-pink accent;
- compact dark sidebar;
- near-black technical text/borders;
- square/nearly-square geometry;
- hard black zero-blur offset shadows.

## Live execution design rule

The task/workspace design must render persisted operational state when work is queued/running.

Do not replace real task activity with a generic spinner or “check another page” message when the backend exposes more information.

Never fabricate percentages, tool activity, evidence or findings.

See `../product/LIVE_EXECUTION_ACTIVITY.md`.

## Public-target design rule

Authorised public targets are a supported product class, but a public URL is never permission.

The UI must distinguish target classification, authorization state, exact plan and worker capability. If the worker remains private-only, show a truthful blocker instead of fake running state.

The browser cannot create execution authority by toggling a flag.

See `../product/PUBLIC_TARGET_ASSESSMENT.md`.

## Existing implementation is subordinate

Templates, CSS, JavaScript and tests may contain presentation debt.

When implementation conflicts with the locked design:

- preserve backend/security behavior;
- replace/refactor the presentation;
- update stale presentation tests;
- remove dead contradictory styles when safe;
- do not weaken the contract to preserve old markup/cascade layering.

## Competing-document rule

Do **not** create another design-system or AI-workspace document that competes with the authority chain above.

Specialist architecture documents may explain state/workflow details but may not redefine:

- primary information architecture;
- reference priority;
- palette/type/spacing/geometry/shadows;
- everyday navigation;
- mobile composition;
- conversation/task-first structure.

## Reference registration rule

A new external visual/site reference may influence implementation only after registration in `references/manifest.json` with:

- identity/URL or repository asset;
- `CANONICAL` or `PARTIAL_REFERENCE` status;
- explicit `use_for` responsibilities;
- explicit `ignore` rules.

External references never grant product functionality or security authority.

## Change control

Permanent visual/interaction rules belong in the locked UI contract and implementation standard.

Persistent running-task state belongs in `LIVE_EXECUTION_ACTIVITY.md`.

Public website authorization/execution semantics belong in `PUBLIC_TARGET_ASSESSMENT.md`.

Deliberate changes to these contracts must be explicit product/security changes, not incidental frontend refactors.
