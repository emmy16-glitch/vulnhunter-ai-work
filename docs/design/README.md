# VulnHunter Design Documentation

This directory contains the **binding product-design source of truth**. It is intentionally structured so coding agents cannot choose whichever historical design document is easiest to follow.

## Mandatory read order

For any frontend, template, CSS, JavaScript, responsive, accessibility, navigation, conversation or interaction change, read:

1. [`VULNHUNTER_UI_CONTRACT.md`](VULNHUNTER_UI_CONTRACT.md) — **locked canonical visual and interaction contract**.
2. [`AI_AGENT_UI_IMPLEMENTATION_STANDARD.md`](AI_AGENT_UI_IMPLEMENTATION_STANDARD.md) — **binding implementation and rejection standard for Codex, Cline and all other coding agents**.
3. [`references/manifest.json`](references/manifest.json) — approved references and explicit `use_for` / `ignore` rules.
4. [`DEPRECATIONS.md`](DEPRECATIONS.md) — retired and currently rejected presentation patterns that must not be revived.
5. [`../product/CHAT_FIRST_WORKSPACE.md`](../product/CHAT_FIRST_WORKSPACE.md) — chat/task-first workflow contract.
6. [`../product/UI_ACCEPTANCE_CRITERIA.md`](../product/UI_ACCEPTANCE_CRITERIA.md) — hard acceptance and fail gates.
7. [`../product/RESPONSIVE_AND_ACCESSIBILITY.md`](../product/RESPONSIVE_AND_ACCESSIBILITY.md) — responsive/accessibility requirements.
8. Existing shared tokens/primitives and repository-backed route/action/state/security contracts.

## Permanent reference hierarchy

The references have different responsibilities:

### MonkeyCode = product structure and task interaction

Use MonkeyCode for the task/chat-first shell, current/recent tasks, task history, running-operation timeline, queued messages, reconnect behavior, persistent composer, contextual controls and mobile drawer.

MonkeyCode is **not** the VulnHunter palette, branding, account model, provider list or product terminology.

### Beautiful UI = AI-native components and microinteractions

Use `https://beautiful-ui-five.vercel.app/` for appropriate patterns such as loading state, safe user-facing thinking/activity, streaming text, approval cards, tool chips, task rows, chat, prompt bar, recommendation cards, context cards, code blocks, source diffs, search and deep-view tables.

Beautiful UI is **not** permission to copy its branding, colors, rounding, sample app concepts, model/provider selectors, fine-tuning controls, dictation or unsupported actions. “Thinking” never means exposing hidden chain-of-thought.

### VulnHunter = visual identity and actual product truth

VulnHunter owns the warm cream/off-white dotted canvas, dusty-pink accent, compact dark sidebar, near-black technical type/borders, square geometry, hard black offset shadows, product wording, actual routes/actions, persisted state and all security/authorization authority.

Historical approved cream references included a warm off-white near `#F7F3EE`; the canonical implementation token remains defined by the locked contract and `tokens.css`.

## Existing implementation is subordinate

Templates, CSS, JavaScript and tests may contain historical or current UI debt. Their existence does not make them the design authority.

When implementation conflicts with the locked design:

- preserve backend and security behavior;
- replace/refactor the presentation;
- update tests that encode deprecated presentation details;
- do not weaken the contract to preserve old markup or stylesheet layering.

## Competing-document rule

Do **not** create another design-system or AI-workspace document that competes with the files above.

Older or specialist documents such as AI-first architecture, premium interaction, Figma handoff, information architecture and implementation notes are subordinate. They may explain workflow details but may not redefine:

- primary information architecture;
- reference priority;
- palette;
- typography;
- spacing;
- geometry;
- shadows;
- everyday navigation;
- mobile composition;
- conversation/task-first product structure.

If wording in a subordinate document appears to conflict, the mandatory read order above wins.

## Reference registration rule

A new visual/site reference may influence implementation only after it is registered in `references/manifest.json` with:

- its identity/URL or repository file;
- `CANONICAL` or `PARTIAL_REFERENCE` status;
- explicit `use_for` responsibilities;
- explicit `ignore` rules.

A screenshot or external component library never grants backend functionality.

## Change control

Permanent visual or interaction rules belong in `VULNHUNTER_UI_CONTRACT.md` and the agent implementation standard. Deliberate contract changes must be explicit product-design changes, not incidental frontend refactors.

A page-specific note may explain how a workflow applies the contract, but may not invent a local design system.
