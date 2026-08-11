# Retired UI Guidance

This file records product-design guidance and implementation patterns that are no longer authoritative. It exists so agents do not revive old concepts from historical documents, screenshots, tests or implementation leftovers.

The replacement sources of truth are:

1. `docs/design/VULNHUNTER_UI_CONTRACT.md`;
2. `docs/design/AI_AGENT_UI_IMPLEMENTATION_STANDARD.md`;
3. `docs/design/references/manifest.json`.

## Retired visual direction

The following guidance is retired:

- a default all-dark or “dark security-operations” product surface;
- neon/cyberpunk styling;
- generic blue-and-white SaaS styling;
- blue-glow/orb decoration as the dominant product identity;
- soft floating-card shadows and large rounded cards as the default system;
- page-specific colours, radii, spacing or shadow systems;
- dense KPI/dashboard walls as the primary workspace;
- tiny low-contrast text justified as “technical density”;
- mechanically shrinking desktop UI until it technically fits on a phone.

The approved direction is the locked warm cream/off-white dotted canvas, dusty-pink accents, compact dark task/chat sidebar, near-black technical typography/borders, square geometry, hard zero-blur offset shadows, generous purposeful spacing and readable conversation typography.

## Retired information architecture

The following primary-navigation models are retired:

- `Overview → Collection → Analysis → Independent Review → Governance → Intelligence → Assurance` as the everyday user journey;
- the campaign control room as the centre of the product;
- every backend subsystem receiving equal permanent sidebar prominence;
- a generic “security operations dashboard” as the default landing/working model;
- mobile being treated as a separate bottom-tab dashboard product;
- page-level toolbars that expose every utility action at once;
- a standalone Source Hunt form being treated as the primary source-analysis product;
- multiple competing navigation systems being visible simultaneously.

Campaigns, releases, datasets, analysis services, audit, reports, review/adjudication and other governed capabilities remain supported. They are progressively disclosed specialist/deep views of the same assessment/workspace state.

## Retired reference-derived concepts

Do not implement these merely because they appear in generated/reference screenshots or external component libraries:

- MonkeyCode or Threxa branding;
- `Projects` navigation copied from MonkeyCode;
- `Basic`, `Pro` or other reference-product account tiers;
- fictional model selectors such as `deepseek-v4-flash`, `gpt-4.1` or `vulnhunter-v1` unless a repository-backed product decision explicitly adds such a control;
- GitHub SSO or other unsupported sign-in methods;
- a generic operator `Pause` button;
- Share controls, layouts or other screenshot actions that are not repository-backed;
- DataHub-specific product language unless it is actually part of a VulnHunter workflow;
- browser-created operational percentages or success states;
- Beautiful UI Fine-tune controls, model/provider pickers, dictation, demo commands or sample business content when not repository-backed;
- any “Thinking” view that displays hidden chain-of-thought or private model reasoning.

## Current implementation debt explicitly rejected on 2026-08-11

The following patterns were observed in the then-current browser implementation and are now explicitly classified as **presentation debt**, not product precedent:

1. a four-card state strip for `Authorization`, `Scope`, `Approval` and `Active` occupying the top of the ordinary conversation workspace;
2. a horizontal page-header action row containing `Source Hunt`, `Search`, `Export`, `History` and `New workspace`;
3. `Runs`, `Scanner`, `Execution` and `Entry point` KPI-style cards as the primary history/workspace presentation;
4. giant dark dashboard panels inside the cream product for ordinary source-analysis workflows;
5. a large Source Hunt form as the default/primary way to begin repository analysis;
6. giant empty vertical regions between sparse messages and the composer;
7. assistant copy with insufficient contrast against the cream canvas;
8. tiny status/helper text that becomes effectively unreadable on phone;
9. desktop action layouts clipped on phone, including truncated controls such as `New wo…`;
10. a mobile layout that squeezes desktop composition rather than becoming a one-column task workspace;
11. multiple navigation/action systems competing for attention;
12. decorative blue shield/glow treatments that conflict with the locked warm editorial visual identity;
13. dashboard cards that merely expose backend nouns instead of helping the current conversational task;
14. context/detail areas shown persistently when the user has not requested details;
15. additional late-loaded CSS layers used only to override earlier contradictory presentation.

Future agents must remove/refactor these patterns when working on the affected surface. They must not preserve them because a test, selector, screenshot or template already contains them.

## Retired implementation strategy

The following frontend strategy is also retired:

```text
find a visual defect
→ add another late CSS file or selector override
→ leave the contradictory primitive in place
→ repeat
```

The accepted strategy is:

```text
identify the canonical component/style owner
→ remove or consolidate contradictory rules
→ reuse shared tokens/primitives
→ update responsive behavior at the component owner
→ remove dead presentation debt when safe
→ verify real desktop + phone flows
```

Do not use `!important` or stylesheet load order as the normal way to enforce the design contract.

## Historical documents and tests

A historical document may remain in the repository because it contains useful implementation history, security rationale, acceptance evidence or architecture detail. Where its visual/navigation wording conflicts with the locked UI contract or agent implementation standard, the locked sources win.

Existing runtime code or tests may still encode a pre-redesign interface. Their presence documents implementation history, not the approved product. Do not treat an old CSS-token assertion, navigation-label assertion, DOM selector or screenshot as permission to revert the design contract.

A test that encodes a deprecated presentation detail should be replaced with an assertion of the canonical interaction/semantic contract while preserving security and functional behavior.

## Deletion rule

Do not delete useful security, audit, worker, evidence, review or historical documentation merely because its UI examples are old. Remove or rewrite only guidance that is actively misleading, duplicated as a competing authority, or unsafe to follow without context.
