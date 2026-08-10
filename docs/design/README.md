# VulnHunter Design Documentation

This directory contains the binding product-design source of truth.

## Read order

For any frontend, template, CSS, JavaScript, responsive, accessibility or interaction change:

1. [`VULNHUNTER_UI_CONTRACT.md`](VULNHUNTER_UI_CONTRACT.md) — **locked canonical visual and interaction contract**.
2. [`references/manifest.json`](references/manifest.json) — approved visual references and explicit ignore rules.
3. [`DEPRECATIONS.md`](DEPRECATIONS.md) — retired/stale UI guidance that must not be revived.
4. [`../product/CHAT_FIRST_WORKSPACE.md`](../product/CHAT_FIRST_WORKSPACE.md) — chat-first workflow contract.
5. [`../product/UI_QUALITY_ASSURANCE.md`](../product/UI_QUALITY_ASSURANCE.md) — browser, responsive and accessibility evidence gates.
6. Existing shared tokens/components and the backend-backed route/action contracts.

## Permanent interpretation

- MonkeyCode references demonstrate **interaction patterns only**.
- Cream/dotted editorial references demonstrate **visual language only**.
- The VulnHunter repository defines **actual product content and capability**.

Reference images are not specifications for routes, buttons, model/provider names, account tiers or security authority.

The four approved reference images stored in `references/` are intentionally small implementation-reference previews. Their manifest determines what may be copied and what must be ignored. The locked text contract remains authoritative for exact spacing, tokens, shadows, typography, navigation and behaviour.

## Change control

Do not create another design-system document that competes with the UI contract. New permanent visual rules belong in `VULNHUNTER_UI_CONTRACT.md`. New approved screenshots belong in `references/` and must be registered in `references/manifest.json` with explicit `use_for` and `ignore` fields.

A page-specific implementation note may explain how it applies the contract, but may not redefine colours, spacing, shadows, typography, navigation hierarchy or primary interaction architecture.
