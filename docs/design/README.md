# VulnHunter Design Documentation

This directory contains the binding product-design source of truth.

## Read order

For any frontend, template, CSS, JavaScript, responsive, accessibility or interaction change:

1. [`VULNHUNTER_UI_CONTRACT.md`](VULNHUNTER_UI_CONTRACT.md) — **locked canonical visual and interaction contract**.
2. [`references/manifest.json`](references/manifest.json) — approved visual references and explicit ignore rules.
3. [`../product/CHAT_FIRST_WORKSPACE.md`](../product/CHAT_FIRST_WORKSPACE.md) — chat-first workflow contract.
4. [`../product/UI_QUALITY_ASSURANCE.md`](../product/UI_QUALITY_ASSURANCE.md) — browser, responsive and accessibility evidence gates.
5. Existing shared tokens/components and the backend-backed route/action contracts.

## Permanent interpretation

- MonkeyCode references demonstrate **interaction patterns only**.
- Cream/dotted editorial references demonstrate **visual language only**.
- The VulnHunter repository defines **actual product content and capability**.

Reference images are not specifications for routes, buttons, model/provider names, account tiers or security authority.

## Change control

Do not create another design-system document that competes with the UI contract. New permanent visual rules belong in `VULNHUNTER_UI_CONTRACT.md`. New approved screenshots belong in `references/` and must be registered in `references/manifest.json` with explicit `use_for` and `ignore` fields.

A page-specific implementation note may explain how it applies the contract, but may not redefine colours, spacing, shadows, typography, navigation hierarchy or primary interaction architecture.
