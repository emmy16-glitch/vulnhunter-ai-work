# VulnHunter repository instructions for GitHub Copilot

For any browser UI, template, CSS, JavaScript, navigation, responsive, accessibility, conversation or UI-test work, read and obey:

1. `AGENTS.md`
2. `vulnhunter/web/AGENTS.md`
3. `docs/design/VULNHUNTER_UI_CONTRACT.md`
4. `docs/design/AI_AGENT_UI_IMPLEMENTATION_STANDARD.md`
5. `docs/design/references/manifest.json`
6. `docs/design/DEPRECATIONS.md`
7. `docs/product/CHAT_FIRST_WORKSPACE.md`
8. `docs/product/UI_ACCEPTANCE_CRITERIA.md`
9. `docs/product/RESPONSIVE_AND_ACCESSIBILITY.md`

The UI authority hierarchy is fixed:

- MonkeyCode supplies task/workspace structure and interaction patterns only.
- Beautiful UI supplies AI-native component and microinteraction patterns only.
- VulnHunter supplies actual functionality, security authority, terminology, branding and its warm cream/off-white dotted + dusty-pink + dark-sidebar visual language.

Never preserve contradictory existing UI just because markup/tests already exist. Never invent reference-derived features. Never convert VulnHunter into a generic dashboard. Never squeeze desktop UI onto phone. Never expose hidden chain-of-thought. Never add another global CSS patch layer merely to override existing contradictory presentation.

Backend authorization, approval, review, verification and publication authority remain authoritative regardless of browser presentation.
