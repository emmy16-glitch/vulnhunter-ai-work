# VulnHunter UI authority

When a task changes or reviews any VulnHunter browser UI, design, template, CSS, JavaScript, responsive behavior, navigation, conversation surface or UI test, you MUST read and obey, in order:

1. `AGENTS.md`
2. `vulnhunter/web/AGENTS.md`
3. `docs/design/VULNHUNTER_UI_CONTRACT.md`
4. `docs/design/AI_AGENT_UI_IMPLEMENTATION_STANDARD.md`
5. `docs/design/references/manifest.json`
6. `docs/design/DEPRECATIONS.md`
7. `docs/product/CHAT_FIRST_WORKSPACE.md`
8. `docs/product/UI_ACCEPTANCE_CRITERIA.md`
9. `docs/product/RESPONSIVE_AND_ACCESSIBILITY.md`

Do not treat current markup, CSS, screenshots or tests as the design authority when they conflict with those files.

Reference hierarchy:

- MonkeyCode = task/workspace structure and interaction behavior.
- Beautiful UI = AI-native components and microinteractions.
- VulnHunter = actual product functionality, security authority, branding and warm cream/dotted/dusty-pink visual identity.

A generic dashboard result, desktop UI squeezed onto mobile, reference-derived unsupported functionality, or another CSS override layer is not acceptable completion.
