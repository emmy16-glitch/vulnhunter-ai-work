# VulnHunter UI and task authority

For every task, read `AGENTS.md` first.

When changing/reviewing browser UI, design, templates, CSS, JavaScript, responsive behavior, navigation, conversation, website/public-target flow, live task state, Source Hunt entry or UI tests, read and obey in order:

1. `AGENTS.md`
2. `vulnhunter/web/AGENTS.md`
3. `docs/design/VULNHUNTER_UI_CONTRACT.md`
4. `docs/design/AI_AGENT_UI_IMPLEMENTATION_STANDARD.md`
5. `docs/design/references/manifest.json`
6. `docs/design/DEPRECATIONS.md`
7. `docs/product/CHAT_FIRST_WORKSPACE.md`
8. `docs/product/LIVE_EXECUTION_ACTIVITY.md`
9. `docs/product/PUBLIC_TARGET_ASSESSMENT.md` when website/public-target behavior is affected
10. `docs/product/UI_ACCEPTANCE_CRITERIA.md`
11. `docs/product/RESPONSIVE_AND_ACCESSIBILITY.md`
12. relevant backend routes/actions/projections/persisted state/tests

Do not treat current markup, CSS, screenshots or tests as authority when they conflict with those files.

Reference hierarchy:

- MonkeyCode = task/workspace structure and interaction behavior only.
- Beautiful UI = AI-native components/microinteractions only.
- VulnHunter = actual functionality, security authority, terminology, branding and warm cream/dotted/dusty-pink + dark-sidebar identity.

Permanent execution rules:

- authorised public targets are supported by product policy, but a public URL never grants permission;
- do not enable public scanning by globally relaxing scope checks or deleting private-worker restrictions;
- preserve private/public target classification, exact authorization, DNS/address containment, Host/TLS identity and explicit worker capability;
- if the worker is private-only, show a truthful blocker until a public-capable worker is implemented;
- running work must show persisted operational activity in the originating workspace when backend activity exists;
- never fabricate tool activity, percentages, evidence or findings;
- never expose hidden chain-of-thought/private model reasoning;
- never create another global CSS patch layer merely to beat contradictory styling;
- never squeeze desktop UI onto phone.

A generic dashboard result, unsafe public-target shortcut, black-box running task, desktop-on-phone layout or reference-derived unsupported function is not acceptable completion.
