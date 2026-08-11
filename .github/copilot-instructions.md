# VulnHunter repository instructions for GitHub Copilot

For every VulnHunter task, read `AGENTS.md` first.

For browser UI, template, CSS, JavaScript, navigation, responsive, accessibility, conversation, website authorization, live task state, Source Hunt entry or UI-test work, read and obey in order:

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
12. relevant backend routes/actions/projections/state/tests

Fixed product rules:

- VulnHunter is conversation/task-first, not a generic dashboard.
- MonkeyCode supplies task/workspace structure and interaction behavior only.
- Beautiful UI supplies AI-native component/microinteraction patterns only.
- VulnHunter supplies actual functionality, security authority, terminology, branding and the warm cream/off-white dotted + dusty-pink + compact-dark-sidebar identity.
- Existing markup/CSS/tests are not design authority when they conflict with the locked contracts.
- Authorised public targets are a supported product class, but a public URL is never permission.
- Never enable public scanning by globally relaxing scope checks or removing the private-worker boundary. Follow `PUBLIC_TARGET_ASSESSMENT.md` and implement explicit worker/transport containment.
- A private-only worker must continue to reject public jobs until a reviewed public-capable worker exists.
- Long-running queued/running work must expose persisted operational activity in the same workspace. A generic “backend is running; check elsewhere” response is not an acceptable primary experience when richer backend activity exists.
- Never fabricate progress, tool activity, evidence or findings.
- Never expose hidden chain-of-thought/private model reasoning.
- Never add another global CSS patch layer merely to override contradictory presentation.
- Never squeeze desktop UI onto phone.

Backend authorization, scope, worker capability, approval, verification, human review and publication authority remain authoritative regardless of browser presentation.

When a requested implementation cannot preserve those boundaries, stop and report the exact blocker rather than weakening the product contract.
