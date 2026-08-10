# Figma Handoff

Figma is a design and review surface, not a runtime connector and not a competing design authority.

Before creating or changing any VulnHunter Figma screen, read:

1. `docs/design/VULNHUNTER_UI_CONTRACT.md`;
2. `docs/design/references/manifest.json`;
3. `docs/product/CHAT_FIRST_WORKSPACE.md`;
4. the repository-backed route/action/state contract for the affected workflow.

## Source-of-truth rule

The locked UI contract owns visual language, spacing, typography, shadows, geometry, sidebar hierarchy and chat-first interaction rules. Figma must express those rules; it must not redefine them.

Visual references never grant product functionality. Do not copy sample branding, account tiers, model names, project concepts, buttons or workflows from a reference unless VulnHunter already supports them.

## File organization

Build foundations and reusable component/state sets before full screens. Use Auto Layout, named variables, semantic layers and component variants. Maintain desktop and mobile states for the same component family rather than creating unrelated visual systems.

## Locked visual direction

VulnHunter uses:

- a warm cream/off-white dotted working surface;
- a compact dark task/chat sidebar;
- dusty pink active/primary accents;
- near-black typography and technical borders;
- bold grotesk headings;
- monospace/typewriter technical UI text;
- editorial italic serif only for rare expressive statements;
- square/nearly square cards and controls;
- hard black zero-blur offset shadows;
- generous whitespace and progressive disclosure.

Avoid gradients, glassmorphism, glow, generic blue/white SaaS styling, soft floating-card shadows, excessive rounding, neon cyberpunk styling and dashboard KPI walls.

## Interaction direction

The primary screen is the conversation/task workspace. Findings, reports, approvals, authorization requirements, Source Hunt setup, APK upload state, worker recovery/failure and queued follow-ups are represented contextually in that workspace first. Dedicated pages are deep views when more room or a governed identity-bound action requires them.

## Approval boundary

Figma and screenshots define approved composition and behaviour only. They do not define backend permission, authorization, scope, review independence, worker truth, finding verification, release eligibility or publication authority.
