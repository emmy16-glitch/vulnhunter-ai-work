# VulnHunter Web — Frontend Agent Rules

This file applies to every file below `vulnhunter/web/`.

## Mandatory read order

Before changing templates, CSS, JavaScript, navigation, forms, dialogs, responsive layout or browser interaction:

1. read repository-root `AGENTS.md` for security boundaries;
2. read `docs/design/VULNHUNTER_UI_CONTRACT.md` in full;
3. read `docs/design/references/manifest.json`;
4. read `docs/product/CHAT_FIRST_WORKSPACE.md`;
5. inspect existing shared tokens/components and the backend-backed route/action/state contract for the affected surface.

## Binding product rule

VulnHunter is a conversation/task-first security workspace, not an admin dashboard with a chatbot attached.

- MonkeyCode screenshots are interaction references only.
- Cream/dotted editorial screenshots are visual-language references only.
- The VulnHunter repository is the functional/content source of truth.

Do not copy reference branding, Projects concepts, account tiers, fake model/provider selectors, unsupported SSO, unsupported actions or fictional task states.

## Visual lock

Do not invent local alternatives to the canonical:

- cream dotted working canvas;
- compact dark task/chat sidebar;
- dusty-pink active/primary accents;
- near-black technical borders/text;
- bold grotesk headings;
- monospace/typewriter technical UI;
- square/nearly-square geometry;
- hard black zero-blur offset shadows;
- generous spacing/progressive disclosure.

No gradients, glow, glassmorphism, generic blue/white SaaS redesign, soft floating-card shadows, default large radii or dashboard KPI walls.

## Interaction lock

- Chat/task workspace is the primary surface.
- Findings, reports, approvals, authorization requirements, Source Hunt setup, APK uploads and worker recovery/failure appear contextually in chat first when practical.
- Dedicated pages are deep views of the same persisted state.
- The running-task composer remains usable.
- Follow-up instructions that cannot run immediately are visibly queued.
- Refresh/reconnect reconstructs state; it does not restart work.
- Cancel appears only when supported.
- **Do not add Pause unless an explicit backend operator-pause contract exists.**
- Never invent progress, findings, readiness, approval or completion state in browser code.

## Change discipline

A frontend change that violates `docs/design/VULNHUNTER_UI_CONTRACT.md` is a regression even if it functions.

If the requested implementation appears to require breaking the contract, stop and report the exact conflict instead of silently reinterpreting the design.
