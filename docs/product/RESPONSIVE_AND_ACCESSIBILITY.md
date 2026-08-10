# Responsive and Accessibility Requirements

**Visual source of truth:** `docs/design/VULNHUNTER_UI_CONTRACT.md`

Desktop and mobile are the same chat/task-first VulnHunter product, not separate dashboard designs.

## Responsive behaviour

- Desktop uses a compact task/chat sidebar (target approximately 260–300px) and gives the remaining space to the conversation workspace.
- Mobile converts the sidebar into an overlay drawer. It must not leave a desktop sidebar permanently visible or replace the product with an unrelated mobile dashboard.
- Cards stack vertically on narrow screens and approach the available width while preserving readable padding.
- Large evidence, findings and specialist details may become full-screen/deep views or sheets on mobile.
- Do not shrink desktop tables into unreadable miniatures. Prioritize fields and move secondary detail into a drawer/deep view.
- The task composer remains reachable during running work, approval waits, queued follow-ups and recovery states.
- The cream dotted surface, square geometry, hard offset shadows, type hierarchy and dusty-pink state language remain consistent across breakpoints.
- Spacious layout is intentional; do not compress mobile merely to show more controls at once.

Smaller layouts may progressively disclose secondary metadata, but must not hide authorization/scope warnings, review conflicts, approval requirements, release blockers, integrity failures, cancellation state or terminal task failures.

## Accessibility

Required practices include:

- keyboard navigation and logical focus order;
- visible focus states;
- semantic landmarks;
- labelled controls;
- status text/icons in addition to colour;
- minimum 44px touch targets;
- reduced-motion support;
- screen-reader announcements for meaningful task-state changes;
- accessible dialogs/sheets/menus with focus restoration;
- Android/browser Back behaviour where relevant;
- error summaries linked to invalid fields;
- readable long filenames, URLs and hashes without destructive clipping;
- sufficient contrast on the cream/dotted surface and dark sidebar.

A responsive implementation is not accepted until the same critical workflow can be completed on supported desktop and phone layouts using truthful backend state.
