# Responsive and Accessibility Requirements

**Visual source of truth:** `docs/design/VULNHUNTER_UI_CONTRACT.md`  
**Implementation standard:** `docs/design/AI_AGENT_UI_IMPLEMENTATION_STANDARD.md`

Desktop and mobile are the same chat/task-first VulnHunter product, not separate dashboard designs and not the same desktop grid at different scale.

## 1. Responsive behavior

### Desktop

- Use a compact task/chat sidebar, target approximately `260–300px`.
- Give the main working width to conversation, task state and the persistent composer.
- A contextual detail area may open beside the conversation but is closed by default.
- Do not use permanent metric rails or wide utility-button strips to consume the main task area.
- Keep long-form assistant text in a comfortable reading width rather than stretching it across the entire viewport.

### Mobile

- Convert the sidebar into a true overlay task/chat drawer.
- Use a one-column conversation/task layout.
- Do not leave a desktop sidebar permanently visible.
- Do not shrink four-column or two-column dashboard grids into tiny cards.
- Do not squeeze a desktop toolbar into the phone header.
- Do not require horizontal scrolling to reach an essential action.
- Do not truncate primary actions into labels such as `New wo…` because the desktop composition was retained.
- Cards approach the available width with readable padding.
- Large evidence, findings, source detail and specialist information become full-width cards, sheets, drawers or deep views.
- Tables use priority fields and detail disclosure; do not scale an entire desktop table down until text is unreadable.
- The task composer remains reachable during running work, approval waits, queued follow-ups and recovery states.
- The cream dotted surface, square geometry, hard offset shadows, type hierarchy and dusty-pink state language remain consistent.

### Responsive widths to verify

Meaningful UI changes should be checked at representative widths near:

- `360px`;
- `390px`;
- `412px`;
- `768px`;
- `1024px`;
- `1280px`;
- `1440px`.

The exact device model is not the design contract; the absence of broken layout across representative sizes is.

## 2. Readability requirements

The product may be technical and restrained, but it must not become microscopic.

- Desktop body/conversation copy is generally around `14–16px`.
- Phone body/conversation copy is generally around `15–17px`.
- Secondary metadata may be smaller but remains legible at normal browser zoom.
- Assistant message text on the cream background must use high enough contrast for ordinary reading.
- Long URLs, hashes, filenames, package names and code must wrap, scroll inside a bounded technical container, or use safe truncation with a way to inspect the full value.
- Do not reduce text size merely to keep a desktop control row on one line.
- Whitespace is purposeful; large blank areas must not separate the user from important task state or make the interface look unfinished.

## 3. Touch and interaction

- Critical touch targets are at least approximately `44px` in both dimensions.
- Composer send, attachment, drawer/menu, approval/confirmation and destructive controls must be comfortably tappable.
- Overlays/sheets must not place primary controls under browser/system bars.
- The mobile drawer and contextual sheets have predictable Back behavior.
- Focus should return to the logical trigger after a modal/drawer closes where applicable.

## 4. Progressive disclosure

Smaller layouts may hide secondary metadata behind disclosure, but must not hide:

- authorization/scope warnings;
- confirmation/approval requirements;
- review conflicts;
- integrity failures;
- cancellation state;
- terminal failures;
- current task state;
- the safe next action.

Technical detail may move into context cards/drawers/deep views rather than being compressed into the base chat.

## 5. Accessibility

Required practices include:

- keyboard navigation and logical focus order;
- visible focus states;
- semantic landmarks;
- labelled controls;
- status text/icons in addition to color;
- minimum 44px critical touch targets;
- reduced-motion support;
- screen-reader announcements for meaningful task-state changes;
- accessible dialogs/sheets/menus with focus trapping/restoration where appropriate;
- Android/browser Back behavior where relevant;
- error summaries linked to invalid fields;
- sufficient contrast on the cream/dotted surface and dark sidebar;
- meaningful button/link names rather than icon-only ambiguity;
- no hidden chain-of-thought/private reasoning content exposed to any accessibility channel.

## 6. Immediate responsive failure conditions

A responsive implementation fails if any applicable condition occurs:

- essential horizontal page scroll on a supported phone width;
- clipped or inaccessible primary action;
- desktop sidebar permanently occupying phone width;
- assistant/body text that is effectively unreadable;
- approval/confirmation actions that require horizontal scrolling;
- a composer that becomes unreachable or is obscured by the layout;
- evidence/code forcing uncontrolled viewport expansion;
- a header/action row wider than the phone;
- desktop-only status/KPI cards made tiny instead of being restructured;
- multiple navigation systems consuming most of the phone screen.

A responsive implementation is not accepted until the same critical workflow can be completed on supported desktop and phone layouts using truthful backend state and the same product hierarchy.
