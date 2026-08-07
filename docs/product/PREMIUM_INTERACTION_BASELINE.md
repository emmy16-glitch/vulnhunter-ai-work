# Premium interaction inventory and baseline

This note implements the inventory/baseline deliverable required by
`PREMIUM_INTERACTION_MOTION_AND_CONVERSATION_EXPERIENCE.md`. It records how the
current repository interaction surface is measured; it is not a second product
state source and does not claim runtime or physical-device success.

## Reproducible repository baseline

Run from the repository root:

```bash
python scripts/interaction_inventory.py --check
```

The command emits deterministic JSON for the exact checkout. It measures:

- active CSS and JavaScript interaction files;
- transition, animation and keyframe declarations;
- reduced-motion blocks;
- JavaScript timers and animation-frame scheduling;
- native dialog opening, EventSource streaming and loading/progress markers;
- the canonical shared shell owner stack (`tokens.css`, `workspace.css`,
  `premium-interaction.css`, `premium-interaction.js`);
- absence of the retired `workspace-polish.css` and
  `workspace-final-fixes.css` correction layers.

`--check` fails when the shared owner stack disappears, retired correction
layers return, reduced-motion coverage disappears, or the repository no longer
contains measurable interaction motion/scheduling. Unit coverage executes the
same inventory in CI so the baseline evolves with the exact checked-out code
instead of becoming a stale hand-maintained count.

## Evidence boundary

The inventory is static repository evidence. Transition/keyframe/timer counts
are not frame-time measurements and must never be interpreted as assessment,
worker, provider or task progress. Browser automation remains separate from
physical evidence.

The following acceptance categories still require real-device/manual evidence
where the binding quality standard requires it:

- realistic physical Android performance;
- TalkBack behaviour;
- bright-environment/real-device contrast review;
- non-technical usability and subjective polish review.

Those categories must not be inferred from this inventory, Playwright,
responsive Chromium emulation, or repository unit tests.
