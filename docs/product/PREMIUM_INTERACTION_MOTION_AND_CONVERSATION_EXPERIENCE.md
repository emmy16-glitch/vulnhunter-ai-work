# VulnHunter Premium Interaction, Motion and Conversation Experience Standard

**Status:** Binding post-architecture product-quality and implementation programme  
**Owner:** Emmanuel Okunlola  
**Repository:** `emmy16-glitch/vulnhunter-ai-work`  
**Created:** 2026-08-02  
**Applies to:** authentication, conversation, uploads, task execution, navigation, inspector, activity, findings, evidence, graph, reports, forms, controls, overlays, desktop pointer behaviour, mobile touch behaviour, accessibility, perceived performance and frontend motion architecture

---

## 0. Authority, ownership and non-duplication rule

This document defines the interaction quality, motion system, microinteractions,
perceived performance and conversation behaviour required for VulnHunter to feel
like one deliberate, high-quality product.

It does not replace or restate the existing owners:

- `docs/product/AI_FIRST_ASSESSMENT_WORKSPACE_ARCHITECTURE.md` owns required
  product behaviour, information architecture, lifecycle meaning and the
  AI-first workspace definition of done;
- `docs/product/AI_FIRST_ASSESSMENT_WORKSPACE_IMPLEMENTATION_STANDARD.md` owns
  the state-model migration, canonical projection, create-or-bind boundary,
  error/retry contracts, frontend state ownership and core implementation
  sequence;
- `docs/product/UI_QUALITY_ASSURANCE.md` owns general browser-connected product
  truth, responsive, accessibility and evidence gates;
- this document owns premium interaction behaviour, motion semantics,
  component-state choreography, direct manipulation, chat smoothness,
  perceived-performance behaviour and interaction-specific acceptance.

Agents must not create another document that claims to own the same interaction
or motion programme. New interaction requirements belong here. Changes to
assessment truth, lifecycle, navigation ownership or security boundaries belong
in their existing authoritative documents.

The permanent product rule is:

> VulnHunter must feel calm, precise, fast, tactile, coherent and trustworthy.
> Motion and microinteractions may explain state, hierarchy, continuity or
> feedback, but may never fabricate progress, capability, authority or success.

This standard is not permission to add random animation. A static interface that
is truthful, accessible and responsive is better than an animated interface that
is misleading, slow, distracting or inconsistent.

---

# 1. Mandatory execution order

## 1.1 Do not interrupt the current architecture programme

The active AI-first assessment workspace programme must be completed first.
This includes the authoritative assessment projection, canonical lifecycle,
typed errors, persisted task card, APK path repair, responsive inspector,
navigation consolidation, composer simplification, assessment-scoped results,
website alignment, Source Hunt alignment, content-language pass and frontend
state consolidation.

Do not mix broad interaction-polish work into an active bounded architecture
pull request merely because the same CSS, JavaScript or template files are
nearby.

A current implementation pull request must be finished, tested, reviewed and
merged before a later interaction slice begins.

## 1.2 Preconditions for starting this programme

The premium interaction programme may begin only when all of the following are
true for the supported workflow being polished:

1. the selected assessment is reconstructed from authoritative backend state;
2. lifecycle, failure, retry and allowed actions are backend-derived;
3. the relevant desktop and mobile information architecture is stable;
4. no page displays contradictory assessment identity or terminal state;
5. no fake progress, result, evidence, finding, report or readiness value exists;
6. primary actions are wired and permission-checked;
7. the supported failure and recovery path is implemented;
8. baseline responsive and accessibility defects that would invalidate the
   interaction work are already corrected.

Do not animate around missing state contracts. Do not use transitions to conceal
an incorrect route, stale browser state, unimplemented action or backend error.

## 1.3 Implementation order

Deliver this programme through bounded dependency-ordered pull requests:

1. interaction inventory and measurable baseline;
2. shared motion and interaction tokens;
3. primitive component states;
4. overlay, dialog, sheet and focus behaviour;
5. shell and navigation continuity;
6. login, session and reauthentication experience;
7. conversation, streaming and scroll behaviour;
8. upload, artifact and task-card choreography;
9. inspector, activity, findings, evidence and report transitions;
10. mobile direct manipulation, keyboard and Back behaviour;
11. performance, reduced-motion and accessibility hardening;
12. cross-workflow acceptance and obsolete-animation cleanup.

Do not begin with page-specific hover decoration. Build the shared system first.

---

# 2. Product quality target

## 2.1 Intended feeling

VulnHunter should feel:

- calm rather than noisy;
- precise rather than playful;
- fast rather than rushed;
- tactile rather than decorative;
- intelligent rather than mysterious;
- serious without feeling cold;
- information-dense without feeling cramped;
- responsive without pretending work has completed;
- consistent across desktop and mobile;
- accessible when motion is reduced or disabled.

## 2.2 What “premium” means in this repository

Premium interaction quality means:

- input receives immediate acknowledgement;
- visual response matches the true backend state;
- controls have complete and consistent states;
- movement explains origin, destination or relationship;
- frequent actions use restrained short motion;
- loading preserves orientation and useful content;
- errors preserve completed work and explain recovery;
- mobile interactions feel designed for touch rather than compressed desktop;
- keyboard, pointer and touch users receive equivalent feedback;
- refresh, reconnect and navigation preserve context;
- the product never relies on novelty, glow, blur or animation volume to appear
  sophisticated.

## 2.3 Reference principle

Agents may study high-quality interaction patterns from mature productivity,
security, developer-tool, communication and operating-system products. They may
borrow interaction principles such as clear feedback, spatial continuity,
progressive disclosure and stable layouts.

They must not copy another product's branding, exact visual identity, proprietary
assets, wording, signature animation or information architecture without a
repository-specific reason.

---

# 3. Motion semantics

## 3.1 Every motion requires a purpose

An animation is allowed only when it serves at least one of these purposes:

- acknowledge an input;
- confirm a state transition;
- show where an element came from or went;
- preserve spatial continuity;
- direct attention to required action;
- reveal hierarchy or additional detail;
- communicate loading or active work truthfully;
- distinguish success, partial completion, blocked state or failure;
- support direct manipulation such as a sheet following the user's gesture.

Remove motion that exists only to make the interface look busy.

## 3.2 Motion hierarchy

Use the least motion necessary.

- **State change:** colour, border, icon or opacity may be sufficient.
- **Local reveal:** short fade/translate for menu, tooltip or inline detail.
- **Component expansion:** controlled height/opacity transition when content
  ownership remains obvious.
- **Overlay transition:** deliberate entrance/exit with focus and scroll
  behaviour.
- **Route or workspace transition:** restrained continuity only; navigation must
  not wait for animation.
- **Operational activity:** update the stable task surface rather than repeatedly
  animating the whole page.

## 3.3 Direction and origin

Movement should reflect relationship:

- menus originate from their trigger;
- mobile sheets enter from the edge or region they conceptually occupy;
- inspector content opens from the selected object or contextual action;
- expanded details remain visually attached to their summary;
- returning closes toward the originating context where practical;
- new conversation messages enter in the message flow, not from unrelated screen
  edges.

Avoid arbitrary slide directions.

## 3.4 Interruption safety

Every transition must remain correct when interrupted by:

- rapid repeated input;
- browser Back;
- Android Back;
- route change;
- session expiry;
- network response arriving early or late;
- component unmount;
- viewport change;
- keyboard opening;
- reduced-motion preference changing;
- user closing an overlay before its entrance completes.

Interrupted transitions must not leave:

- body scroll locked;
- focus lost;
- an invisible overlay blocking input;
- a button permanently disabled;
- stale success visible;
- duplicate task cards;
- incorrect `aria-hidden` state;
- an orphan backdrop;
- a route that cannot be revisited.

---

# 4. Shared motion and interaction tokens

## 4.1 One source of truth

Define semantic motion tokens alongside the existing product-interface design
tokens. Runtime CSS and JavaScript must consume those shared tokens rather than
inventing feature-local timing.

Recommended token categories:

```text
motion.duration.instant
motion.duration.fast
motion.duration.standard
motion.duration.deliberate
motion.duration.large

motion.easing.standard
motion.easing.enter
motion.easing.exit
motion.easing.emphasized

motion.distance.xs
motion.distance.sm
motion.distance.md
motion.distance.lg

motion.scale.press
motion.scale.enter

motion.opacity.muted
motion.opacity.disabled
```

Exact values must be validated on realistic Android devices and ordinary
laptops. Starting ranges may be:

| Token | Starting range | Typical use |
|---|---:|---|
| instant | 0–80 ms | pressed acknowledgement, immediate state swap |
| fast | 100–140 ms | hover, focus, icon emphasis |
| standard | 160–200 ms | toggles, menus, tabs, inline reveal |
| deliberate | 220–280 ms | dialog, sheet, inspector transition |
| large | 280–360 ms | major workspace continuity only |

Do not use long transitions for frequent actions. Do not exceed roughly 400 ms
for ordinary interface movement without a documented reason and user testing.

## 4.2 Easing

Use a small semantic easing set:

- standard for ordinary state movement;
- enter for an element becoming present;
- exit for an element leaving;
- emphasized only for a major continuity transition;
- linear only for truly continuous measurable progress or media movement.

Avoid random cubic-bezier values per feature.

Avoid exaggerated spring or bounce behaviour in a security product. A subtle
spring may be used for direct manipulation only when it improves physical
continuity and remains stable under reduced motion.

## 4.3 Distances and scale

Prefer small movement distances such as 4, 8, 12 or 16 CSS pixels.

Large travel across the screen is usually inappropriate for frequent VulnHunter
interactions.

Pressed-scale feedback must be subtle and must not cause surrounding layout
movement. Do not scale text or cards so much that they blur, clip or trigger
motion discomfort.

## 4.4 Reduced motion tokens

Reduced-motion mode is a complete alternative behaviour, not a global
`transition: none` patch added at the end.

Under reduced motion:

- eliminate unnecessary travel;
- replace major translation with opacity or immediate state change;
- stop continuous decorative animation;
- stop looping pulses unless the state still needs a static indicator;
- preserve loading and status through text, icons and announcements;
- retain direct-manipulation correctness without inertial flourish;
- keep focus and route changes understandable.

---

# 5. Complete component-state contract

Every shared interactive component must implement the states that apply to it:

```text
default
hover
focus-visible
pressed
selected
active
loading
disabled
unavailable
locked
success
warning
failure
```

The same component must behave consistently in conversation, inspector,
findings, reports, settings and specialist governance pages.

## 5.1 Buttons

Buttons must provide:

- immediate pressed feedback before an asynchronous response;
- visible keyboard focus;
- stable width while loading;
- loading label that describes the action where useful;
- prevention of unsafe repeated submission;
- truthful transition to success or failure;
- disabled reason when the unmet condition is not obvious;
- no success styling before the backend confirms success;
- no layout jump when an icon or spinner appears.

Examples:

```text
Sign in → Signing in… → Workspace opened
Retry JADX → Retrying JADX… → Attempt 2 started
Confirm plan → Confirming… → Queued
```

Do not replace every label with a spinner. The user should still know what is
happening.

## 5.2 Icon buttons

Icon buttons require:

- accessible name;
- visible focus ring;
- hover and pressed feedback;
- adequate touch target;
- tooltip only when the icon meaning is not obvious;
- no tooltip dependency on mobile;
- stable position when state changes;
- correct toggle semantics when the button represents an on/off state.

## 5.3 Links and navigation actions

Links must remain recognisable without relying only on hover.

Navigation actions must:

- acknowledge activation immediately;
- preserve current selection until the next state is ready;
- avoid blank-screen transitions;
- restore focus appropriately after route change;
- not delay navigation to finish an animation;
- not animate an active marker toward a route that failed to load.

## 5.4 Toggles

A premium toggle must include:

- clear label and current meaning;
- distinct hover, focus, pressed, checked, disabled and loading states;
- smooth but restrained thumb movement;
- server-confirmed state when the setting is authoritative;
- rollback to real state after failure;
- inline failure explanation;
- keyboard and screen-reader operation;
- reduced-motion behaviour;
- no decorative toggle for a capability that is not actually implemented.

A toggle must not represent `unknown`, `checking` or `requires approval` as an
ordinary off state. Use the correct status pattern.

## 5.5 Inputs and text areas

Fields must provide:

- clear resting boundary;
- visible focus without moving the layout;
- persistent label or unambiguous accessible name;
- inline help separate from error text;
- validation after an appropriate interaction, not aggressive premature error;
- preservation of user input after recoverable failure;
- stable height where possible;
- clear disabled/read-only distinction;
- visible autofill state;
- correct mobile keyboard type and enter action;
- no animation that obscures typed text.

## 5.6 Cards and rows

Clickable cards and rows may use subtle:

- border emphasis;
- surface change;
- one- or two-pixel visual lift using transform;
- icon emphasis;
- contextual action reveal.

They must not:

- resize and push neighbouring content;
- hide the only required action behind hover;
- use large moving gradients;
- pulse continuously;
- treat static information as clickable;
- reanimate every row when polling refreshes a list.

Only rows whose meaningful state changed may receive a brief update emphasis.

## 5.7 Tabs and segmented controls

Tabs must:

- show selected state without relying only on motion;
- keep label positions stable;
- move an indicator only when it accurately connects adjacent options;
- support keyboard navigation;
- preserve panel state when appropriate;
- avoid replaying expensive entrance animation whenever the user switches back;
- not animate to a tab whose content fails to load.

## 5.8 Tooltips

Tooltips are supplemental. They must not contain essential instructions or the
only explanation of a disabled action.

They must:

- appear after a restrained delay;
- remain readable under zoom;
- dismiss on Escape and pointer exit;
- not trap focus;
- avoid covering the control or critical status;
- be replaced by visible labels or help on touch interfaces where needed.

---

# 6. Desktop pointer interaction

## 6.1 Hover feedback

Desktop hover should make interactivity obvious without making the product feel
restless.

Allowed patterns include:

- subtle border or surface emphasis;
- controlled icon movement of a few pixels;
- concise contextual actions fading in;
- underline or text emphasis;
- minor transform lift;
- restrained shadow change;
- tooltip for unfamiliar icon-only controls.

## 6.2 Hover restrictions

Do not:

- animate every card on pointer movement;
- create 3D tilt or cursor-following effects;
- use parallax in operational pages;
- require hover to reveal the only destructive, approval or recovery action;
- move text baselines;
- trigger layout shifts;
- use permanent glow after the pointer leaves;
- play repeated entrance animation when crossing child elements.

## 6.3 Pointer and keyboard parity

Anything discoverable or operable with a pointer must also be discoverable and
operable with keyboard navigation.

`focus-visible` must be at least as clear as hover.

---

# 7. Mobile tactile interaction and direct manipulation

## 7.1 Touch acknowledgement

Mobile controls must respond visually on touch-down or the next rendered frame.
The response confirms that the target received the input; it does not claim the
operation succeeded.

Use pressed state, surface change, icon response or subtle scale. Do not depend
on vibration.

## 7.2 Touch targets

Primary touch targets must remain at least 44 by 44 CSS pixels. Adjacent controls
must have enough spacing to prevent accidental activation.

Small visual icons may sit inside larger invisible hit areas, but the hit areas
must not overlap unpredictably.

## 7.3 Sheets and drawers

Mobile inspectors, activity detail and secondary controls may use full-screen
sheets, routes or appropriate bottom sheets.

They must support:

- safe initial focus;
- background scroll lock;
- visible close affordance;
- Android/browser Back;
- gesture dismissal only when the operation is safe to dismiss;
- keyboard and safe-area insets;
- interruption-safe entrance/exit;
- return to the exact conversation and scroll position;
- previous-focus restoration where applicable.

Do not use drag-to-dismiss for an approval, destructive confirmation or form with
unsaved critical input unless an explicit discard flow exists.

## 7.4 Mobile navigation

Mobile navigation must remain stable while:

- the keyboard opens;
- a task card expands;
- upload progress changes;
- an inspector opens;
- a system permission prompt returns;
- the viewport changes between portrait and landscape.

Bottom navigation must not compete with the composer or cover the latest message.

## 7.5 Android Back

Android Back and browser Back must follow a predictable hierarchy:

1. close the top transient menu;
2. close the active sheet/dialog when safe;
3. leave contextual inspector/detail;
4. return to the previous route/workspace;
5. leave the application only when no internal layer remains.

Back must never discard work silently or create duplicate history entries.

---

# 8. Authentication and session experience

## 8.1 Login entrance

The login screen may use a restrained initial reveal, but the form must remain
usable immediately and must not wait for decorative animation.

Focus should land only where intentional. Do not steal focus from password
managers, autofill or accessibility tools.

## 8.2 Field interaction

Login fields require:

- stable labels;
- visible focus;
- password visibility control with correct accessible state;
- Caps Lock or relevant input warning where supported;
- inline validation that does not aggressively shake the entire form;
- preserved username and appropriate input after ordinary failure;
- no animated placeholder used as the only label.

A small controlled error emphasis may be used, but text and accessible
announcement carry the meaning.

## 8.3 Submission

On submit:

1. acknowledge the press immediately;
2. prevent unsafe duplicate submission;
3. change the label to a truthful pending state;
4. keep the form dimensions stable;
5. retain a cancellation path only if the underlying request supports it;
6. transition to the intended authenticated destination after confirmed success;
7. preserve entered data and explain recovery after recoverable failure.

## 8.4 Reauthentication and expiry

Session expiry must not produce a confusing full reset.

The product must:

- explain that authentication is required again;
- preserve safe workspace context;
- return to the intended action after successful reauthentication where policy
  permits;
- distinguish expired session from invalid credentials;
- avoid replaying a destructive action automatically;
- avoid stale success animation from the expired request.

## 8.5 Login success

Login success may use a short controlled transition into the workspace. Do not
show confetti, large logo animation or a fake loading phase.

---

# 9. Premium conversation experience

## 9.1 Stable conversation shell

The conversation must behave as one continuous workspace. Sending, streaming,
uploading, task execution and result inspection must not make the layout feel as
though unrelated applications are being swapped in and out.

## 9.2 Message submission

When a message is sent:

- render the user message immediately with a truthful pending/sending state;
- clear or retain composer text according to a recoverable-send contract;
- prevent accidental duplicate submission;
- show failed-send state on the same message;
- offer safe retry without duplicating the logical message;
- preserve attachment association;
- announce failure accessibly;
- keep the composer available unless policy or a modal truly blocks it.

Do not present a message as delivered when the server did not accept it.

## 9.3 Streaming response

Streaming must:

- update text smoothly without re-rendering the whole conversation;
- preserve selection and copy behaviour;
- avoid layout jumps caused by replacing message containers;
- expose a clear generating state;
- distinguish provider response from assessment-worker activity;
- support cancellation only when the backend can cancel generation;
- end in a stable message state;
- show a recoverable interrupted state if streaming stops.

Do not use a fake typing animation after the complete response is already
available. Do not animate individual characters merely for decoration.

## 9.4 Autoscroll

Autoscroll must be user-controlled:

- follow new content while the user is already near the bottom;
- stop following when the user deliberately scrolls upward;
- show `Jump to latest` when newer content exists;
- preserve the user's reading position during streaming;
- return to the exact position after opening and closing contextual detail;
- not fight the user after they dismiss the latest-message affordance.

## 9.5 Message arrival

New messages may enter with a subtle opacity/short-distance transition. Existing
messages must not reanimate when polling, reconnection or state projection
refresh occurs.

## 9.6 Composer interaction

The composer must remain stable with:

- attachment control;
- text entry;
- mode control;
- send action;
- mobile keyboard;
- long content;
- safe-area inset;
- latest-message affordance;
- background upload indicator.

Secondary model, provider and diagnostic controls must not crowd the primary
composer.

The send button should change state without changing the surrounding layout.

## 9.7 Conversation continuity

Opening Activity, Findings, Evidence, Report or a finding detail must preserve:

- workspace ID;
- selected assessment ID;
- conversation position;
- expanded task state;
- unsent composer draft where safe;
- active upload state;
- appropriate focus return.

Returning must not create a duplicate conversation or reset the selected
assessment.

---

# 10. Upload and artifact interaction

## 10.1 Attachment selection

Support desktop file selection, drag-and-drop and mobile file picking with clear
feedback.

After selection, immediately show:

- filename;
- size;
- type where known;
- selected state;
- remove/replace action before upload when safe.

Do not imply validation before validation completes.

## 10.2 Upload progress

Use byte-accurate progress from the upload system.

The product may show:

- one full upload card inside the workspace;
- one compact global indicator outside the workspace;
- one completion or failure notification.

Do not simultaneously show conflicting modal, banner, toast, footer and card
percentages.

Progress animation must track the real value. It must not continue moving when
no progress event has arrived.

## 10.3 Upload interruption and recovery

Interrupted upload must show:

- preserved bytes/chunks where supported;
- whether upload can resume;
- whether user action is required;
- safe retry/cancel action;
- no duplicate artifact creation after timeout or reconnect.

Resuming should continue the same logical upload where the backend supports it.

## 10.4 Validation transition

Upload completion and artifact validation are separate states.

Use a clear transition:

```text
Uploading → Uploaded, validating → Validated → Assessment created/bound
```

Do not animate directly from 100% uploaded to analysis running when validation,
assessment creation or plan confirmation has not completed.

## 10.5 Replacement flow

Replacing an artifact must be explicit. The product must explain whether the
replacement creates a new assessment, a new artifact revision or invalidates an
existing plan.

Do not silently replace the artifact when the user attaches another file.

---

# 11. Live task card and operational activity

## 11.1 One stable task surface

Each active operation has one primary task card that updates in place from
authoritative events.

Do not append a new repetitive message for every poll or stage update.

## 11.2 Stage transitions

Allowed transition feedback includes:

- newly completed stage receives a brief success emphasis;
- current stage receives active emphasis;
- waiting state becomes visually calm;
- approval-required state draws restrained attention;
- failure highlights the exact stage;
- retry creates and labels a new attempt;
- terminal completion settles into a stable summary.

The whole card must not replay its entrance animation when one stage changes.

## 11.3 Progress truth

Percentage is allowed only for:

- uploaded bytes;
- a declared measurable batch;
- a documented weighted-stage model tied to real completion;
- another exact measurable quantity.

For analysis, prefer:

```text
Stage 4 of 8
Running JADX extraction
```

Do not derive percentage from elapsed time or an arbitrary polling counter.

## 11.4 Active indicators

An active indicator may pulse subtly only while authoritative state confirms the
operation is active.

Under reduced motion, use a static icon and text.

Do not pulse:

- queued work;
- scheduled work;
- blocked work;
- a static artifact;
- a failed operation;
- an operation with a lost worker lease.

## 11.5 Failure transition

Failure must not appear as a sudden generic red banner detached from the task.
The card should transition to a stable failure summary containing:

- exact stage;
- user-readable category;
- preserved completed work;
- attempt number;
- safe retry scope;
- required user or operator action;
- technical-detail link;
- stable redacted reference ID.

Failure motion must be restrained. Do not flash the screen or shake the complete
workspace.

## 11.6 Retry

Retry acknowledgement must distinguish:

```text
Retry requested
Attempt 2 queued
Attempt 2 running
Attempt 2 completed/failed
```

Do not erase the previous attempt or animate the old failure into success.
History remains inspectable.

---

# 12. Menus, dialogs, sheets and overlays

## 12.1 Shared overlay controller

Menus, dialogs, confirmation panels and sheets must use shared behaviour for:

- stacking;
- backdrop;
- body scroll lock;
- initial focus;
- focus containment;
- Escape;
- Android/browser Back;
- safe dismissal;
- previous-focus restoration;
- interruption cleanup;
- reduced motion;
- safe areas and virtual keyboard.

Do not reimplement these rules independently in conversation, inspector,
settings and reports.

## 12.2 Menu motion

Menus should open quickly from their trigger, remain aligned under zoom and
close without delaying the selected action.

Clicking an item must not wait for the closing animation before invoking a safe
local action, unless sequencing is necessary to prevent state corruption.

## 12.3 Dialog motion

Dialogs use a restrained fade/scale or fade/translate. The backdrop must not
continue animating after the dialog is interactive.

Destructive dialogs must not use playful bounce or celebratory success.

## 12.4 Mobile sheets

Mobile sheet motion should preserve the sense that the sheet is attached to the
current task. Full-screen detail routes may be preferable when content is long,
complex or deeply navigable.

Do not force large evidence tables into a small draggable sheet merely to use an
animation pattern.

## 12.5 Toasts and notifications

Use toasts only for concise non-blocking confirmation or awareness.

Do not use a transient toast as the only location for:

- task failure;
- approval requirement;
- upload recovery;
- evidence integrity problem;
- unsaved destructive result;
- session expiry.

Persistent operational state belongs in the owning task surface.

---

# 13. Inspector, activity and result continuity

## 13.1 Inspector opening

Desktop inspector opens only with meaningful selected assessment context.

Opening from a task, finding, evidence item or report action should select the
correct tab and item without replacing the assessment state.

## 13.2 Inspector transition

The inspector may slide/fade into its allocated desktop region without
compressing the conversation below its readable minimum.

Closing must restore the conversation width and preserve scroll position.

On mobile, use a route or full-screen/appropriate bottom sheet rather than
side-by-side compression.

## 13.3 Activity updates

Activity timeline additions may receive a brief new-item emphasis. Existing rows
must not reanimate after polling or reconnection.

Technical details expand in place or in contextual detail without moving the user
to an unrelated global page.

## 13.4 Findings

A newly persisted finding may be highlighted briefly, but the product must not
celebrate vulnerability discovery.

Severity motion, flashing red states or dramatic effects are prohibited.

Finding status changes must preserve evidence and review context.

## 13.5 Evidence

Evidence detail should reveal provenance progressively. Expanding technical
metadata must not shift the user far away from the selected evidence summary.

Copy actions require immediate acknowledgement and accessible confirmation.

## 13.6 Graph

Graph motion is permitted only when it improves spatial understanding of real
relationships.

Do not animate a lone artifact node as though an attack path exists.

Graph layout movement must be controllable, must stop after stabilisation and
must respect reduced motion. User-selected nodes must not jump position during
background refresh unless the graph structure truly changed.

## 13.7 Reports

Report generation, rendering and publication remain distinct.

Use named stages or exact readiness states. Do not show a fake generation
percentage.

When a report becomes available, update the existing assessment-scoped report
surface. Do not redirect unexpectedly to a global pilot-report page.

---

# 14. Loading, empty, blocked and failure states

## 14.1 State separation

The interface must visibly and semantically distinguish:

```text
initial loading
background refresh
empty
input required
confirmation required
approval required
queued
running
blocked
dependency unavailable
partially completed
failed
cancelled
complete
report ready
```

A spinner must not represent all of these states.

## 14.2 Skeletons

Use skeletons only when the content structure is known and the expected delay
makes them useful.

Skeletons should resemble the actual layout and stop once content or an error is
available.

Do not use shimmering skeletons for short local state changes, buttons or known
empty pages. Under reduced motion, use static placeholders.

## 14.3 Background refresh

Preserve existing useful content during safe refresh. Show a restrained refresh
indicator rather than blanking the entire page.

Do not reset filters, selected assessment, scroll position or expanded details
merely because data was refreshed.

## 14.4 Empty states

Empty states are compact and contextual. They may use a subtle entrance but must
not animate large decorative illustrations.

They include one meaningful next action where policy permits.

## 14.5 Blocked states

Blocked state must explain:

- what is blocked;
- why;
- who can resolve it;
- what was preserved;
- what the user can do now.

Do not use continuous warning animation.

## 14.6 Error persistence

Operational errors remain visible in the owning context until resolved or
explicitly dismissed. A transient toast alone is insufficient.

---

# 15. Perceived performance and responsiveness

## 15.1 Immediate acknowledgement

Pointer, keyboard and touch activation should receive visual acknowledgement in
the next rendered frame where practical.

Acknowledgement is not success.

## 15.2 Stable layout

Avoid layout shift during:

- button loading;
- message streaming;
- upload progress;
- task-stage updates;
- validation errors;
- navigation selection;
- inspector opening within defined desktop limits;
- font loading;
- icon loading.

Reserve space where the state transition is predictable.

## 15.3 Progressive rendering

Render trustworthy available information before slower secondary details.

Examples:

- show assessment identity before optional technical metadata;
- show the message shell before provider provenance;
- show preserved evidence counts before loading full evidence detail;
- show report readiness summary before loading preview.

## 15.4 Optimistic updates

Use optimistic updates only when:

- the operation is safe;
- rollback is clear;
- duplicate submission is idempotent;
- the user is not shown authoritative success prematurely.

Do not optimistically display approval granted, worker running, finding verified,
report published or release completed.

## 15.5 Animation implementation

Prefer compositor-friendly `transform` and `opacity` where appropriate.

Avoid:

- animating layout-heavy properties continuously;
- large continuous blur or filter effects;
- expensive box-shadow animation on many elements;
- JavaScript animation loops for ordinary controls;
- measuring and mutating layout repeatedly in one frame;
- reanimating complete lists on polling;
- loading a heavy animation dependency for basic transitions;
- motion that blocks input or delays navigation.

## 15.6 Performance baseline

Before broad motion work, record:

- current JavaScript and CSS ownership;
- animation/transition declarations;
- long tasks during primary interactions;
- layout shifts during chat and inspector use;
- realistic Android frame stability;
- conversation streaming responsiveness;
- mobile keyboard opening behaviour;
- reduced-motion state;
- bundle impact.

Each implementation slice must compare against the baseline and must not degrade
critical task responsiveness.

---

# 16. Delight with restraint

Small moments of restrained delight are permitted for:

- confirmed login success;
- completed upload and validation;
- copied identifier or hash;
- saved preference;
- resolved recoverable failure;
- completed assessment;
- newly verified result;
- restored connection.

Appropriate patterns include:

- concise check/icon transition;
- subtle surface confirmation;
- short status change;
- restrained success emphasis;
- accessible confirmation message.

Prohibited patterns include:

- confetti;
- fireworks;
- particles;
- bouncing controls;
- dramatic screen flashes;
- permanent neon glow;
- gaming-dashboard treatment;
- celebratory vulnerability effects;
- large mascot animation;
- cursor trails;
- parallax on operational pages;
- general UI sound effects.

---

# 17. Haptics and sound

Web haptics are optional and must not be required for understanding.

Use haptics only when:

- the platform supports them safely;
- the user action is direct and local;
- the feedback is restrained;
- the haptic does not imply success before confirmation;
- the feature remains fully understandable without it.

Do not add general UI sounds. Security workflow status must not depend on audio.

---

# 18. Accessibility and reduced motion

## 18.1 Meaning is never motion-only

Every animated state change must also be communicated through one or more of:

- text;
- icon;
- accessible name/state;
- live-region announcement;
- persistent status;
- focus movement where appropriate.

## 18.2 Focus visibility

Focus must remain visible during and after transitions. Do not animate focus rings
in a way that delays or weakens them.

Opening an overlay moves focus only when appropriate. Closing restores focus to
a meaningful element.

## 18.3 Screen-reader announcements

Announce important asynchronous changes such as:

- message failed to send;
- upload completed or failed;
- validation completed;
- approval required;
- task stage failed;
- retry started;
- assessment completed;
- session expired;
- report became available.

Do not announce every polling update or streaming token.

## 18.4 Reduced motion acceptance

Reduced-motion mode must be tested across:

- login;
- navigation;
- conversation message arrival;
- streaming;
- upload progress;
- task card;
- menus;
- dialogs;
- mobile sheets;
- inspector;
- findings/evidence/report detail;
- graph;
- notifications.

## 18.5 Zoom and reflow

At 200% zoom and narrow widths:

- animation must not move critical controls off-screen;
- focus remains visible;
- overlays fit or scroll internally;
- tooltips do not obscure the trigger;
- mobile card conversion remains usable;
- text does not clip;
- no horizontal scrolling is required for ordinary tasks.

## 18.6 Motion sensitivity

Avoid large zooming, spinning, continuous movement and rapid flashing. No
interaction may flash at a rate or intensity that creates a seizure risk.

---

# 19. Interaction-specific testing matrix

Each affected slice requires automated and manual evidence for the states that
apply.

## 19.1 Input methods

Test:

- mouse hover;
- mouse click;
- keyboard Tab and Shift+Tab;
- Enter and Space activation;
- Escape;
- touch press;
- Android Back;
- browser Back/forward;
- screen reader/TalkBack where practical.

## 19.2 Component states

Test:

- default;
- hover;
- focus-visible;
- pressed;
- selected;
- loading;
- success;
- failure;
- disabled;
- unavailable;
- reduced motion;
- interruption during transition.

## 19.3 Network and lifecycle conditions

Test:

- fast success;
- slow success;
- request timeout after backend success;
- duplicate tap/submission;
- disconnect/reconnect;
- stale session;
- stale CSRF;
- server validation failure;
- worker unavailable;
- partial result;
- retry;
- cancellation race;
- refresh during active work;
- device switching.

## 19.4 Conversation conditions

Test:

- short message;
- long message;
- code block;
- streaming response;
- interrupted stream;
- user scrolls upward during stream;
- jump to latest;
- failed send and retry;
- keyboard open and closed;
- attachment plus text;
- task card updating while user reads earlier messages;
- inspector open and closed;
- return to exact scroll position.

## 19.5 Upload conditions

Test:

- valid APK;
- large filename;
- long filename;
- interrupted upload;
- resumed upload;
- duplicate finalisation;
- validation failure;
- replacement flow;
- navigation away and return;
- background completion;
- one authoritative progress value.

## 19.6 Viewports

Test at minimum:

- common desktop Chromium;
- wide desktop;
- tablet width;
- narrow Android Chrome portrait;
- short-height landscape where relevant;
- Android desktop-site simulation;
- keyboard open and closed;
- safe-area simulation;
- 200% zoom;
- reduced motion.

## 19.7 Acceptance assertions

Automated checks should verify where practical:

- no body-level horizontal overflow;
- no duplicate active navigation;
- no invisible overlay intercepting input;
- focus remains inside a modal/sheet when required;
- focus returns after close;
- body scroll lock is removed;
- button width is stable during loading;
- no duplicate logical submission;
- no fake success before backend confirmation;
- no repeated animation of unchanged rows;
- reduced-motion media query changes behaviour;
- active pulse is absent for queued, scheduled, blocked and failed states;
- scheduled or static content does not show a live waveform;
- task progress corresponds to authoritative data;
- state persists after refresh/reconnect.

Pair visual assertions with backend or projection assertions whenever the motion
represents lifecycle, progress, approval, evidence, findings or reports.

---

# 20. Evidence required in every interaction pull request

Each pull request must include:

1. the interaction problem and affected user task;
2. the authoritative state that drives the interaction;
3. before/after behaviour description;
4. shared tokens/components changed;
5. success, failure and interruption tests;
6. reduced-motion result;
7. keyboard and focus result;
8. mobile touch/Back/keyboard result where relevant;
9. performance or bundle impact;
10. screenshots or recordings of meaningful states;
11. machine-readable browser report where the repository supports it;
12. documentation reconciliation;
13. obsolete local transition or override removed;
14. remaining limitation stated precisely.

A recording of a smooth animation is not sufficient evidence when the underlying
state is fabricated, stale or browser-owned.

---

# 21. Detailed implementation programme

## Slice 1 — Inventory and baseline

Goal:

- catalogue all CSS transitions, animations and keyframes;
- catalogue JavaScript animation/state timers;
- identify inconsistent hover, focus, pressed, loading and disabled states;
- identify duplicate loaders, skeletons and progress indicators;
- record desktop and Android performance baselines;
- capture reduced-motion behaviour;
- identify overlays with separate focus/scroll implementations;
- identify unchanged rows/cards that reanimate during polling.

Deliverable:

- maintained inventory or implementation note;
- no broad product redesign;
- exact candidate list for consolidation.

## Slice 2 — Semantic tokens

Goal:

- add shared duration, easing, distance, scale and reduced-motion tokens;
- wire tokens into the design-token source and runtime output;
- replace arbitrary values in shared primitives first;
- add tests preventing unsupported token drift.

Do not mass-replace values without reviewing the meaning of each transition.

## Slice 3 — Primitive controls

Goal:

- standardise Button, IconButton, LinkButton, toggle, checkbox, radio, input,
  textarea, select, tab and menu-item states;
- preserve stable dimensions;
- implement pointer, keyboard and touch parity;
- remove feature-local duplicated interaction rules.

## Slice 4 — Overlay controller

Goal:

- unify menu, dialog, sheet and contextual overlay behaviour;
- implement focus, Escape, Back, scroll lock, safe closure and interruption
  cleanup;
- add reduced-motion variants;
- preserve safe areas and keyboard usability.

## Slice 5 — Shell continuity

Goal:

- make sidebar, topbar, conversation and contextual inspector transitions
  coherent;
- preserve assessment selection and scroll;
- ensure navigation does not wait for animation;
- eliminate page flashes and duplicate active markers;
- retain role-aware destination truth.

## Slice 6 — Authentication and session

Goal:

- polish login field, password visibility, validation, submission and success;
- preserve autofill and password-manager behaviour;
- implement session-expiry and reauthentication continuity;
- prevent duplicate submission and stale success.

## Slice 7 — Conversation experience

Goal:

- stabilise message sending, failed-send retry, streaming and autoscroll;
- implement user-controlled jump-to-latest;
- stop full conversation re-render animation;
- preserve keyboard, drafts and scroll context;
- separate conversation-provider state from assessment-worker state.

## Slice 8 — Upload and task execution

Goal:

- provide one truthful upload experience;
- choreograph upload, validation, assessment create/bind and planning states;
- update one task card in place;
- animate only changed stages;
- preserve attempts, failures and recovery.

## Slice 9 — Inspector and results

Goal:

- implement contextual desktop inspector and mobile detail transitions;
- preserve originating assessment and chat position;
- standardise activity, findings, evidence, graph and report update behaviour;
- prevent celebratory or misleading vulnerability motion.

## Slice 10 — Mobile direct manipulation

Goal:

- verify touch feedback, sheets, drawers, Back hierarchy and keyboard stability;
- fix gesture interruption and scroll-lock defects;
- ensure no essential hover-only action;
- test realistic Android performance and safe areas.

## Slice 11 — Performance and accessibility

Goal:

- remove expensive or unnecessary animation;
- verify reduced motion comprehensively;
- verify screen-reader announcements and focus;
- verify 200% zoom, long text and high-density states;
- enforce no layout shift during key interactions;
- document performance impact.

## Slice 12 — Cross-workflow acceptance and cleanup

Goal:

- run login → conversation → website/APK/Source assessment → activity → findings
  → evidence → report workflows on desktop and phone;
- remove obsolete keyframes, loaders, transition helpers and override files;
- reconcile tokens, component ownership and documentation;
- record remaining real limitations;
- verify the product remains useful with animation disabled.

---

# 22. Anti-patterns and mandatory rejection rules

Reject or remove changes that introduce:

- random animation without a user-state purpose;
- page-wide entrance animation on every route;
- repeated list animation during polling;
- hover-only essential actions;
- fake typing after complete text is available;
- fake progress or continuously moving indeterminate bars for a known blocked
  state;
- success animation before backend confirmation;
- animated skeletons for immediate local interactions;
- large spring/bounce motion in operational workflows;
- continuous pulses on queued, scheduled, blocked or failed work;
- fake waveform or activity animation without real signal;
- confetti, particles, fireworks or gaming effects;
- excessive glass blur or background filters;
- cursor-following effects, 3D card tilt or operational parallax;
- button shrink/jump while loading;
- overlays that leave scroll locked or focus lost;
- route transition that delays navigation;
- generic spinner replacing a meaningful task state;
- local timers that pretend a backend operation advanced;
- another frontend lifecycle store;
- feature CSS files named `polish`, `final-fixes`, `bridge`, `compatibility`,
  `temporary`, `mobile-patch` or similar when a shared owner should be fixed;
- heavy animation dependency without clear need, bundle review and accessibility
  plan;
- UI sounds as general feedback;
- documentation-only claims of premium quality.

---

# 23. Permanent invariants

1. Backend and persisted projection remain authoritative.
2. Input acknowledgement is immediate, but success waits for real confirmation.
3. No animation may change or imply authorisation, approval, review, release or
   publication state.
4. No animation may fabricate progress, findings, evidence, reports or worker
   activity.
5. Provider health, worker health and assessment lifecycle remain separate.
6. One logical action produces one logical submission under repeated input.
7. Button dimensions and surrounding layout remain stable during loading.
8. Hover is never required for a necessary action.
9. Keyboard and touch parity are mandatory.
10. Android/browser Back and Escape follow a predictable layer hierarchy.
11. Reduced motion is a complete tested mode.
12. Interrupted transitions leave no stale overlay, lock, focus or state.
13. Existing surfaces remain the only owners of their workflow and business
    rules.
14. Motion wrappers may present state but may not create a competing state
    machine.
15. Percentage is shown only for measurable progress.
16. Unchanged content does not reanimate during polling.
17. Static, scheduled, queued, blocked and failed states do not use active/live
    motion.
18. Critical feedback remains understandable when animation is disabled.
19. Responsive quality means efficient real-phone task completion, not merely no
    horizontal overflow.
20. Product seriousness does not justify unreadable density or weak feedback.

---

# 24. Definition of done

The premium interaction, motion and conversation programme is complete only
when:

- one semantic motion-token system is used across the product;
- shared controls have complete consistent states;
- pointer, keyboard and touch users receive equivalent feedback;
- login is responsive, stable, autofill-safe and recoverable;
- conversation sending, streaming, scrolling and retry remain smooth and
  truthful;
- the composer remains stable with the mobile keyboard;
- upload has one authoritative progress experience;
- upload, validation, assessment creation and planning remain distinct;
- one persisted task card updates in place;
- unchanged stages and rows do not reanimate;
- failure and retry preserve prior attempts and evidence;
- overlays share focus, Escape, Back, scroll-lock and interruption behaviour;
- desktop inspector and mobile detail preserve the originating context;
- findings, evidence, graph and reports use restrained truthful transitions;
- loading, empty, blocked, partial, failed and complete states are distinct;
- reduced motion is comprehensive and tested;
- 200% zoom, long text, safe areas and keyboard states pass;
- realistic Android performance remains acceptable;
- no animation delays navigation or blocks an action;
- no fake progress, live indicator, waveform, success or capability exists;
- obsolete local animation and patch layers are removed;
- all required browser, phone, accessibility and backend-state evidence passes;
- documentation agrees with actual implementation;
- the complete product remains understandable and usable with animation disabled.

Until these conditions are met, isolated hover effects or smooth transitions may
look attractive, but VulnHunter must not be described as having a complete
premium interaction experience.
