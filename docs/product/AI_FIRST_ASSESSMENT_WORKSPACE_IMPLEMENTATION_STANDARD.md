# VulnHunter AI-First Assessment Workspace Implementation Standard

**Status:** Binding for migration/state implementation discipline; **subordinate for UI design**  
**UI authority corrected:** 2026-08-11  
**Applies to:** authenticated web workspace, website assessments, APK assessments, Source Hunt, activity, findings, evidence, reports, responsive behavior and frontend migration

## 0. Authority and non-duplication rule

This file is no longer a competing visual/product-design specification.

For any browser UI work, read in this exact order:

1. `AGENTS.md`;
2. `vulnhunter/web/AGENTS.md`;
3. `docs/design/VULNHUNTER_UI_CONTRACT.md`;
4. `docs/design/AI_AGENT_UI_IMPLEMENTATION_STANDARD.md`;
5. `docs/design/references/manifest.json`;
6. `docs/design/DEPRECATIONS.md`;
7. `docs/product/CHAT_FIRST_WORKSPACE.md`;
8. `docs/product/UI_ACCEPTANCE_CRITERIA.md`;
9. `docs/product/RESPONSIVE_AND_ACCESSIBILITY.md`;
10. `docs/product/AI_FIRST_ASSESSMENT_WORKSPACE_ARCHITECTURE.md` for state/lifecycle architecture;
11. this document for migration sequencing and code-quality discipline.

This document must not redefine palette, typography, spacing, geometry, shadows, shell composition, mobile composition or reference priority.

Do not create another competing AI-first workspace specification. Permanent UI rules belong in the locked design documents.

---

## 1. Core implementation principle

The programme is not a cosmetic reskin. It is a combined state, lifecycle, navigation, recovery, accessibility and presentation correction.

However, “state first” is not permission to ship a poor interface. Each completed UI slice must satisfy both:

- backend/state correctness;
- canonical UI/interaction acceptance.

Color polishing must not conceal contradictory state, and backend correctness must not excuse dashboard-first presentation.

---

## 2. Mandatory execution order

For each implementation run:

1. inspect current `main`, relevant open PRs, recent commits, CI and changed files;
2. identify the exact UI/state slice being changed;
3. read the canonical design/agent rules before touching browser code;
4. inspect the backend projection/state powering the surface;
5. identify the existing CSS/component owner rather than adding an override layer;
6. define expected mobile behavior before editing;
7. implement one coherent slice;
8. update tests that encode deprecated presentation while preserving functional/security assertions;
9. run focused verification;
10. run repository gates required by `AGENTS.md` before claiming completion.

Do not bundle unrelated UI redesign, backend behavior and later-slice work merely because files are nearby.

---

## 3. Migration dependency order

Use this dependency order unless the current state proves a later prerequisite is already complete:

1. authoritative workspace/assessment identity and projection;
2. canonical lifecycle and typed errors;
3. persisted live task experience;
4. complete APK path/state alignment;
5. canonical chat/task shell;
6. mobile overlay drawer and one-column workspace;
7. navigation/utility consolidation;
8. composer simplification and persistence;
9. task rows/tool chips/approval/context/finding primitives;
10. evidence/findings/report deep-view alignment;
11. website-flow alignment;
12. Source Hunt conversational entry + focused specialist deep view;
13. empty-state/content-language/readability pass;
14. CSS consolidation and obsolete presentation removal;
15. cross-workflow browser acceptance.

The order does not require waiting for the entire programme to make a touched surface visually compliant. Every changed surface must move toward the canonical contract rather than temporarily adding more debt.

---

## 4. Current presentation debt is not a baseline to preserve

When working on affected surfaces, actively remove/refactor patterns listed in `docs/design/DEPRECATIONS.md`, including:

- the four-card `Authorization / Scope / Approval / Active` state strip;
- the `Source Hunt / Search / Export / History / New workspace` toolbar row;
- KPI-style `Runs / Scanner / Execution / Entry point` cards;
- giant dark Source Hunt/admin panels;
- giant Source Hunt form as primary entry;
- low-contrast/tiny conversation text;
- desktop layout clipped on phone;
- competing navigation systems;
- global CSS override layers created to beat earlier styles.

A stale test asserting these patterns should be migrated to semantic/canonical assertions.

---

## 5. Shared component migration

The target browser architecture should converge on a small set of shared primitives rather than page-specific card families.

Preferred conceptual primitives:

- shell sidebar/drawer;
- task header;
- task row;
- tool chip;
- assistant/user message;
- persistent prompt bar/composer;
- authorization card;
- exact-plan confirmation card;
- independent approval card;
- context/evidence card;
- finding card;
- recommendation/remediation card;
- contextual detail drawer/sheet;
- compact empty/error/recovery state;
- specialist table/list for deep views.

These names describe interaction roles, not a required JS framework.

Reuse Django templates/static assets where appropriate. Do not introduce React or another component framework merely to imitate a reference site.

---

## 6. CSS migration rules

The repository currently contains historical stylesheet layers. Migration must reduce ambiguity.

For each changed component:

1. identify the canonical token source (`tokens.css`);
2. identify the existing component/style owner;
3. remove or consolidate contradictory rules;
4. keep responsive behavior with the component owner where practical;
5. remove dead selectors when safe;
6. avoid `!important` except for a narrowly justified interoperability/accessibility edge;
7. do not create another global patch stylesheet merely to win cascade order;
8. do not create page-local palette/radius/shadow/type systems;
9. preserve CSP and no-inline-script requirements.

A successful migration should reduce the number of places an agent must edit to change one component.

---

## 7. Canonical reference usage during implementation

Before coding a visual/interaction slice, state explicitly:

- which **MonkeyCode** structural behavior applies;
- which **Beautiful UI** primitive applies, if any;
- which VulnHunter backend state powers it;
- which VulnHunter design tokens/geometry apply;
- which reference details are forbidden by the manifest.

Reference screenshots and component sites are comparison inputs, not code generators with authority to invent functions.

---

## 8. Conversation/task implementation requirements

The main workspace must project persisted state into a coherent task experience.

A running operation should provide enough real information to answer:

- what is happening now;
- what completed;
- what comes next;
- whether user action is required;
- which real tool/worker is active when known;
- what evidence exists;
- what failed/recovered;
- what safe next action is available.

Prefer stable task rows and tool receipts over repeated prose messages or decorative progress cards.

Do not show hidden chain-of-thought. User-facing AI activity must be safe and state-oriented.

---

## 9. Composer implementation requirements

The composer remains the primary control surface.

Required behavior:

- reachable on desktop and phone;
- usable while supported long-running work continues;
- attachment flow integrated with the conversation;
- queued follow-up presentation where supported;
- keyboard opening does not cover latest content/actions;
- secondary settings progressively disclosed;
- provider/readiness details do not dominate ordinary composition;
- no desktop-only control row squeezed into phone width.

The primary composer should remain visually simple.

---

## 10. Contextual detail implementation

Desktop may open contextual detail beside the conversation. Mobile converts the same context to a full-width sheet/drawer/deep view.

Context detail may include:

- evidence;
- source/file-line context;
- request/response detail;
- finding detail;
- tool receipt;
- plan identity;
- report detail.

The context area is closed when nothing is selected. It must not become a permanent second dashboard.

---

## 11. Website-flow implementation

Target flow:

```text
chat target intent
→ backend authorization/scope resolution
→ contextual immutable plan
→ required confirmation/approval
→ task execution
→ task rows/tool receipts
→ evidence/findings
→ review/report
```

Do not recreate a standalone scan-creation dashboard as the primary path.

---

## 12. Source Hunt implementation

Target flow:

```text
chat repository intent
→ exact repository/revision/snapshot projection
→ compact Source Hunt setup/task card
→ exact source-processing approval when required
→ queued worker
→ task/tool/evidence/remediation projection
```

The specialist Source Hunt form exists only when exact advanced fields/re-authentication are required. It must adopt the same canonical visual system and should not default to a giant dark panel.

---

## 13. APK implementation

Target flow:

```text
chat attachment
→ resumable upload
→ integrity validation
→ durable artifact/assessment state
→ real static tool receipts
→ evidence/findings
→ separately governed dynamic capabilities where available
```

A tool failure does not fabricate a finding and should not erase completed receipts/evidence.

---

## 14. Error/recovery implementation

Every affected blocked/failed/recovering task should expose from backend truth:

- stage;
- safe reason category;
- stable reference;
- completed stages;
- preserved evidence;
- automatic recovery status;
- retry availability/boundary;
- required user/operator action.

Update the same task surface in place rather than creating another disconnected error dashboard.

---

## 15. Responsive implementation gates

Meaningful workspace changes must be exercised around representative widths:

- `360`;
- `390`;
- `412`;
- `768`;
- `1024`;
- `1280`;
- `1440` CSS pixels.

Immediate failure:

- essential phone horizontal scroll;
- clipped primary controls;
- unreadable body/assistant text;
- desktop sidebar permanently consuming phone width;
- desktop toolbar/grid merely shrunk;
- unreachable composer;
- approval/evidence actions inaccessible without horizontal scrolling.

Mobile design follows `docs/product/RESPONSIVE_AND_ACCESSIBILITY.md`, not historical screenshots of the old implementation.

---

## 16. Browser verification

Real browser evidence is required for significant presentation changes.

Depending on the slice, verify:

- login;
- empty/new workspace;
- task drawer/sidebar;
- running task;
- queued follow-up;
- confirmation/approval;
- evidence/finding context;
- recovery/failure;
- Source Hunt entry/deep view;
- APK attachment/upload;
- desktop contextual detail;
- representative phone widths.

Do not declare success because HTML renders or unit tests pass.

---

## 17. Test migration

Tests should protect semantic and interaction contracts rather than stale CSS/DOM accidents.

Good assertions include:

- required semantic region/control exists;
- backend-derived state is projected correctly;
- unsupported controls are absent;
- mobile drawer behavior works;
- composer stays available during running state;
- reconnect restores persisted state;
- approval/authorization boundaries remain enforced;
- critical phone overflow/clipping regression is covered where practical.

Avoid tests whose only purpose is to freeze deprecated class names or dashboard card composition.

Never weaken security/functional tests merely to satisfy a redesign.

---

## 18. Definition of implementation done

A slice is complete only when:

- backend/state behavior remains correct;
- canonical UI documents were followed;
- current presentation debt on the touched surface was reduced rather than layered over;
- shared primitives/tokens are used;
- desktop and phone use the same product hierarchy;
- real non-happy states are represented;
- no reference-derived unsupported action was added;
- no hidden reasoning is exposed;
- focused tests pass;
- required repository gates pass;
- real browser evidence confirms the changed flow;
- limitations are recorded.

A generic dashboard, desktop-only result, CSS-patch pile, or screenshot imitation with unsupported functionality is not complete.
