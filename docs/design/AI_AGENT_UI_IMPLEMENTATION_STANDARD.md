# VulnHunter AI Agent UI Implementation Standard

**STATUS: BINDING — AGENT EXECUTION STANDARD**  
**Applies to:** Codex, Cline, Claude Code, Copilot, Cursor, ChatGPT coding agents, local agents, humans and automated processes changing VulnHunter browser UI  
**Visual authority:** `docs/design/VULNHUNTER_UI_CONTRACT.md`  
**Workflow authority:** `docs/product/CHAT_FIRST_WORKSPACE.md`  
**Live-task authority:** `docs/product/LIVE_EXECUTION_ACTIVITY.md`  
**Public-target authority:** `docs/product/PUBLIC_TARGET_ASSESSMENT.md`

This document exists because a correct backend can still be presented through a poor, contradictory, dashboard-first, unsafe or state-fabricating UI.

---

## 1. Non-negotiable product model

VulnHunter is a **conversation/task-first authorised security workspace**.

The default experience is:

```text
conversation / attachment / target
→ exact governed interpretation
→ required authorization / confirmation / approval
→ persisted task execution
→ truthful live activity
→ tool receipts / evidence / findings / recommendations
→ contextual deep view only when more room or identity-bound action is required
```

It is not:

- an admin dashboard with a chatbot attached;
- a KPI wall;
- a generic SOC console;
- a cyberpunk terminal UI;
- a generic blue-and-white SaaS dashboard;
- a desktop dashboard squeezed onto phone;
- a black-box worker with only a spinner;
- a UI that treats a public URL as permission.

---

## 2. Mandatory authority order

Before browser UI work, read in this order:

1. `AGENTS.md`;
2. `vulnhunter/web/AGENTS.md`;
3. `docs/design/VULNHUNTER_UI_CONTRACT.md`;
4. this file;
5. `docs/design/references/manifest.json`;
6. `docs/design/DEPRECATIONS.md`;
7. `docs/product/CHAT_FIRST_WORKSPACE.md`;
8. `docs/product/LIVE_EXECUTION_ACTIVITY.md`;
9. `docs/product/PUBLIC_TARGET_ASSESSMENT.md` when website/public-target behavior is affected;
10. `docs/product/UI_ACCEPTANCE_CRITERIA.md`;
11. `docs/product/RESPONSIVE_AND_ACCESSIBILITY.md`;
12. relevant routes/actions/projections/persisted state/security/tests/shared primitives.

Current implementation is never visual/product authority when it conflicts with this chain.

---

## 3. Reference roles

### MonkeyCode — structure/task behavior

Use for:

- compact chat/task sidebar;
- current/recent tasks;
- task history;
- running timeline;
- queued follow-ups;
- reconnect/restore;
- persistent composer;
- contextual controls;
- mobile overlay drawer.

Never copy branding, Projects/account tiers, provider/model names or unsupported actions.

### Beautiful UI — AI-native primitives

Use for:

- loading/safe activity;
- assistant streaming;
- approval/confirmation cards;
- tool chips;
- task rows;
- chat/prompt bar;
- recommendation/context/finding cards;
- code/diff presentation;
- search/deep-view records.

Never copy its branding, palette, rounding, Fine-tune controls, dictation, sample commands, provider/model selectors or hidden model reasoning.

### VulnHunter — identity/functionality/authority

VulnHunter owns:

- actual routes/actions/capabilities;
- authorization/security boundaries;
- persisted state/evidence/findings;
- terminology;
- warm cream/off-white dotted canvas;
- dusty-pink accent;
- compact dark sidebar;
- near-black technical text/borders;
- square/nearly-square geometry;
- hard zero-blur offset shadows.

---

## 4. Canonical desktop composition

```text
┌──────────────────┬─────────────────────────────────────────┬──────────────────┐
│ task/chat sidebar│ current conversation + task timeline    │ contextual detail│
│                  │                                         │ only when opened │
│ + New assessment │ user / assistant messages               │ evidence/finding │
│ current task     │ task rows / tool chips / live activity  │ receipt/source   │
│ recent tasks     │ contextual cards                        │                  │
│ history/manage   │ persistent composer                     │                  │
└──────────────────┴─────────────────────────────────────────┴──────────────────┘
```

Rules:

- conversation owns main width;
- right detail is closed by default;
- no permanent metrics rail;
- no wide action row competing with task;
- no four-card state strip;
- composer remains anchored/reachable;
- running state updates in place.

---

## 5. Canonical mobile composition

Phone is one column:

```text
☰  current task                               ⋯

Running · truthful duration if derivable

✓ Authorization verified
✓ Plan confirmed
◌ Nuclei assessment
○ Verification

assistant response
[tool chips]
[context/finding/approval/live activity]

+ Ask VulnHunter…                          ➜
```

Requirements:

- no essential horizontal page scroll;
- no clipped primary actions;
- no desktop toolbar/grid squeezed onto phone;
- body text generally ~15–17px on phone;
- critical touch targets ~44px minimum;
- composer reachable with keyboard open;
- context/activity detail becomes full-width sheet/drawer/deep view;
- long paths/URLs/hashes wrap/truncate deliberately.

---

## 6. Public-target implementation rule

Authorised public targets are a supported product class.

A public target UI must show the difference between:

- target classification;
- authorization existence/scope;
- worker capability/readiness;
- immutable plan;
- confirmation/approval;
- actual queued/running execution.

Never implement public support by browser-only toggles or by presenting a public URL as authorized.

When runtime is private-only, the UI should say something like:

```text
Public target authorized
Execution unavailable
The configured worker is private-target-only.
```

rather than claiming it queued.

After public runtime exists, the same task flow continues into plan/queue/live activity.

See `PUBLIC_TARGET_ASSESSMENT.md`.

---

## 7. Live execution implementation rule

When work is queued/running/recovering, show persisted operational telemetry.

Required when backend exposes it:

- current stage;
- completed/pending stages;
- active worker/tool;
- safe current target/file/artifact;
- real receipt/evidence/candidate counts;
- latest event;
- failure/recovery/preserved work;
- safe supported action.

Do not append one assistant paragraph per poll. Update one stable task group/timeline.

A separate Activity/Inspector view may provide detail, but the conversation must make basic task health understandable.

Do not expose chain-of-thought. See `LIVE_EXECUTION_ACTIVITY.md`.

---

## 8. Conversation anatomy

Use a small durable primitive set.

### User message

Clean text with optional attachment reference. Avoid oversized bubbly chat balloons.

### Assistant message

Readable high-contrast prose with structured state below it when useful.

### Task group

```text
✓ Check authorization
✓ Prepare immutable plan
◌ Nuclei assessment
○ Evidence normalization
○ Verification
```

One state language only.

### Tool chips

```text
[Nuclei ◌]
[HTTP probe ✓ 1.2s]
[Evidence 4]
```

Only from real receipts/state.

### Authorization/approval cards

Show exact object/action/scope and backend-supported decisions. Authorization, owner plan confirmation and independent approval remain distinct.

### Context/evidence/finding cards

Show concise summary/provenance and allow deeper inspection.

---

## 9. Source Hunt implementation rule

Source Hunt is conversational/contextual first.

Specialist setup may collect exact root/revision/permitted paths/password/attestations.

Before full submission, use deterministic preflight when available:

```text
Root             /workspaces/project
Revision         HEAD → abc123
Eligible Python  684 / 2,000
Eligible bytes   12.4 MB / 50 MB
Permitted paths  vulnhunter/
```

Predictable limits should be shown before queue failure.

Do not imply permitted paths constrain snapshot construction unless runtime actually enforces that.

After queueing, return to the conversation and show snapshot/inventory/hunt/falsification/capability/remediation activity from persisted events.

---

## 10. APK implementation rule

APK analysis starts from attachment flow.

Distinguish:

```text
upload
→ uploaded/validating
→ integrity verified
→ static tools
→ evidence
→ verification
```

100% upload is not assessment completion.

Uploading never implies dynamic execution.

Individual tool receipts/failures remain truthful and preserve partial work.

---

## 11. Running/composer behavior

- composer remains usable while supported work runs;
- follow-up can be visibly queued where backend supports it;
- reconnect reconstructs state and never restarts work;
- leaving page does not imply cancellation;
- Cancel only when backend supports it;
- Pause never without a real pause/resume contract;
- progress only from measured backend data.

---

## 12. Safe activity / streaming

Allowed:

```text
Checking authorization…
Preparing bounded passive plan…
Worker claimed signed job…
Reviewing persisted evidence…
```

Forbidden:

- hidden chain-of-thought;
- private reasoning traces;
- fake internal deliberation;
- fake percentages;
- animated work with no backend state.

Streaming streams user-facing answer text only.

---

## 13. Failure/recovery

Failure should show, when available:

- exact stage;
- safe category/reason/reference;
- completed stages;
- preserved artifact/evidence/snapshot;
- whether retry exists;
- exact retry scope;
- user-vs-operator action required.

Recovery updates same task identity.

Do not offer Retry when backend cannot safely/idempotently retry.

---

## 14. CSS/presentation architecture

For each affected component:

1. identify canonical tokens (`tokens.css`);
2. identify existing component/style owner;
3. remove/consolidate contradictory rules;
4. keep responsive behavior with owner;
5. remove dead selectors when safe;
6. avoid `!important` as normal repair;
7. never add a global patch stylesheet just to win cascade order;
8. do not introduce page-local palette/radius/shadow/type systems;
9. preserve CSP/no-inline-script requirements.

Migration should reduce the number of competing style owners.

---

## 15. Explicitly rejected current/deprecated patterns

Treat these as debt, not precedent:

1. four large Authorization/Scope/Approval/Active cards;
2. wide Source Hunt/Search/Export/History/New workspace toolbar;
3. Runs/Scanner/Execution/Entry point KPI cards;
4. giant dark Source Hunt/admin panels;
5. giant Source Hunt form as primary entry;
6. giant empty conversation areas while task state is tiny;
7. low-contrast/tiny assistant text;
8. blue-glow identity;
9. desktop UI squeezed/clipped on phone;
10. competing navigation systems;
11. permanent context panel when not opened;
12. repeated CSS patch layers;
13. fake tool/progress/activity;
14. generic “backend is running; check elsewhere” as sole live state;
15. public URL treated as authorization.

---

## 16. Mandatory implementation sequence

Before editing:

1. inspect current `main`, open PRs, recent commits, CI;
2. inspect exact backend projection/state powering the surface;
3. identify the security/authorization boundary;
4. identify existing component/style owner;
5. define expected phone behavior;
6. identify applicable MonkeyCode pattern;
7. identify applicable Beautiful UI primitive;
8. identify deprecated presentation to remove;
9. define loading/blocked/running/failure/recovery states;
10. define tests/browser evidence.

During implementation:

- preserve routes/API/auth/security/state truth;
- reuse shared tokens/primitives;
- do not duplicate frontend lifecycle stores;
- keep desktop/mobile one system;
- never invent backend capability/state;
- never weaken authorization/public-target containment;
- never expose hidden reasoning.

After implementation:

- run focused tests;
- run `AGENTS.md` repository gates;
- run real browser acceptance;
- verify backend state matches UI;
- verify representative phone widths;
- report actual limitations.

---

## 17. Public-target UI exit gate

A public-target UI slice is not complete unless:

- exact authorization state is backend-driven;
- target class is truthful;
- private-only worker blocker is truthful when applicable;
- public-capable worker state appears only when runtime supports it;
- plan decision is exact/digest-bound;
- reconnect preserves same task;
- no browser control can broaden scope/worker capability.

---

## 18. Live-execution UI exit gate

A long-running UI slice is not complete unless:

- worker/service persists meaningful activity;
- projection exposes it;
- conversation renders it;
- reconnect deduplicates/reconstructs it;
- browser tests compare rendered state with persisted state;
- no fake percentage/tool/event exists.

---

## 19. Browser/phone acceptance

Verify representative widths near:

`360`, `390`, `412`, `768`, `1024`, `1280`, `1440` CSS pixels.

Applicable evidence includes:

- empty/new workspace;
- authorization required/verified;
- public target blocked/running when supported;
- plan confirmation/approval;
- queued/running live task;
- Source Hunt preflight/running;
- APK upload/tool state;
- evidence/finding;
- failure/recovery/cancellation;
- reconnect;
- contextual drawer/sheet;
- keyboard/focus/touch/reduced-motion behavior.

---

## Final rule

A generic dashboard is not close enough. A polished screenshot with fabricated state is a failure. A public-target shortcut that weakens containment is a failure. A spinner-only running task when the backend has useful activity is a failure. A desktop-only result is a failure.

The UI is complete only when **security truth, persisted task truth, canonical design and responsive/accessibility evidence agree**.
