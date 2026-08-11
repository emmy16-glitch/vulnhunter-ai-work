# VulnHunter Chat-First Workspace Contract

**Status:** BINDING PRODUCT WORKFLOW CONTRACT  
**Visual contract:** `docs/design/VULNHUNTER_UI_CONTRACT.md`  
**Agent implementation standard:** `docs/design/AI_AGENT_UI_IMPLEMENTATION_STANDARD.md`  
**Live execution:** `docs/product/LIVE_EXECUTION_ACTIVITY.md`  
**Public targets:** `docs/product/PUBLIC_TARGET_ASSESSMENT.md`

---

## 1. Permanent product rule

VulnHunter is a **conversation/task-first authorised security-assessment product**.

> The user talks to VulnHunter. VulnHunter resolves the exact object and intent, then deterministic backend services authorize, plan, execute, verify, persist and report the result.

Chat is the operating surface, not the authority.

The authenticated workspace is where an operator should be able to:

- provide a private or public website target;
- resolve/create/select valid authorization through supported policy;
- review an exact plan;
- confirm/approve governed work;
- start and observe long-running work;
- continue chatting while supported work runs;
- start Source Hunt;
- attach and analyze APKs;
- see blockers/recovery/failures;
- inspect evidence/findings;
- request remediation/retest/report work;
- continue the same task after reconnect.

Specialist pages exist only when more room, step-up authentication or identity-bound governance genuinely requires them. They project the same persisted state back to the originating conversation.

---

## 2. Core command path

Every actionable request follows the same shape:

```text
message / attachment
→ workspace ownership/session validation
→ intent + exact entity resolution
→ typed command proposal
→ role/policy/scope/authorization/state validation
→ required confirmation / approval / re-authentication
→ immutable action/plan identity
→ persisted task graph / bounded service
→ worker/tool receipts + activity
→ evidence/findings
→ verification/review/report state
→ contextual conversation projection
```

A user message must never directly become:

- arbitrary shell commands;
- unrestricted scanner arguments;
- target authorization;
- repository/file authority;
- approval;
- review/adjudication decision;
- finding verification;
- severity authority;
- merge/release/publication authority.

---

## 3. Durable workspace identity

Each conversation binds to a durable owner-scoped workspace containing the relevant:

- workspace/conversation ID;
- messages/uploads;
- selected target/repository/artifact;
- authorization references;
- assessment/job IDs;
- immutable plan/action digests;
- approval references;
- task graph/worker state;
- append-only activity events;
- tool receipts;
- evidence/finding references;
- verification/review/adjudication state;
- remediation/retest state;
- report/export references;
- cancellation/recovery state.

Browser storage may cache ephemeral selection/draft/UI state only. It is not authoritative for task lifecycle.

Refresh, disconnect, close/reopen or device switching reconstructs the same persisted task instead of restarting it.

---

## 4. Canonical surfaces

### Desktop

```text
compact task/chat sidebar
→ main conversation + task timeline + live activity
→ persistent composer
→ contextual detail drawer only when opened
```

### Mobile

```text
overlay task/chat drawer
→ one-column conversation + task timeline + live activity
→ persistent composer
→ full-width detail sheet/deep view when needed
```

Do not turn the main workspace into a KPI dashboard or permanent multi-panel admin console.

---

## 5. Public target workflow

Authorised public targets are a supported product class.

Canonical flow:

```text
User provides https://example.com
→ normalize/classify as public
→ check exact active authorization
→ if absent, show authorization-required card
→ collect/select backend-supported authorization evidence
→ verify worker capability for public target class
→ prepare immutable passive plan
→ required confirmation/approval
→ queue
→ persisted live execution activity
→ evidence/findings/verification
```

The UI must never treat “public” as permission.

If the configured worker is still private-only, say so truthfully and block execution. Do not pretend the scan started.

See `docs/product/PUBLIC_TARGET_ASSESSMENT.md`.

---

## 6. Private target workflow

Private/laboratory targets use the same conversation/task semantics, with the applicable private-network authorization and worker policy.

The UI should not maintain a completely different product shell just because target class differs.

---

## 7. Authorization presentation

When authorization is missing, show the exact unresolved object:

```text
Authorization required
Target  https://example.com/
Class   Public
Port    443
Path    /

No active authorization covers this exact target.
[Review authorization]
```

After authorization succeeds:

```text
✓ Authorization verified
  AUTH-...
  public · HTTPS/443 · /
```

The conversation should not repeatedly ask for evidence already covered by a valid active exact record.

Authorization, owner confirmation, independent approval, human review and adjudication are separate concepts and must not be collapsed into one generic “Approve” action.

---

## 8. Exact plan confirmation

Before executable website assessment, show a backend-produced immutable plan with relevant fields such as:

- authorization ID;
- target/class;
- protocol/port/path;
- scanner/profile;
- template selection/manifest digest;
- rate/concurrency;
- prohibited actions;
- expiry;
- plan digest.

The UI may summarize, but confirmation binds the exact plan identity.

A changed plan requires a new decision.

---

## 9. Live running-task behavior

While a task is queued/running/recovering, the workspace must project persisted operational state.

A running task should answer, where backend data exists:

- current stage;
- completed stages;
- next stages;
- current worker/tool;
- safe current target/file/artifact;
- receipt/evidence/candidate counts;
- latest activity;
- human action required;
- failure/recovery/preserved state.

Example:

```text
Website assessment — Running

✓ Authorization verified
✓ Passive plan confirmed
✓ Worker claimed job
◌ Nuclei assessment
  17 reviewed passive templates
  Latest receipt: HTTP probe completed
○ Evidence normalization
○ Deterministic verification

[Nuclei ◌] [Evidence 4]
```

Do not expose hidden chain-of-thought. Do not invent percentages.

See `docs/product/LIVE_EXECUTION_ACTIVITY.md`.

---

## 10. Composer while work runs

The composer remains available unless a real backend restriction requires otherwise.

The user may ask:

- “what is it doing now?”;
- “show activity”;
- “what has completed?”;
- “what failed?”;
- “what findings do we have so far?” where supported;
- “cancel” where cancellation exists;
- a follow-up instruction.

If a follow-up cannot execute immediately but queued-follow-up behavior exists, persist it and label it `Queued`.

Do not disable the whole conversation just because one stage waits for approval/input.

---

## 11. Website assessment shape

```text
target intent
→ exact target class + authorization
→ immutable plan
→ required decision
→ persisted worker execution
→ task rows + tool receipts + live activity
→ evidence
→ candidate findings
→ deterministic verification
→ optional separately governed active validation
→ review
→ report/release state
```

Evidence/findings/report remain assessment-scoped.

---

## 12. Source Hunt shape

```text
repository intent
→ exact approved root
→ deterministic preflight
→ exact revision/snapshot/permitted path boundary
→ source-processing approval + step-up
→ queued worker
→ live snapshot/inventory/hunt/falsification/capability activity
→ evidence-backed remediation
→ deterministic/human-controlled fix workflow
→ report/result in same conversation
```

The specialist setup page is a continuation, not the product centre.

See `docs/product/SOURCE_HUNT.md`.

---

## 13. APK/mobile shape

```text
APK attachment
→ resumable upload
→ integrity validation
→ artifact/assessment identity
→ plan/worker capability
→ static tool receipts
→ evidence/findings/verification
→ optional separately governed dynamic path
```

Uploading never means execution.

Individual tool failures preserve truthful partial state.

---

## 14. Contextual product primitives

Use a small set of structured objects in chat:

- task rows;
- tool chips;
- authorization card;
- exact-plan confirmation card;
- independent approval card;
- upload/integrity card;
- context/evidence card;
- finding card;
- remediation/recommendation card;
- report-ready card;
- recovery/failure/cancellation state;
- live activity disclosure.

Cards render backend truth. They do not create authority.

---

## 15. Task language

Primary task language should be understandable:

```text
Understanding request
Checking authorization
Preparing plan
Waiting for confirmation
Waiting for approval
Queued for analysis
Collecting evidence
Analyzing evidence
Verification
Waiting for independent review
Preparing remediation
Retesting
Preparing report
Report ready
Recovering
Blocked
Cancelled
Failed safely
```

Technical queue/node/provider/hash details belong under Activity/Details/Evidence when useful.

---

## 16. Safe AI activity

Allowed:

```text
Checking authorization…
Preparing bounded passive plan…
Waiting for worker receipt…
Reviewing persisted evidence…
```

Forbidden:

- hidden chain-of-thought;
- private reasoning tokens;
- fabricated deliberation;
- fake activity when no backend work exists.

Streaming may stream user-facing assistant text, not private reasoning.

---

## 17. Failure and recovery

When typed backend state exists, failure UI should identify:

- failed stage;
- safe reason/reference;
- completed stages;
- preserved evidence/artifact/snapshot;
- whether automatic recovery is occurring;
- whether safe retry exists;
- retry scope;
- user-vs-operator action required.

Recovery updates the same task:

```text
Worker interrupted — recovering
Persisted state preserved
Restoring execution context…
```

A reconnect never converts a failed/running task into a new assessment automatically.

---

## 18. Search/history/utilities

- task history lives primarily in task/chat navigation;
- search is a compact utility or dedicated search interaction;
- export/report appears when a relevant persisted result exists;
- Source Hunt is initiated conversationally/progressively disclosed;
- `+ New assessment` remains the main new-work action.

Do not restore a permanent `Source Hunt / Search / Export / History / New workspace` toolbar row.

---

## 19. State truth rules

The workspace must never:

- infer authorization from a URL/user claim;
- claim a public target is executable when worker policy is private-only;
- claim queued/running/completed without persisted evidence;
- invent progress/findings/evidence/readiness/tool state;
- request an APK/repository/authorization that is already present and valid;
- continue a cancelled/revoked/expired/terminal task;
- expose another user's workspace through guessed identifiers;
- use model prose instead of authoritative state when the state exists.

Unknown/unavailable remains unknown/unavailable.

---

## 20. Acceptance criteria

A chat-first workflow is complete only when:

1. it can be requested from the conversation;
2. request becomes a typed backend operation;
3. required authorization/confirmation/approval/re-authentication/review cannot be bypassed;
4. long-running work is persisted independently of the browser;
5. the conversation shows meaningful live activity while it runs;
6. reconnect restores exact current state and deduplicated activity;
7. failure/recovery/cancellation are truthful;
8. follow-up queuing works where supported;
9. evidence/findings/reports remain assessment-scoped;
10. specialist decisions project back to the same task;
11. mobile/desktop preserve the same semantics;
12. UI complies with the locked design contract;
13. public-target behavior complies with `PUBLIC_TARGET_ASSESSMENT.md` when applicable;
14. no hidden chain-of-thought is rendered.

A standalone page, a backend service or an attractive screenshot alone does not satisfy this contract.
