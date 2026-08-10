# VulnHunter Chat-First Workspace Contract

**Status:** Binding product workflow contract  
**Visual contract:** `docs/design/VULNHUNTER_UI_CONTRACT.md`

## 1. Permanent product rule

VulnHunter is a **chat-first security assessment product**.

> The user talks to VulnHunter. VulnHunter converts the request into a typed, governed operation. The backend — not chat text — authorizes, executes, verifies, persists and reports the result.

The authenticated conversation/task workspace is the primary place where an operator starts, controls, understands and continues supported VulnHunter work.

This includes website assessment, repository Source Hunt, APK/mobile analysis, authorization requests that policy permits, plan confirmation, independent approval, progress/blockers, cancellation, evidence, findings, verification, controlled active validation, review/adjudication status, remediation, retest and report generation.

A separate page may exist for a large evidence view, step-up authentication, independent identity-bound decisions, settings or specialist administration. It remains a **deep view of the same authoritative workspace state** and must project its result back into the conversation.

## 2. Chat is not authority

A user message must never directly become:

- a shell command;
- unrestricted scanner arguments;
- repository/file authority;
- target authorization;
- approval;
- a review/adjudication decision;
- finding verification;
- severity authority;
- merge/release/publication authority.

Every action follows:

```text
message / upload
→ workspace ownership/session validation
→ intent + entity resolution
→ typed command proposal
→ policy/role/scope/authorization/state validation
→ required confirmation or independent approval
→ immutable action/plan identity
→ persisted task graph / bounded service
→ receipts + evidence + audit persistence
→ contextual conversation event/card
```

The UI may explain or request a decision; backend services enforce the decision boundary.

## 3. One conversation, one durable workspace

Each assessment conversation binds to a durable owner-scoped workspace containing the relevant:

- workspace/conversation identity;
- messages and uploads;
- resolved targets/repositories/artifacts;
- authorization references;
- assessment IDs;
- immutable plan/action digests;
- approval references;
- task-graph/worker state;
- activity events;
- evidence/finding references;
- review/adjudication/remediation/retest state;
- report/export references;
- cancellation/recovery state.

The browser may refresh, disconnect, close or move from phone to desktop without becoming the owner of execution. Long-running work continues through persisted backend queues/task state. Returning to the conversation reconstructs current state from authoritative stores, not browser memory.

Multiple conversations may run concurrently, but state and artifacts remain isolated by owner/workspace.

## 4. Contextual surfaces first

The conversation should render structured cards/panels when prose alone is insufficient, including:

- authorization summary/requirement;
- immutable plan/confirmation;
- approval request and outcome;
- task stage and blocker;
- upload/integrity state;
- tool receipts;
- evidence summary;
- finding summary;
- verification/controlled-validation state;
- review assignment/status;
- remediation/retest comparison;
- report/export readiness;
- worker recovery/failure.

The card is a projection of backend state. It never owns the security decision.

Large or identity-bound actions may open a specialist view. After the user acts there, the persisted result returns to the original conversation.

## 5. Running-task behaviour

While a task is running:

1. the message composer remains enabled;
2. the user may submit a follow-up instruction;
3. a follow-up that cannot execute yet is persisted and visibly marked **Queued**;
4. the active task continues independently of the browser connection;
5. Refresh/reconnect reconstructs state and must **not restart** the task;
6. navigation away from the conversation does not imply cancellation;
7. Cancel is offered only when the backend contract allows safe cancellation;
8. a browser-only timer/progress value must never pretend to be authoritative worker progress.

### Pause rule

**There is no generic operator Pause control unless/until the backend implements an explicit pause/resume contract.**

Documentation, visual references or agents must not infer Pause from another product. If a workflow is blocked waiting for approval/authorization/input, represent the true blocked state rather than calling it a user pause.

## 6. Core workflow shape

### Website

```text
authorized target selected/provided in chat
→ authorization + exact scope resolved
→ immutable plan shown
→ required confirmation/approval
→ persisted task graph/worker execution
→ activity/evidence/findings/review/report reflected in chat
```

### Source Hunt

```text
approved repository intent in chat
→ exact root/revision/snapshot/path boundary
→ remote-source-processing approval when required
→ queued worker outside the HTTP request
→ hypotheses/falsification/capability filtering/evidence/remediation reflected in chat
```

A specialist Source Hunt page may exist for exact setup/detail but is not a competing primary product.

### APK/mobile

```text
APK attached in chat
→ resumable upload + integrity validation
→ artifact identity + analysis profile
→ static/native/dynamic nodes only where policy/worker support exists
→ tool failures/evidence/findings/blockers reflected in chat
```

Uploading an APK never means executing it.

### Controlled active validation

```text
persisted finding selected
→ controlled scenario/limits explained
→ required step-up + independent approval
→ bounded generated-data trials
→ cleanup/evidence/abstention/result reflected in original conversation
```

### Remediation/retest/report

The user should be able to request remediation, retest and report generation naturally in the same conversation. Engineering orchestration, deterministic verification, human merge/review and publication remain governed by their existing backend contracts.

## 7. User-facing task states

Default task language should be understandable and stable:

```text
Understanding request
Checking authorization
Waiting for confirmation
Waiting for approval
Queued for analysis
Collecting evidence
Analyzing evidence
Verification required
Waiting for independent review
Preparing remediation
Retesting
Report ready
Recovering
Blocked
Cancelled
Failed safely
```

Technical node names, queue envelopes, provider/model identifiers, hashes and worker diagnostics remain available under details/activity/evidence/settings when useful. Do not turn internal task-graph noise into the default conversation.

## 8. Safety/truth rules

The chat interface must never:

- infer target authorization from a URL or user claim;
- turn natural language into arbitrary execution;
- let an AI model grant scope/roles/approval/verification/review/merge/release/publication authority;
- hide a required human decision behind conversational wording;
- send prohibited material to a remote provider;
- treat a model answer as evidence;
- claim queued/running/completed status without persisted evidence;
- invent percentages, findings, evidence, readiness or tool availability;
- continue a cancelled, revoked, expired or terminal task;
- expose another user's workspace through history or guessed identifiers.

Deterministic-only operation must remain possible when the AI provider is unavailable where the underlying workflow supports it.

## 9. Acceptance criteria

A chat-first feature is complete only when:

1. the supported operation can be started/requested from the conversation;
2. intent becomes a typed policy-checked backend command;
3. required authorization/confirmation/approval/re-authentication/review cannot be bypassed through chat;
4. long-running work is persisted independently of the browser;
5. disconnect/reconnect restores exact current state;
6. task execution has truthful loading, blocked, recovery, failure, cancellation and completion states;
7. follow-up instructions can be queued while supported work is running;
8. evidence/findings/reports remain bound to the owning assessment/workspace;
9. specialist decisions project their result back to the originating conversation;
10. desktop and mobile render the same product semantics;
11. multi-user/workspace isolation is preserved;
12. UI visuals comply with `docs/design/VULNHUNTER_UI_CONTRACT.md`.

A standalone page or backend service alone does not satisfy the product contract.
