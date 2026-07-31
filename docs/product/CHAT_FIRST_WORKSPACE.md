# VulnHunter Chat-First Workspace Contract

## 1. Product rule

VulnHunter is a **chat-first security assessment product**.

The authenticated conversation workspace is the primary place where an operator starts, controls, understands, and continues every supported VulnHunter workflow.

This applies to all current and future product capabilities, including:

- website assessment;
- source-repository assessment;
- APK upload and mobile analysis;
- binary or native-library analysis;
- target authorisation requests that are permitted from chat;
- immutable plan review and confirmation;
- approval requests and approval status;
- assessment progress and blockers;
- cancellation, pause, resume, and retry requests where the backend permits them;
- evidence and candidate-finding explanation;
- machine verification and controlled active validation requests;
- independent review and adjudication status;
- remediation planning;
- retesting;
- report generation and export requests;
- governed learning and model-status questions;
- deployment, worker, provider, and tool-readiness questions.

A separate page may exist for detailed inspection, identity-bound decisions, large evidence views, settings, or specialist operations, but it must remain a supporting surface opened from or reflected back into the conversation. It must not become a second independent workflow or a competing source of state.

Permanent product rule:

> The user talks to VulnHunter. VulnHunter converts the request into a typed, governed operation. The backend—not the chat text—authorises, executes, verifies, persists, and reports the result.

---

## 2. What the chat interface is responsible for

The conversation workspace must allow natural requests such as:

```text
Scan this authorised website.
Upload and analyse this APK.
Review this repository for attacker-reachable vulnerabilities.
What is happening with my assessment?
Why is this task blocked?
Show the evidence for finding VH-204.
Stop this assessment.
Request active validation for this finding.
Prepare a remediation plan.
Retest the fix.
Generate the final report.
```

The chat layer must translate these messages into a structured intent. A message is not itself authority and must never directly become a shell command, scanner argument, repository path, target permission, approval, review decision, or publication instruction.

The chat response should combine ordinary language with persisted product state, including:

- what VulnHunter understood;
- what exact target, repository, artifact, assessment, or finding is involved;
- what is already authorised;
- what still requires confirmation or independent approval;
- which task-graph stage is active;
- which worker or tool is expected;
- what evidence has been produced;
- what failed, abstained, or is unavailable;
- what the user may do next.

The interface must never invent progress percentages, findings, evidence, approvals, worker readiness, model availability, or completion states.

---

## 3. Chat-to-operation architecture

Every chat action must follow this path:

```text
User message or uploaded artifact
        ↓
Conversation ownership and session validation
        ↓
Intent classification and entity resolution
        ↓
Typed command proposal
        ↓
Policy, role, scope, authorisation, and state validation
        ↓
Exact confirmation or independent approval when required
        ↓
Immutable action manifest and authoritative task graph
        ↓
Restricted worker or deterministic service
        ↓
Receipt, evidence, finding, and audit persistence
        ↓
Conversation event and contextual result card
        ↓
User may continue naturally in the same chat
```

The conversation service may propose one of these outcomes:

- `ANSWER` — explain existing persisted information;
- `REQUEST_INPUT` — ask for one concrete missing value;
- `REQUEST_UPLOAD` — request an allowed artifact;
- `PROPOSE_ACTION` — show the exact bounded operation before execution;
- `REQUEST_CONFIRMATION` — require the owner to confirm an immutable low-risk plan;
- `REQUEST_APPROVAL` — route a higher-risk operation to the Approval Centre;
- `STARTED` — report that a persisted task graph or worker job has started;
- `STATUS` — report genuine persisted progress or blockers;
- `COMPLETED` — summarize a terminal persisted result;
- `ABSTAINED` — explain why the system cannot support the claim or action;
- `DENIED` — explain the exact policy or authority boundary;
- `FAILED` — report a bounded operational failure without fabricating success.

---

## 4. One conversation, one durable workspace

Each assessment conversation must bind to a durable user-owned workspace containing:

- workspace ID;
- owner identity;
- conversation messages;
- uploaded artifact references;
- resolved targets and repositories;
- authorisation references;
- assessment IDs;
- immutable plan digests;
- approval references;
- task-graph IDs;
- activity events;
- evidence and finding references;
- review and adjudication status;
- report and export references;
- cancellation and recovery state.

The browser may disconnect, refresh, close, or move from phone to desktop without destroying long-running work. Workers continue through persisted queues and task graphs. Returning to the conversation must reconstruct state from authoritative stores rather than from browser memory.

Multiple conversations may run concurrently, but their state, uploads, plans, evidence, findings, and messages must remain isolated by owner and workspace.

---

## 5. Contextual cards and specialist views

The chat transcript should render structured cards or panels for information that is difficult to understand as prose alone, including:

- target and authorisation summary;
- proposed immutable plan;
- approval request;
- task-graph stage and blocker;
- upload progress and artifact integrity;
- tool receipts;
- evidence references;
- candidate finding;
- verification and active-validation state;
- review assignment;
- remediation and retest comparison;
- report and export readiness.

A card is a view of backend state. It does not own security decisions.

Specialist pages may be opened for:

- password re-authentication;
- independent approval;
- primary review;
- adjudication;
- large evidence inspection;
- detailed source paths;
- administrator settings;
- readiness and audit inspection.

After a decision or inspection, the result must appear back in the conversation as a persisted event. The specialist page must not maintain a separate hidden state machine.

---

## 6. Chat-first rules for every assessment type

### Website assessment

```text
User provides or selects an authorised target in chat
→ VulnHunter resolves authorisation and exact scope
→ chat displays the immutable passive plan
→ owner confirms or approval is requested
→ signed worker job and task graph execute
→ activity, evidence, candidates, verification, review, and report return to chat
```

### Source Hunt

```text
User selects an approved repository in chat
→ VulnHunter builds the exact revision and snapshot
→ chat displays the remote-source-processing boundary when applicable
→ approval is completed through the governed decision surface
→ the Source Hunt worker runs outside the HTTP request
→ hypotheses, falsification, capability filtering, evidence, and remediation return to chat
```

### APK and mobile assessment

```text
User attaches an APK in chat
→ resumable upload and integrity validation
→ chat displays the artifact identity and proposed analysis profile
→ static/native/dynamic nodes run through approved workers
→ tool failures, evidence, findings, and blockers return to chat
```

Uploading an APK never means executing it.

### Active validation

```text
User asks in chat to validate a persisted finding
→ chat explains the controlled scenario and exact limits
→ requester and independent approver complete required step-up authentication
→ bounded generated-data trials run in the controlled worker
→ evidence, cleanup, abstention, and result return to the original conversation
```

### Remediation and retest

```text
User asks for a fix in chat
→ VulnHunter prepares an evidence-bound remediation proposal
→ controlled engineering orchestration may create a bounded patch task
→ independent deterministic verification runs
→ human-controlled merge remains separate
→ user asks for retest in the same conversation
→ before/after evidence and final status return to chat
```

---

## 7. Safety boundary

The chat interface must never:

- infer target authorisation from a URL or user statement;
- turn natural-language text into arbitrary shell execution;
- allow a model to select unrestricted arguments;
- grant roles, scope, approval, verification, review, severity, merge, release, or publication authority;
- hide a required human decision behind conversational wording;
- send prohibited private material to a remote provider;
- treat a model answer as evidence;
- claim that a queued task is running or complete without persisted backend evidence;
- fabricate progress when a worker, tool, provider, or environment is unavailable;
- continue a cancelled, expired, revoked, or terminal task;
- expose another user's workspace through conversation history or guessed identifiers.

The same backend service contracts must support chat, CLI, and future API clients. The chat interface is the primary experience, but it is not a security boundary by itself.

---

## 8. Requirement for the unified task-graph milestone

The next assessment-orchestration implementation must be explicitly chat-first.

Website, APK, Source Hunt, Active Validation, remediation, retest, and report tasks must share:

- one workspace binding;
- one typed intent-to-command layer;
- one immutable plan and action-manifest contract;
- one authoritative task graph;
- one approval and confirmation model;
- one worker lease and receipt envelope;
- one persisted activity stream;
- one cancellation and recovery model;
- one evidence/finding linkage model;
- one chat event projection.

The task graph must not be exposed as technical noise by default. The user should see understandable stages such as:

```text
Understanding request
Checking authorisation
Waiting for confirmation
Queued for analysis
Collecting evidence
Analysing evidence
Verification required
Waiting for independent review
Preparing remediation
Retesting
Report ready
Blocked
Cancelled
Failed safely
```

Technical node details remain available when the user asks for them.

---

## 9. Acceptance criteria

The chat-first contract is satisfied only when all of the following are true:

1. A user can start every supported assessment type from the conversation workspace.
2. The user can attach an APK and select an approved repository or website without moving to a separate primary creation form.
3. Every proposed action is resolved into a typed backend command.
4. Required confirmation, approval, re-authentication, or review is shown clearly and cannot be bypassed through chat.
5. Every long-running action is represented by persisted workspace and task-graph state.
6. Browser disconnection does not stop worker execution or lose conversation state.
7. Returning to the chat reconstructs the exact current status.
8. The user can ask naturally for status, evidence, blockers, cancellation, remediation, retest, and reports.
9. Structured cards display backend state without inventing data.
10. Supporting specialist pages return their decisions and results to the original conversation.
11. Multiple user workspaces remain isolated.
12. Deterministic-only operation remains possible when the AI provider is unavailable.
13. The model cannot authorise, execute, verify, approve, review, merge, publish, or change policy.
14. End-to-end tests cover phone and desktop conversation flows, restart recovery, duplicate submissions, stale CSRF/session state, cancellation, failure, and denied operations.

---

## 10. Definition of done

A new feature is not complete merely because its backend service or standalone page works.

For VulnHunter, a product feature is complete only when:

- it can be started or requested from chat;
- it produces a typed, policy-checked backend operation;
- it persists its authoritative state;
- it reports genuine progress, blockers, results, and next actions back into chat;
- required specialist decisions are connected back to the conversation;
- mobile and desktop behaviour is accepted;
- failure, cancellation, recovery, and unavailable states are tested;
- documentation and the master architecture remain consistent.
