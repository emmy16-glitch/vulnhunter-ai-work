# VulnHunter Source Hunt

**Status:** BINDING SOURCE-ANALYSIS PRODUCT CONTRACT  
**Current implementation:** Python-first, Groq-assisted, deterministic snapshot/evidence authority  
**Live activity:** `docs/product/LIVE_EXECUTION_ACTIVITY.md`

---

## 1. Purpose

Source Hunt is VulnHunter's attacker-first source-code analysis path.

The current Source Hunt model provider is Groq. Deterministic repository controls establish what source exists, which files/paths are eligible, which entry points and sinks exist, and whether every model-supplied file/hash/line reference is genuine.

Groq may:

- prioritize deterministic attack surfaces;
- propose bounded attack-path hypotheses;
- challenge/falsify hypotheses;
- assess attacker capability;
- draft remediation and regression-test proposals.

Groq cannot:

- authorize source processing;
- expand repository scope;
- invent source truth;
- execute shell/tools through the model path;
- verify a vulnerability;
- set final severity;
- edit/apply/merge code;
- publish a finding.

---

## 2. Canonical flow

```text
repository intent in conversation
→ resolve operator-approved repository root
→ deterministic preflight
→ exact revision + eligible-file snapshot
→ repository/revision/snapshot/path-bound source-processing approval
→ password re-authentication / attestations where required
→ non-secret queued job
→ separate Source Hunt worker
→ deterministic Python inventory + attack-surface graph
→ Groq reconnaissance
→ bounded hypothesis generation
→ independent Groq falsification
→ capability filtering
→ evidence-bound remediation/test proposal
→ deterministic verification / developer-led isolated fix flow
→ human review
→ result projected back into originating conversation
```

The browser must never perform the long-running hunt inside the HTTP request.

---

## 3. Conversation-first product rule

Source Hunt is initiated from the conversation/task system or contextual task action.

The user should not be dropped immediately into a giant standalone admin dashboard.

Preferred initial projection:

```text
Source Hunt
Repository: /workspaces/project
Revision: HEAD / resolved commit

✓ Repository root resolved
◌ Preflighting eligible source
○ Snapshot
○ Source-processing approval
○ Queue worker
```

A specialist Source Hunt setup view is valid for exact fields that require more room or step-up authentication:

- repository root;
- exact revision;
- visibility;
- permitted paths;
- password re-authentication;
- Groq source-processing approval;
- customer-data attestation;
- provider-retention/data-control attestation.

It remains a focused continuation of the same task and must return its persisted result to the originating conversation.

---

## 4. Mandatory preflight

Before the user completes the full source-processing submission, VulnHunter should deterministically preflight predictable eligibility limits whenever possible.

Preflight should report:

- canonical resolved repository root;
- whether it remains inside an operator-approved root;
- resolved revision or the fact that HEAD/content hash will be bound;
- repository visibility supplied by the user;
- eligible language(s); currently Python;
- eligible `.py` file count;
- configured maximum file count;
- eligible total bytes;
- configured repository-byte limit;
- configured maximum per-file bytes;
- directories excluded by policy;
- symlink policy;
- requested permitted paths;
- whether permitted paths will actually constrain snapshot construction;
- any predictable blocker.

Example:

```text
Source Hunt preflight

Root             /workspaces/vulnhunter-ai-work
Revision         HEAD → 4b3e113…
Eligible Python  2,413 files
File limit       2,000
Eligible bytes   31.7 MB / 50 MB

Blocked
The repository exceeds the approved Python file-count limit.

Suggested safe action
Choose a narrower approved repository root or permitted snapshot path.
```

Do not silently increase limits merely to make a repository pass.

---

## 5. Current deterministic snapshot limits

The current policy defaults include:

```text
maximum files             2,000
maximum file bytes        1,000,000
maximum repository bytes  50,000,000
maximum prompt bytes      90,000
maximum output tokens     2,400
maximum model calls       48
maximum attack surfaces   24
maximum candidates        12
maximum path depth        8
model timeout              90 seconds
```

These are policy defaults, not UI decoration. The effective runtime policy remains authoritative.

If a deployment changes them, the UI/docs must not hard-code stale values as runtime truth; preflight should show the configured effective values.

---

## 6. Snapshot identity

The snapshot binds eligible regular source files to deterministic metadata including path, size, line count and SHA-256.

The snapshot identity must remain immutable for the Source Hunt job.

Required behaviors:

- root must resolve inside an approved root;
- symlinks are not followed as eligible source;
- generated/cache/virtual-environment/local-runtime directories remain excluded according to policy;
- oversized files are skipped or blocked according to policy;
- file mutation during snapshot construction fails closed;
- repository byte/file limits fail closed;
- every eligible file is content hashed;
- revision is exact when supplied, otherwise resolved from Git HEAD or bound to the content snapshot fallback;
- snapshot hash is deterministic for the eligible file set.

---

## 7. Permitted-path semantics

This field must not lie to the user.

Current implementation can build a snapshot from `repository_root` before `permitted_paths` become part of the remote-processing approval. Therefore a narrower permitted-path form value does not necessarily avoid an earlier repository-root file-count/byte-limit failure.

The target implementation should choose one explicit enforceable contract.

### Preferred contract

Permitted paths constrain **snapshot construction and remote processing**.

That means:

```text
repository root
+ exact permitted relative roots
→ eligible snapshot only inside those roots
→ snapshot hash
→ processing approval bound to the same roots
```

This makes the preflight, snapshot and remote-processing boundary agree.

### Acceptable transitional contract

If the implementation intentionally snapshots the complete eligible repository but permits Groq processing only within selected paths, the UI must say so explicitly and may not imply the file-count limit was narrowed.

Do not silently switch between these semantics.

---

## 8. Remote source-processing approval

Before any source excerpt is transmitted, VulnHunter binds approval to:

- repository identifier;
- exact revision;
- eligible-file snapshot SHA-256;
- repository visibility;
- exact permitted repository-relative paths;
- provider identity;
- approving identity;
- approval and expiry times;
- approval-record SHA-256;
- customer-data absence attestation;
- provider retention/data-control review attestation.

The browser additionally requires password re-authentication under the current contract.

A changed revision, snapshot, path set, provider/model policy or expired approval fails closed.

---

## 9. Prohibited remote material

Never transmit through Source Hunt:

- credentials;
- passwords;
- API keys;
- bearer/session tokens;
- cookies;
- private keys;
- authorization records containing sensitive evidence;
- detected secrets;
- unrestricted databases/filesystems;
- customer data when the approval requires its absence;
- files outside the exact approved snapshot/path boundary.

Sensitive-data detection/redaction must happen before a remote-provider boundary.

---

## 10. Queue and worker separation

A browser submission performs bounded local work only:

1. validate actor/permission;
2. password re-authenticate;
3. run deterministic preflight;
4. build/bind the exact snapshot;
5. create exact time-limited source-processing approval;
6. create a non-secret job;
7. bind the job to the assessment/workspace graph;
8. enqueue;
9. return immediately.

The separate worker:

- atomically claims one job;
- records `running`;
- performs deterministic/model stages;
- persists live activity;
- persists the report/result;
- records completed/failed/cancelled state.

Browser navigation/session loss/reverse-proxy timeout must not terminate an active job.

---

## 11. Current deterministic mapper

The current production slice is Python-first.

It can:

- inventory eligible `.py` files;
- discover decorated routes/externally invoked handlers;
- detect request-like attacker inputs;
- build bounded unambiguous inter-function call paths;
- identify authorization/validation/sanitization guards;
- identify bounded sink families including command/subprocess execution, dynamic code execution, unsafe deserialization, database operations, outbound requests, filesystem access/write/delete, template rendering and unsafe HTML marking.

Unsupported languages and ambiguous call targets are not silently treated as covered.

---

## 12. Groq stages

### Reconnaissance

Receives deterministic repository/surface metadata and may prioritize supplied surfaces.

It cannot create a file/function/sink that does not exist in the snapshot.

### Attack-path hunt

Produces a bounded structured hypothesis with:

- entry point;
- sink;
- exact source path;
- assumptions/preconditions;
- confidence/rationale fields allowed by the schema;
- evidence references.

### Independent falsification

A separate request attempts to reject the hypothesis by checking:

- reachability;
- attacker control;
- guards;
- framework protections;
- contradictory source;
- unrealistic preconditions;
- stale/invented references.

Uncertainty should lead to rejection/abstention rather than an inflated finding.

### Capability filtering

Determines the actual attacker capability/boundary break.

Suspicious syntax without a meaningful security capability is discarded.

### Remediation planning

Produces a minimal reviewable change proposal, regression test idea, compatibility risks and deterministic verification recipe.

This stage does not edit the repository.

---

## 13. Evidence integrity

Every model source reference must match:

- exact snapshot file path;
- exact file SHA-256;
- valid line range;
- current immutable snapshot identity.

Before transmitting a source excerpt, re-read/re-hash according to the implementation contract and fail closed on drift.

Invented/stale references are rejected.

Remediation target files must exist in the snapshot.

---

## 14. Live execution activity

Once queued, Source Hunt must not look like a black box.

The worker/service should persist meaningful milestones such as:

- preflight complete;
- snapshot created;
- inventory complete;
- attack surfaces discovered;
- surface/path currently being analyzed when safe;
- hypothesis created;
- falsification started/completed;
- candidate rejected/abstained/survived;
- capability filter started/completed;
- remediation proposal ready;
- report persisted;
- failure/recovery/cancellation.

Example task projection:

```text
Source Hunt — Running

✓ Snapshot created · 684 eligible Python files
✓ Inventory completed
✓ Attack surfaces mapped · 21
◌ Attack-path hunt
  Current surface: web/conversational_views.py
  Surfaces examined: 9
  Candidates: 4
○ Independent falsification
○ Capability filtering
○ Remediation proposal
```

Do not expose hidden model chain-of-thought.

See `docs/product/LIVE_EXECUTION_ACTIVITY.md`.

---

## 15. Failure behavior

A Source Hunt failure should preserve and show, when available:

- job/assessment identity;
- failed stage;
- safe reason/reference;
- snapshot identity;
- processing approval identity;
- completed deterministic work;
- persisted activity/receipts;
- preserved candidate/evidence state;
- retry availability/scope.

A generic “Source Hunt failed” message is insufficient when typed state exists.

Refresh must not restart the job.

---

## 16. Fix and verify

Source Hunt does not directly apply a model patch.

Expected engineering workflow:

```text
safe reproduction/fixture
→ failing security regression test (RED)
→ minimal bounded developer patch
→ security test passes (GREEN)
→ broader deterministic verifiers pass
→ original attack recipe independently shown blocked
→ read-only fix verifier verdict
→ human-controlled review/promotion/merge
```

The read-only verifier may report bounded verdicts such as:

- `fixed`;
- `partially_fixed`;
- `not_fixed`;
- `regression_detected`;
- `cannot_verify`;
- `out_of_scope_change`.

It has no merge/publication authority.

---

## 17. Browser UX

The primary entry is the assessment conversation/task experience.

A specialist Source Hunt page may still exist for exact setup and reports, but:

- it must use the shared product shell;
- it must not become a second dark dashboard product;
- it must not be the only way to understand running work;
- its result/state must project back to the originating workspace;
- it must not fabricate progress/readiness/findings.

Do not describe the primary path as a permanent `Analysis → Source Hunt` dashboard hierarchy when the canonical product is chat/task-first.

---

## 18. Worker operation

Current management command:

```bash
python manage.py vh_run_source_hunt_worker --poll-seconds 0.5
```

Single-job supervised mode:

```bash
python manage.py vh_run_source_hunt_worker --once
```

Runtime configuration remains environment-specific and must not be inferred from documentation alone.

---

## 19. Direct CLI operation

A supervised direct CLI path may remain available for exact approved repository work.

Use actual command help as the operational source of truth. Documentation examples must not invent flags that current CLI does not expose.

---

## 20. Acceptance requirements

Source Hunt is complete for a runtime slice only when applicable tests verify:

1. approved root succeeds;
2. outside-root path fails;
3. symlink escape fails;
4. file mutation during snapshot fails;
5. file-count/byte limits fail predictably;
6. preflight reports those limits before submission where possible;
7. exact snapshot hash is deterministic;
8. changed revision/snapshot/path invalidates approval;
9. prohibited/sensitive source is not transmitted;
10. model references are path/hash/line validated;
11. falsification/capability filters can reject candidates;
12. live activity is persisted and projected;
13. reconnect reconstructs the same job/timeline;
14. failure preserves prior work;
15. no hidden chain-of-thought appears;
16. permitted-path behavior matches what the UI claims.

---

## 21. Limitations

Source Hunt does not claim:

- complete semantic taint analysis;
- complete language coverage;
- automatic exploitability proof;
- production business impact;
- authoritative severity;
- automatic patch correctness;
- merge/publication readiness.

The current source mapper is Python-first and deliberately abstains on ambiguity. Real private-source use also depends on operator review of provider terms, retention and data controls.
