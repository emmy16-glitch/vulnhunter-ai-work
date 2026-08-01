# VulnHunter AI — Test-Engineered Batch Delivery

## Purpose

VulnHunter development uses dependency-aligned implementation batches rather than a long sequence of tiny disconnected changes. A batch may combine several closely related capabilities only when they share the same authoritative data lifecycle, trust boundary, cancellation semantics and acceptance path.

Speed never overrides evidence, safety or correctness. No batch is merged while a required test, security, browser, phone, worker or repository gate is failing.

## Batch selection rules

A valid batch:

- delivers one understandable product outcome;
- combines only directly dependent capabilities;
- reuses existing authoritative stores and task graphs;
- does not introduce a second browser-only or loosely synchronised workflow;
- has a bounded rollback and cancellation boundary;
- records explicit unfinished work without pretending it is complete.

Unrelated areas such as retesting, local-model work, Android dynamic analysis and production deployment must not be combined merely to reduce the number of pull requests.

## Mandatory engineering sequence

Every substantial batch follows this order:

1. Read the canonical architecture, `AGENTS.md`, relevant implementation, exports, tests and web/worker wiring.
2. Define the exact product outcome, exclusions, authority boundaries and failure behaviour.
3. Write or commit contract, adversarial and regression tests before or alongside implementation.
4. Implement immutable trust-boundary models and atomic persistence transitions.
5. Implement services without granting model, browser or submitted text execution authority.
6. Project the same durable state into authoritative task graphs and chat workspaces.
7. Add protected web flows only for password step-up, exact confirmations and large structured evidence.
8. Test cancellation, replay, stale revisions, tampering, duplicate submissions, restart and reconnect recovery.
9. Run the complete repository and operational acceptance gates on the exact candidate commit.
10. Update the canonical architecture and this batch's limitations in the same pull request.
11. Merge only the exact fully green commit, normally by squash merge.

## Required test layers

Each batch must include the applicable layers below.

### Contract tests

- schema validation;
- immutable identifiers and hashes;
- exact source, target, artifact and revision binding;
- legal and illegal state transitions;
- append-only history.

### Adversarial tests

- stale compare-and-swap writers;
- scope or path expansion;
- replay and duplicate receipts;
- identity impersonation;
- tampered evidence or manifests;
- authority supplied through ordinary chat;
- secret-bearing or traversal inputs.

### Service tests

- expected success;
- blocked and failure paths;
- rollback without orphan records;
- deterministic timestamps and outcomes;
- idempotent recovery.

### Task-graph tests

- browser-independent projection;
- bounded retries;
- cancellation;
- immutable terminal states;
- truthful blocked, failed, abstained and unavailable states;
- no downstream review, report or release claim before prerequisites pass.

### Web and conversation tests

- authentication, CSRF and password re-authentication;
- ordinary chat routes but does not consume protected authority;
- phone and desktop use the same durable workspace;
- reconnect refreshes from authoritative storage;
- submitted evidence is parsed as typed data and never executed as a command.

### Repository and operational gates

At minimum, the exact candidate head must pass:

- Python 3.11 and 3.12 complete test suites;
- Ruff lint and formatting;
- Python compilation;
- strict repository audit and `git diff --check` equivalent;
- scanner compatibility and restricted-worker checks;
- conversational workspace tests;
- real phone and resumable-upload recovery tests;
- responsive browser lifecycle and visual/a11y audit;
- genuine private-lab acceptance relevant to the changed boundary.

Additional subsystem acceptance is mandatory whenever a batch touches an activated worker, scanner, provider, database migration or deployment contract.

## Merge discipline

- Open the pull request as draft while integration failures are still expected.
- Never weaken a test to make a defective implementation pass.
- Diagnose every failing gate and fix the authoritative contract.
- Keep temporary workflows, patch helpers, generated artifacts, databases, secrets and test output out of the final diff.
- Compare the final branch against `main` and verify that every changed file belongs to the declared batch.
- Mark ready and merge only after all required checks pass on the exact documented head.

## Permanent authority separation

Even inside a combined batch:

- models propose but do not authorise;
- browsers display and route but are not authoritative stores;
- workers collect bounded evidence but do not confirm findings;
- builders do not verify their own fixes;
- verifiers are read-only;
- independent humans control review, merge, release and publication.

## Definition of batch completion

A batch is complete only when its declared end-to-end outcome works, its failure behaviour is proven, documentation matches reality, all required gates are green, no temporary artifact remains and the canonical architecture states both the completed capability and every remaining limitation.
