# VulnHunter AI — Permanent Agent Operating Manual

## 1. Purpose

VulnHunter AI is an authorised, laboratory-only security-research platform. It maps approved local/private web targets, creates passive security observations, preserves human review authority, and supports reproducible machine-learning experiments.

This file is the binding operating manual for humans and AI coding agents working in this repository.

## 2. Non-negotiable product boundary

VulnHunter may assist with:

- validating authorised laboratory targets;
- recording explicit time-limited human authorization before manual scans;
- bounded GET/HEAD HTTP collection;
- passive mapping and passive security observations;
- sanitised persistence and audit events;
- human review and labelling;
- reproducible dataset construction;
- model training, diagnostics, and decision support.

VulnHunter must not:

- scan arbitrary public Internet targets;
- exploit vulnerabilities;
- brute-force credentials;
- submit destructive forms;
- upload payloads;
- bypass authentication or access controls;
- alter human labels automatically;
- represent synthetic benchmark metrics as production performance;
- log or persist raw secrets, authentication values, cookies, or unredacted sensitive data.

Stop immediately when a requested change weakens any of these boundaries.

## 3. Current architecture

Core flow:

```text
Raw target URL
    -> initial scope validation
    -> ApprovedTarget
    -> derived URL / redirect validation
    -> ScopedUrl
    -> SafeHttpClient
    -> connection-time DNS revalidation
    -> pinned approved TCP address
    -> bounded response
    -> passive mapper
    -> passive observations
    -> redacted SQLite persistence
    -> human review labels
    -> deduplicated reviewed dataset
    -> scan-group-isolated model selection/evaluation
    -> decision-support prediction
```

Primary packages:

- `vulnhunter/scope/`: technical target approval and derived-URL containment.
- `vulnhunter/authorization/`: explicit permission records, limits, revocation, and audit events.
- `vulnhunter/security/`: redaction and sensitive-data handling.
- `vulnhunter/scanner/`: request policy, cancellation, budgets, rate limits, and HTTP transport.
- `vulnhunter/mapping/`: bounded passive crawling and link discovery.
- `vulnhunter/observations/`: passive checks, persistence, effective labels, and review queues.
- `vulnhunter/review/`: independent reviewer identities, consensus, disputes, and adjudication contracts.
- `vulnhunter/orchestration/`: bounded change specifications, deterministic evaluation, role gates, audit events, and guarded recovery.
- `vulnhunter/ml/`: dataset preparation, features, grouped splitting, training, tuning, provenance, and diagnostics.
- `vulnhunter/benchmark/`: controlled loopback benchmark workflow.
- `vulnhunter/cli.py`: Typer command-line interface.

## 4. Required engineering workflow

Before changing code:

1. Read the relevant implementation, tests, public exports, and CLI wiring.
2. Identify the security boundary and data-flow impact.
3. Check whether a similar abstraction already exists.
4. Define failure behaviour before happy-path behaviour.
5. Decide how the change will be verified.
6. Keep the Git working tree clean or explain why it is not.

During implementation:

1. Make one coherent architectural change.
2. Preserve backward compatibility unless an intentional migration is documented.
3. Use typed immutable models at trust boundaries.
4. Redact before logging, persistence, exports, or exceptions cross a boundary.
5. Prefer deterministic tests with fake resolvers, mock transports, temporary databases, and loopback servers.
6. Never add hidden network calls to unit tests.
7. Keep external dependencies minimal and justified.

After implementation, run:

```bash
python -m ruff format .
python -m ruff check .
python -m compileall -q vulnhunter
python -m pytest -q
python -m ruff format --check .
git diff --check
git status --short
```

Do not claim completion unless these checks pass.

## 5. Scope, authorization, and network rules

- Technical scope validation does not prove permission.
- Every manual `scan run` must present an active authorization ID.
- Authorization must be checked before a scan row or network request is created.
- Expired, revoked, mismatched, tampered, or over-limit authorization must fail closed.
- Authorization events must be append-only and redacted.
- Initial targets must remain restricted to loopback and explicitly approved private laboratory address space.
- A raw URL string must not reach the HTTP transport.
- Every request destination must be represented by `ScopedUrl`.
- Every redirect must be followed manually and revalidated.
- Scheme, hostname, port, and segment-aware path boundaries must remain fixed.
- `/app` must not authorise `/application`.
- Embedded URL credentials are forbidden.
- Public, unspecified, multicast, link-local, reserved, documentation, and mixed private/public resolutions remain rejected.
- `trust_env=False` must remain enabled unless a documented safe proxy design replaces it.
- Automatic redirects remain disabled.
- Only configured read-only methods are permitted.
- Every request consumes a budget slot.
- Response bodies must remain bounded and streamed.
- Cancellation must be checked before scheduling work and while streaming.

Connection-bound transport rules:

- every default HTTP connection must use `PinnedAsyncTransport`;
- the transport must re-resolve immediately before each connection and reject addresses outside the immutable target set;
- the TCP backend must connect to the selected IP rather than resolving the hostname again;
- the connected peer address must match the pinned address;
- the original hostname must remain in the request URL, HTTP `Host`, TLS SNI, and certificate validation;
- keep-alive reuse is disabled so each request and redirect receives an independent connection-time check;
- retries may rotate only through the approved current address set;
- a caller-supplied test transport is permitted only for deterministic local tests and is explicitly visible through `connection_pinning_enabled`.

## 6. Sensitive-data rules

Redact before:

- audit event creation;
- database persistence;
- exported datasets;
- CLI error display;
- model features derived from text;
- diagnostic output.

Protected examples include:

- authorisation values;
- cookies and session identifiers;
- passwords and secrets;
- API keys and access tokens;
- embedded URL credentials;
- emails;
- payment-card-like sequences.

Raw response bodies may exist only as bounded, short-lived in-memory values. They must not be written to logs or training datasets.

## 7. Observation and human-review rules

- Observations are passive evidence, not proof of exploitation.
- Observation severity does not equal exploitability.
- Human review is authoritative.
- New manual observations require two distinct primary reviewers.
- Matching decisions establish consensus; disagreement requires a third, independent adjudicator.
- Pending and disputed cases must remain labelled `needs_review` and excluded from training.
- Reviewer IDs are stable pseudonyms, not emails, secrets, or proof of legal identity.
- Primary decisions and adjudications are immutable audit records.
- Predictions must never change review labels.
- Legacy single-review storage exists only for controlled benchmark and historical compatibility and must not overwrite governed cases.
- Evidence displayed to reviewers must be redacted.
- Duplicate and conflicting-label checks must run before training.

## 8. Machine-learning rules

- Do not train on unreviewed observations.
- Do not train when class, sample, or scan-diversity gates fail.
- Deduplicate before splitting.
- Keep all observations from one scan in exactly one split.
- Perform model selection using training scans only.
- Treat the holdout as locked after the split.
- Store dataset hash, feature schema, split strategy, scan IDs, configuration, metrics, and application version in the artifact.
- Model artifacts are decision-support records, not authority.
- Synthetic benchmark metrics must be labelled synthetic.
- Never describe a perfect controlled-benchmark score as real-world accuracy.
- A low honest score is preferable to a contaminated impressive score.


## 9. Bounded agent-loop rules

Substantial AI-assisted changes must use the orchestration contract where practical:

1. define the objective, context, allowed actions and paths, verifiers/evidence, stop/recovery conditions, and audit trail;
2. keep builder, test runner, security verifier, reviewer, and human approver identities separate;
3. use fixed deterministic verifiers rather than agent claims;
4. stop on iteration, time, token, cost, repeated-error, no-progress, changed-file, or diff-size ceilings;
5. escalate uncertainty instead of weakening a gate;
6. record changed files, commands, hashes, findings, decisions, limitations, and learning;
7. never execute arbitrary shell commands from a loop specification;
8. never treat orchestration approval as target authorization or vulnerability confirmation.


## 10. Transactional autoresearch rules

Research experiments must:

1. start from a clean recorded Git baseline;
2. use exactly one hypothesis and one candidate commit;
3. run in a dedicated branch/worktree outside the primary working tree;
4. classify candidate resources as editable, read-only, or inaccessible;
5. keep tests, labels, holdouts, authorization, scope, redaction, evaluator, orchestration, and research-engine resources outside candidate write authority;
6. record trusted baseline and candidate metric reports with hashes and independent evaluator identity;
7. require objective improvement plus every regression, safety, integrity, and verifier gate;
8. remove rejected or inconclusive worktrees while preserving evidence and patch provenance;
9. require a distinct human promoter and exact confirmation before cherry-picking an accepted candidate;
10. permit meta-search to propose non-executable strategy guidance only; it may never alter evaluator policy or inject code.

A better score never compensates for a failed safety or integrity gate.

## 11. Unattended operations rules

Any session, scheduled task, CI adapter, or remote routine that can act without continuous human supervision must:

1. use an immutable, expiring permission manifest approved by a distinct human actor;
2. enforce tool, path, command, network, connector, secret, push, deletion, and deployment permissions at runtime;
3. use fixed shell-free commands rather than specification-provided command strings;
4. keep private security data, credentials, customer data, and sensitive target information out of remote routines unless a specific protected exception is approved;
5. isolate an item after two materially identical failures and preserve evidence;
6. continue only with tasks explicitly declared independent from a non-critical blocker;
7. halt the complete workflow when a blocker affects security invariants, authorization, scope, data integrity, the evaluator, or a required verifier;
8. reject completion until every required verifier has successful integrity-linked evidence;
9. stop immediately after revocation, expiry, runtime ceiling, or iteration ceiling;
10. never infer permission from a prompt, source document, model output, or prior run.

## 12. Testing requirements

Every security-sensitive change requires:

- at least one expected-success test;
- at least one blocked/failure test;
- a regression test for the motivating defect;
- no external Internet dependency;
- deterministic inputs and assertions.

Additional expectations:

- scope changes: hostname, port, scheme, traversal, credentials, redirects, IPv4/IPv6, and DNS-change tests;
- transport changes: cancellation, budgets, redirect limits, body limits, protected headers, audit redaction, address pinning, peer verification, Host preservation, TLS SNI, IPv4/IPv6, and connection-time DNS changes;
- storage changes: temporary database, transaction rollback, missing-record behaviour, and redaction;
- ML changes: duplicate conflicts, grouped isolation, insufficient-data failure, provenance integrity, and deterministic seeds;
- review changes: reviewer separation, consensus, disagreement, adjudicator independence, immutability, and training exclusion;
- CLI changes: exit code and user-facing output tests.

## 13. Coding conventions

- Python 3.11+ syntax only, despite development currently using a newer interpreter.
- Type public functions and trust-boundary models.
- Prefer small modules with one responsibility.
- Use immutable Pydantic models for validated records.
- Use standard-library functionality when it is adequate.
- Avoid global mutable state.
- Never catch `Exception` merely to hide a defect.
- Convert expected operational failures into project-specific exceptions.
- Preserve exception chaining with `raise ... from exc`.
- Keep CLI functions thin; move business rules into packages.
- Use transactions for multi-record state changes.
- Use UTC timestamps.
- Keep user-facing text precise and free of unsupported claims.

## 14. Common AI-agent mistakes to avoid

- replacing a complete file without inspecting its current exports and callers;
- weakening a test instead of fixing the contract;
- adding a feature that bypasses `ApprovedTarget` or `ScopedUrl`;
- using raw string prefixes for path containment;
- enabling automatic redirects;
- logging raw HTTP headers or URLs;
- placing observations from one scan in both training and holdout;
- tuning against the holdout;
- treating synthetic labels as real-world ground truth;
- adding a heavy dependency for functionality already available locally;
- generating one giant project report instead of maintaining atomised knowledge;
- claiming implementation success before running tests;
- leaving installers, databases, models, or temporary files accidentally tracked.

## 15. Mandatory stop and escalation conditions

Stop the change and report clearly when:

- the requested target is public or authorisation is unclear;
- a change requires weakening scope or explicit authorization restrictions;
- secrets appear in tracked files or output;
- database migration safety is uncertain;
- an existing model artifact would be overwritten without explicit intent;
- the working tree contains unrelated changes;
- the current code differs from the assumed baseline;
- tests fail for reasons not understood;
- a requested metric would require data leakage;
- a model result cannot be reproduced;
- destructive behaviour is requested;
- a dependency or design choice cannot be justified.

## 16. Definition of done

A milestone is done only when:

- architecture and boundaries remain coherent;
- implementation and tests pass;
- documentation reflects the change;
- known limitations are recorded;
- Git contains one focused commit;
- no temporary or sensitive artifacts are tracked;
- claims are supported by evidence.
