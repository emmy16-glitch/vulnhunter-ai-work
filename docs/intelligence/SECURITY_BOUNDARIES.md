# Security Boundaries

## Authorisation boundary

Testing is restricted to explicitly authorised laboratory targets. Current target validation permits loopback and approved private laboratory address ranges while rejecting public and ambiguous destinations.

Authorisation is a human responsibility. Passing technical scope validation does not independently prove permission. Manual scans therefore require a separate active authorization record with owner, approver, purpose, expiry, target boundary, and passive-scan ceilings.

## Authorization-record boundary

Before manual scanning, VulnHunter verifies record integrity, time window, revocation state, target origin/path, address snapshot, and requested limits. Failed authorization creates no scan row and performs no network request.

## URL boundary

The original target establishes immutable:

- scheme;
- hostname;
- port;
- path boundary;
- approved resolved addresses.

Every discovered link, redirect, form action, or manually supplied follow-up URL must pass the derived-URL guard.

## HTTP boundary

The transport enforces:

- configured read-only methods;
- no automatic redirects;
- no proxy inheritance from the environment;
- protected transport headers;
- request-count limits;
- minimum delays;
- timeouts;
- bounded response bodies;
- cooperative cancellation;
- redacted audit events.

## Data boundary

Raw secrets and sensitive values must not cross into:

- logs;
- SQLite records;
- exported datasets;
- model artifacts;
- diagnostics;
- CLI error output.

## ML boundary

Predictions are advisory. They cannot:

- mutate labels;
- resolve conflicts;
- approve findings;
- override human review;
- establish exploitability.

## Known security limitation

Pre-request DNS revalidation reduces risk but does not fully bind the eventual socket connection to the validated address. Connection-level address pinning remains open technical debt.

## Prohibited boundary changes

Do not:

- allow arbitrary public targets;
- accept raw strings directly in transport code;
- enable automatic redirects;
- permit caller-controlled `Host`;
- disable body limits;
- persist raw bodies;
- weaken redaction for convenience;
- merge train and holdout scan groups;
- make model decisions authoritative.

## Engineering-orchestration boundary

Loop approval governs a repository change only. It cannot authorize a target, confirm a vulnerability, alter a finding label, or promote a model. The verifier registry executes fixed command templates without a shell, but it is not a kernel-level sandbox. All evidence remains local and must be treated according to the project artifact-retention policy.

## Autoresearch evaluator boundary

Research candidates operate in isolated Git worktrees and may change only paths that are both listed by the experiment and classified as editable. Tests, accepted ADRs, scope, redaction, authorization, orchestration, research-engine code, benchmark evaluator logic, and CI policy are read-only. Local artifacts, secrets, private keys, production/customer data, and private-target inventories are classified as inaccessible and must not be tracked in the experiment baseline.

Protected resources are hashed from the clean primary baseline. Any protected-file change, missing resource, out-of-scope path, safety failure, regression, or verifier failure prevents acceptance regardless of objective score. Rejected candidates are removed from their isolated worktrees without rewriting the primary branch.

The current controls are application-level integrity and transaction controls, not a kernel sandbox. Local actor identities are recorded but not cryptographically authenticated.

## Unattended execution boundary

Unattended work requires an active manifest whose exact bytes were approved by a distinct human. Runtime adapters enforce tool, path, fixed-command, network, connector, named-secret, push, delete, and deployment permissions. Remote routines use stricter limits and exclude sensitive data by default. Revocation, expiry, or a critical blocker stops further actions.
