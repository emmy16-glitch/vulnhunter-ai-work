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
- redacted audit events;
- connection-time DNS revalidation;
- approved-address-only TCP connection attempts;
- connected-peer verification;
- original-host preservation for HTTP routing and TLS validation;
- no keep-alive reuse across independently pinned requests.

## Connection binding boundary

`ApprovedTarget.resolved_addresses` remains the immutable outer address set. Each request, including every redirect hop, receives a fresh connection-time resolution. The result must be a non-empty subset of the approved set. The TCP backend receives the selected IP address directly, verifies the connected peer, and never falls back to an unapproved result.

The request URL hostname remains unchanged. This preserves virtual-host routing, TLS SNI, and certificate hostname verification while removing the second hostname lookup from the socket connection path.

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

## Residual transport limitations

Connection pinning is implemented for VulnHunter's direct HTTP/HTTPS transport. Proxy support remains intentionally disabled because a proxy creates a separate DNS and routing trust boundary. Operating-system compromise, malicious local certificate stores, or privileged socket interception remain outside the application's protection boundary.

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

## Governed collection boundary

A campaign is not permission to scan. It narrows existing authorization records
and accepts only scans whose authorization event sequence and persisted scan
summary agree. Campaign approval is bound to the SHA-256 digest of the exact
campaign intent and registered applications.

## Authenticated review boundary

Governed review requires an active local identity, successful secret
verification, the required role, an explicit assignment, no application
conflict, and separation from the campaign creator and owner. Existing direct
review commands remain available for synthetic and historical workflows, but
those decisions cannot qualify for governed dataset release without a matching
identity-bound attestation.

The local secret registry is not a federated identity provider, hardware-backed
credential store, or proof that two accounts are controlled by different human
beings. Those limitations must remain explicit.
