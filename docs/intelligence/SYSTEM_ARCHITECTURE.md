# System Architecture

## Trust-boundary pipeline

```text
User-provided URL
  |
  v
scope.validator.validate_target
  |
  v
ApprovedTarget
  |
  v
authorization.validate_scan_authorization
  |
  v
Authorized scan decision
  |
  +--> scope.guard.validate_scoped_url
  |        |
  |        v
  |      ScopedUrl
  |        |
  v        v
scanner.SafeHttpClient
  |
  +--> policy / cancellation / request budget / rate limiter
  +--> manual redirect validation
  +--> PinnedAsyncTransport
  |      +--> connection-time DNS subset validation
  |      +--> approved-address-only TCP attempts
  |      +--> connected-peer verification
  |      +--> original Host and TLS hostname preservation
  +--> bounded body streaming
  +--> redacted HTTP and connection audit events
  |
  v
mapping
  |
  +--> bounded queue
  +--> HTML link extraction
  +--> out-of-scope rejection
  |
  v
observations
  |
  +--> passive analyzers
  +--> redacted persistence
  +--> first-review and second-review queues
  +--> two-reviewer consensus or independent adjudication
  +--> effective human label
  |
  v
governance
  |
  +--> authenticated campaign administrators, reviewers, and adjudicators
  +--> exact authorization and completed-scan bindings
  +--> application-family metadata and conflict checks
  +--> identity-bound review attestations
  +--> fail-closed campaign completion and release manifest
  |
  v
ml.dataset / quality / splitting
  |
  +--> reviewed-only records
  +--> duplicate/conflict checks
  +--> scan-group isolation
  |
  v
ml.training / tuning / diagnostics
  |
  +--> training-only selection
  +--> locked holdout evaluation
  +--> versioned model provenance
```

## Architectural principles

- Validate technical scope before use.
- Validate explicit human authorization before manual network activity.
- Represent trusted values with dedicated types.
- Revalidate every derived network destination.
- Bind each socket connection to an approved connection-time address.
- Redact at the earliest persistence or display boundary.
- Keep passive evidence separate from human conclusions.
- Preserve immutable reviewer decisions separately from the effective compatibility label.
- Keep scans intact across dataset splits.
- Store enough provenance to reproduce every model artifact.
- Prefer explicit failure to silent fallback.

## Runtime dependencies

The project intentionally uses a small dependency set:

- HTTPX for asynchronous HTTP;
- HTTPcore for the explicit connection-pinning backend used beneath HTTPX;
- Pydantic for validated immutable models;
- Typer for CLI commands;
- SQLAlchemy for persistence;
- Beautiful Soup for HTML parsing;
- pytest and Ruff for development verification.

New dependencies require a written justification covering security, maintenance cost, disk impact, and why existing dependencies are insufficient.


## Engineering orchestration boundary

```text
LoopSpec
  -> bounded builder changes
  -> deterministic evaluation evidence
  -> security-policy evidence
  -> independent review
  -> human approval
  -> documentation and learning record
```

The orchestration subsystem governs project changes; it is separate from target scanning and cannot grant scan authorization or alter human finding labels.

## Transactional research plane

```text
clean Git baseline
  -> immutable evaluator policy and protected snapshot
  -> isolated experiment worktree
  -> exactly one candidate commit
  -> trusted baseline/candidate metric reports
  -> fixed verifiers plus safety/regression gates
  -> accept, reject, or inconclusive
  -> rejected worktree removed; accepted candidate awaits human promotion
```

The optional meta-search layer reads experiment metadata only. It can propose strategy-weight changes after detecting repetition or stagnation, but it cannot edit code, evaluator resources, labels, holdouts, or safety policy.

## Unattended control-plane flow

```text
Task profile
  -> scheduling recommendation
  -> immutable permission manifest
  -> distinct human approval bound to SHA-256
  -> run record bound to repository commit
  -> runtime permission checks
  -> fixed shell-free command evidence
  -> blocker isolation or critical halt
  -> required-verifier completion gate
```

The control plane composes with orchestration and autoresearch; it does not replace their objective, evaluator, review, or promotion gates.

## Connection-bound transport flow

```text
ScopedUrl
  -> connection-time resolver
  -> canonical current address set
  -> subset check against ApprovedTarget
  -> deterministic approved-address attempts
  -> TCP peer-address verification
  -> HTTP using original hostname
  -> TLS SNI and certificate validation using original hostname
  -> immutable ConnectionAuditEvent
```

The connection pool disables keep-alive reuse. This intentionally trades some throughput for a fresh, auditable binding decision on every request and redirect.

## Governed collection and review flow

```text
Target authorization registry
        ↓ exact immutable authorization snapshot
Draft campaign + application diversity metadata
        ↓ distinct administrator approval of manifest SHA-256
Active campaign
        ↓ authorization validation/start/completion event correlation
Completed passive scan links
        ↓ observation-specific assignments
Authenticated reviewer A + authenticated reviewer B
        ↓ consensus or assigned adjudicator
Identity-bound repository decision attestations
        ↓ campaign completion gate
Immutable dataset release manifest
```

The governance database stores identity records, campaign records, application
bindings, scan links, assignments, attestations, releases, and a global
hash-chained event history. The observation database remains authoritative for
finding evidence and effective labels; the governance layer proves which
approved identity and campaign workflow produced those labels.
