# Testing Strategy

## Test pyramid

### Unit tests

Cover deterministic business rules:

- scope and URL validation;
- redaction;
- budgets and cancellation;
- passive analyzers;
- persistence methods;
- fingerprints and conflicts;
- features, splitting, estimators, and metrics.

### Integration tests

Cover component boundaries using local resources:

- HTTPX mock transport;
- loopback HTTP server;
- temporary SQLite database;
- CLI runner;
- benchmark manifest and review workflow;
- scripted HTTPcore streams and real loopback sockets for address pinning.

### End-to-end smoke tests

Cover:

- local target approval;
- passive mapping;
- observation persistence;
- review labelling;
- readiness;
- model training;
- artifact inspection and prediction.

## Mandatory commands

```bash
python -m ruff format .
python -m ruff check .
python -m compileall -q vulnhunter
python -m pytest -q
python -m ruff format --check .
git diff --check
```

## Test isolation

Tests must not:

- contact the public Internet;
- rely on external DNS;
- mutate a developer database;
- depend on execution order;
- use nondeterministic seeds without recording them;
- leave servers or temporary files behind.

## Security regression expectations

Any discovered bypass or contract mismatch receives a dedicated regression test before the milestone is committed.

## Performance testing

Current tests focus on correctness. Future performance tests should measure:

- bounded-memory response processing;
- mapping queue growth;
- SQLite query performance;
- feature extraction latency;
- model prediction latency;
- benchmark reproducibility.

- orchestration changes: specification validation, path boundaries, role separation, verifier timeouts, repeated-error/no-progress stops, diff binding, evidence integrity, review/approval gates, and guarded rollback;

### Transactional research tests

Cover:

- editable, read-only, and inaccessible path classification;
- protected-snapshot tampering;
- exactly-one-commit worktree rules;
- trusted metric schema and finite values;
- objective, regression, and safety gates;
- reject cleanup and accepted-candidate promotion;
- event/evidence integrity;
- meta-search repetition and stagnation detection;
- no arbitrary shell execution or evaluator-policy mutation.

## Unattended control-plane tests

Cover manifest validation, independent approval, hash binding, revocation, expiry, path escape, command allowlists, connector/secret/network allowlists, remote-sensitive-data restrictions, fixed command execution, evidence tampering, two-failure isolation, independent-task continuation, critical blocker halting, and required-verifier completion.

## Connection-pinning tests

Cover:

- original hostname preservation in the HTTP `Host` header;
- original hostname preservation for TLS SNI;
- connection-time DNS changes before any TCP attempt;
- approved-address-only retries;
- peer-address mismatch rejection;
- direct IPv4 and IPv6 targets;
- independent connections with keep-alive disabled;
- connection audit evidence;
- safe-client default integration and caller-supplied test transports;
- an operating-system loopback socket integration path with no external DNS.
