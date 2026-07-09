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
- benchmark manifest and review workflow.

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
