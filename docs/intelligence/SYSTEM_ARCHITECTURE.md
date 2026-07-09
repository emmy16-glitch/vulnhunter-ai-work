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
  +--> bounded body streaming
  +--> redacted audit events
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
- Redact at the earliest persistence or display boundary.
- Keep passive evidence separate from human conclusions.
- Preserve immutable reviewer decisions separately from the effective compatibility label.
- Keep scans intact across dataset splits.
- Store enough provenance to reproduce every model artifact.
- Prefer explicit failure to silent fallback.

## Runtime dependencies

The project intentionally uses a small dependency set:

- HTTPX for asynchronous HTTP;
- Pydantic for validated immutable models;
- Typer for CLI commands;
- SQLAlchemy for persistence;
- Beautiful Soup for HTML parsing;
- pytest and Ruff for development verification.

New dependencies require a written justification covering security, maintenance cost, disk impact, and why existing dependencies are insufficient.
