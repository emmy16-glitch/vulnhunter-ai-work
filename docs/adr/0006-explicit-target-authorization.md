# ADR-0006: Require explicit target authorization before scanning

- Status: Accepted
- Decision date: 2026-07-09

## Context

Private-address and path validation reduce technical scope risk but cannot establish legal or organizational permission. The previous workflow could validate a laboratory URL and immediately start a scan without binding it to a human authorization record.

## Decision

Require a time-limited, integrity-checked authorization ID before `scan run` creates a scan or performs a network request.

The record binds:

- approved origin and path;
- resolved-address snapshot;
- owner, approver, and purpose;
- expiry and revocation state;
- passive scan ceilings;
- append-only lifecycle events.

The registry is stored separately from scan observations so it can evolve without unsafe alteration of existing scan tables.

## Consequences

Benefits:

- technical scope and human permission become distinct enforced boundaries;
- every manual scan has auditable permission context;
- revocation and expiry stop future scans;
- requested limits cannot exceed approved ceilings.

Costs:

- operators must create and manage authorization records;
- current permission evidence is referenced rather than cryptographically signed;
- benchmark internals remain a separate controlled workflow rather than using manual scan authorization records.
