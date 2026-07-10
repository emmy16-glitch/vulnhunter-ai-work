# Explicit Target Authorization

## Purpose

Technical scope validation proves that a URL belongs to the configured laboratory address space. It does not prove that the operator has permission to test that target.

Milestone 12 adds a separate authorization boundary that must succeed before `vulnhunter scan run` performs any network request.

## Record contents

Each authorization records:

- a unique authorization ID;
- normalized target origin and path boundary;
- the resolved-address snapshot approved at issuance;
- target owner and person granting permission;
- the specific testing purpose;
- optional reference to supporting permission evidence;
- issuance, activation, and expiry timestamps;
- maximum pages, depth, requests, and fastest permitted request rate;
- active or revoked status;
- revocation reason and timestamp;
- deterministic SHA-256 integrity hash.

## Validation order

```text
Raw target URL
    -> laboratory scope validation
    -> load authorization by ID
    -> verify stored-record integrity
    -> verify active time window
    -> verify not revoked
    -> verify origin and path containment
    -> verify current addresses are within the approval snapshot
    -> verify requested scan limits
    -> append audit event
    -> permit scan creation
```

No scan row is created when authorization validation fails.

## Audit lifecycle

The authorization registry preserves append-only events for:

- creation;
- successful validation;
- rejected validation;
- scan start;
- scan completion;
- scan failure;
- revocation.

Event details are redacted before persistence.

`scan_completed` events include the authorization ID, normalized scan database
path, scan ID, normalized target URL, and the deterministic persisted scan
snapshot hash. Governed campaign linking requires that exact completion tuple to
match the scan-start evidence and the current scan repository row.

## Boundaries

An authorization does not:

- expand the laboratory-only network scope;
- permit POST, PUT, PATCH, or DELETE;
- permit exploitation or credential attacks;
- override redirect or derived-URL containment;
- prove that a human-provided permission statement is genuine.

The operator remains responsible for entering truthful authorization details and retaining real permission evidence outside secret-bearing tracked files.

## Commands

```bash
vulnhunter authorize create --help
vulnhunter authorize list --help
vulnhunter authorize show --help
vulnhunter authorize check --help
vulnhunter authorize revoke --help
vulnhunter authorize events --help
```

A passive scan now requires:

```bash
vulnhunter scan run URL \
  --authorization AUTHORIZATION_ID \
  --authorization-database authorizations.db
```
