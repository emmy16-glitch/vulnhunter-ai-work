# ADR-0006: Require Explicit Target Authorization Before Scanning

- **Status:** Accepted
- **Decision date:** 2026-07-09
- **Clarified for public targets:** 2026-08-11 by ADR 0022

## Context

Technical address/path validation cannot establish legal or organizational permission.

That is true for both private and public targets.

A private address may belong to another internal system; a public hostname may be globally reachable but completely out of testing scope. Therefore technical target validity and testing authorization must remain separate enforced boundaries.

## Decision

Require a time-limited, integrity-checked authorization record before an executable website assessment job is created or performs network activity.

The authorization binds, directly or through immutable linked activation records:

- exact normalized target/origin and path boundary;
- scheme/protocol and port;
- target/address class;
- approved address snapshot/policy;
- owner/controller and approver;
- purpose and safe evidence reference;
- validity/expiry and revocation state;
- approved profiles and request/rate ceilings;
- append-only lifecycle/audit events;
- deterministic integrity digest.

The registry remains separate from scanner observations so authorization history cannot be silently rewritten by finding/evidence state.

## Public-target clarification

ADR 0022 adds `public` as an authorised product target class.

This ADR therefore means:

```text
private target + exact authorization → potentially eligible
public target + exact authorization  → potentially eligible
public target without authorization  → prohibited
```

Authorization alone does not prove that the currently configured worker can safely execute the target class. Public execution also requires the transport/worker containment in `docs/product/PUBLIC_TARGET_ASSESSMENT.md`.

## Consequences

Benefits:

- technical scope and permission remain distinct;
- private/public targets share one auditable permission model;
- expiry/revocation stops future work;
- requested scope/profile/limits cannot exceed the record;
- public support does not require weakening the authorization model.

Costs:

- operators must create/select truthful authorization records;
- permission evidence may still be referenced rather than independently cryptographically proven;
- owner self-attestation must be limited to genuine owner-controlled targets under explicit policy;
- client/third-party/bounty scope requires the relevant external authorization evidence;
- public worker capability needs separate transport acceptance.

## Rejected interpretation

Do not interpret this ADR as saying that a user can type “I authorize this target” in chat and thereby create unrestricted network authority.

The backend authorization workflow, target-class policy and worker capability remain authoritative.
