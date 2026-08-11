# ADR 0021 — Authorised Public Targets and Transport Containment

**Status:** ACCEPTED PRODUCT ARCHITECTURE / RUNTIME IMPLEMENTATION PENDING  
**Date:** 2026-08-11  
**Supersedes:** the product-level prohibition on public targets in ADR 0001; ADR 0001 remains historical rationale for strict target containment

## Context

VulnHunter originally restricted website assessment to local/private laboratory targets. That boundary was appropriate while the scanner/transport architecture matured, but the intended product must also assess public Internet targets that the operator is explicitly authorised to test.

Simply allowing globally routable IP addresses would be unsafe. A public hostname can change DNS results, redirect, or otherwise attempt to reach private/metadata networks. The scanner must also preserve virtual-host/TLS semantics while containing the connection to an approved address policy.

## Decision

VulnHunter supports two website target classes:

- `private`;
- `public`.

Both require exact active authorization.

A public address/hostname is **not** permission. Authorization must bind the exact target, owner/controller, approver, purpose, evidence reference, profile/limits and validity.

The first supported public execution profile is bounded passive assessment.

Public runtime execution is accepted only when the worker provides:

- explicit public target-class capability;
- connection-time DNS/address revalidation;
- no mixed public/private resolution;
- no localhost/loopback/link-local/metadata destination;
- no public-to-private/metadata rebinding;
- approved-address pinning or equivalent containment;
- original hostname preservation for HTTP Host, TLS SNI and certificate validation;
- redirect revalidation;
- signed immutable plan/job identity;
- reviewed passive templates and bounded rate/concurrency/timeout/output.

The existing private-only worker remains private-only until the public transport boundary is implemented and accepted.

## Authorization basis

Acceptable bases include:

- owner-controlled target self-attestation where product policy permits;
- client/third-party written testing authorization;
- contract/SOW/ticket approval;
- exact bug-bounty/VDP in-scope reference.

The effective VulnHunter scope must be equal to or narrower than the external authorization.

## Consequences

### Positive

- VulnHunter can evolve beyond private labs without abandoning explicit authorization.
- Public scanning becomes a governed product capability rather than an ad-hoc bypass.
- Existing private-target protections remain intact.
- Agents have an explicit transport/security design target.

### Costs

- public-host execution requires stronger transport work than a simple scope flag;
- public acceptance requires DNS/redirect/Host/SNI/certificate tests;
- current private worker cannot be labeled public-capable until that work lands.

## Rejected alternatives

### Globally set `allow_public=True`

Rejected. This changes address validation without proving authorization or worker transport containment.

### Delete `private_targets_only`

Rejected. This removes an existing safety invariant without replacing it.

### Scan the resolved public IP directly

Rejected as a general solution because it can break HTTP virtual-host routing, TLS SNI and certificate identity.

### Trust browser/chat evidence directly

Rejected. Browser/model text is not execution authority.

## Related contracts

- `AGENTS.md`
- `docs/product/PUBLIC_TARGET_ASSESSMENT.md`
- `docs/product/NUCLEI_INTEGRATION.md`
- `docs/product/CHAT_FIRST_WORKSPACE.md`
- `docs/product/LIVE_EXECUTION_ACTIVITY.md`
- `docs/intelligence/CURRENT_STATE.md`
- `docs/intelligence/ROADMAP.md`
