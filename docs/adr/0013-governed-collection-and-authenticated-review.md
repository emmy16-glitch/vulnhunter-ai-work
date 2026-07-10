# ADR-0013: Governed collection campaigns and authenticated review identities

- Status: Accepted
- Date: 2026-07-09

## Context

VulnHunter already had explicit target authorization, two-person review, and
adjudication. Collection records were not grouped into approved campaigns, and
review operations accepted caller-supplied pseudonymous IDs without authenticating
the actor. Building campaigns first with unverified reviewer strings would
create a temporary architecture that immediately needed replacement.

## Decision

Implement campaigns and reviewer identity enforcement together as one
trust-boundary milestone.

Campaigns bind exact authorization-record digests, narrower collection limits,
application-family metadata, and minimum diversity requirements. A distinct
administrator approves the digest of the complete draft and application set.
Only completed scans with matching authorization validation/start/completion
events can be linked. The completion event must bind the authorization ID,
normalized scan database path, scan ID, normalized target URL, and persisted scan
snapshot hash.

Review identities are local accounts with scrypt-protected secrets and explicit
administrator, reviewer, or adjudicator roles. Assignments enforce distinct
primary reviewers, creator/owner separation, conflict tags, active status, and a
distinct adjudicator. Each repository decision receives an immutable governance
attestation. Unattested direct or legacy decisions cannot qualify for a governed
release.

Dataset release requires a completed campaign, current unchanged authorization
records, diversity minima, matching scan snapshots, and final governed review
for every linked observation. The release is represented by an immutable
provenance manifest.

## Consequences

- Campaign review and release are fail-closed and auditable.
- Existing direct review commands remain compatible for synthetic and historical
  workflows but do not satisfy campaign release gates.
- Local secret authentication improves actor accountability without claiming
  external identity proof, MFA, or human uniqueness.
- A separate digital-signature and key-management milestone remains necessary
  for portable artifact authenticity.
- Real-data acquisition and external model validation can now proceed through a
  controlled workflow rather than ad hoc scans and labels.
