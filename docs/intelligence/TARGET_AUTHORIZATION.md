# Explicit Target Authorization

**Status:** BINDING AUTHORIZATION CONCEPT  
**Public-target execution contract:** `docs/product/PUBLIC_TARGET_ASSESSMENT.md`

## 1. Purpose

Technical target validation answers questions such as:

- is this a syntactically supported URL?;
- what hostname, scheme, port and path does it identify?;
- does it resolve to a supported private/public address class?;
- does the current resolution remain inside the intended technical boundary?

It does **not** prove that the operator has permission to test the target.

Authorization is a separate persisted, time-limited, integrity-bound decision that must succeed before any executable website assessment job is created.

This applies to both private and public targets.

## 2. Core rule

```text
reachable target
≠ authorized target
```

A URL, DNS resolution, browser checkbox, chat message, model answer or user claim does not itself create execution authority.

The backend authorization service owns the authorization record and validation decision.

## 3. Target classes

Authorization may cover an exact target whose addresses are classified as:

- `private` — private/laboratory target;
- `public` — globally routable public Internet target.

The target class does not replace authorization.

Mixed public/private, localhost/loopback, link-local, metadata and unsupported special-use conditions remain fail-closed according to the active transport/worker contract.

## 4. Authorization bases

### Owner-controlled target

When product policy permits it, the actual owner/controller may use a bounded self-attestation flow.

Record:

- owner/controller identity;
- approving identity;
- why that actor may authorize testing;
- exact target;
- purpose;
- evidence reference;
- profile/limits;
- expiry.

Self-attestation is a specific authorization basis, not a general bypass.

### Client / third-party target

Use a real written authorization basis such as:

- contract;
- statement of work;
- ticket;
- security-testing approval;
- customer instruction from an authorized contact.

Store a safe reference, not confidential/secret-bearing content.

### Bug bounty / VDP target

Record the exact programme and in-scope asset reference.

VulnHunter's effective scope/profile/limits must be equal to or narrower than the programme rules. Prohibited test categories remain prohibited.

## 5. Record contents

Each authorization should bind, directly or through immutable linked records:

- unique authorization ID;
- normalized target URL;
- hostname;
- scheme/protocol;
- effective port;
- segment-aware path boundary;
- approved address snapshot/policy;
- target class;
- owner/controller;
- approving person/identity;
- authorization basis;
- testing purpose;
- safe evidence reference;
- issuance/activation/expiry timestamps;
- approved scan profile(s);
- maximum pages/depth/requests and minimum delay where applicable;
- active/revoked status;
- revocation reason/time;
- deterministic integrity digest;
- append-only audit history.

## 6. Website assessment validation order

Conceptually:

```text
Raw target URL
→ normalize target
→ classify current addresses
→ load exact authorization by ID / exact active match
→ verify record integrity
→ verify active time window
→ verify not revoked
→ verify actor may use authorization
→ verify exact scheme / host / port / path boundary
→ verify requested profile and limits
→ verify current DNS/address state remains permitted
→ verify worker supports target class
→ build immutable plan
→ required confirmation / approval
→ create signed worker job
```

No executable worker job is created when authorization/scope/capability validation fails.

## 7. Public-target validation

Public authorization is not complete execution support by itself.

Before public network execution, the runtime must also satisfy `PUBLIC_TARGET_ASSESSMENT.md`, including:

- explicit public worker capability;
- connection-time DNS/address containment;
- no public-to-private/metadata rebinding;
- Host/TLS SNI/certificate identity preservation;
- redirect revalidation;
- bounded passive scanner policy.

The current private-only worker must truthfully reject public jobs until that execution path exists.

## 8. Private-target validation

Private authorization continues to require the relevant private-network approval/worker capability and exact address/target containment.

Public support does not remove existing private-target protections.

## 9. Path containment

Path boundaries are segment-aware.

For example:

```text
authorized: /app
allowed:    /app
allowed:    /app/login
not allowed:/application
```

Encoded traversal, dot segments, backslash ambiguity and other malformed boundary escapes remain rejected.

## 10. DNS/address lifecycle

Authorization issuance may bind a resolved-address snapshot or approved address policy, but execution must not assume DNS can never change.

The actual network transport must revalidate according to the target-class transport contract.

For public execution in particular, DNS changes must never allow a public hostname to pivot to private/metadata space.

## 11. Audit lifecycle

The authorization registry preserves append-only events for relevant lifecycle actions such as:

- creation;
- validation accepted/rejected;
- scanner activation binding;
- plan/run start;
- completion/failure;
- revocation.

Event details are redacted before persistence.

Where governed campaign/release correlation requires exact scan-completion provenance, completion records must remain bound to authorization/target/scan identities and persisted content hashes according to the current governance contract.

## 12. What authorization does not do

Authorization does not automatically:

- make a private-only worker public-capable;
- permit a different hostname, port, protocol or path;
- allow redirects outside scope;
- allow DNS rebinding outside the approved transport policy;
- permit arbitrary POST/PUT/PATCH/DELETE behavior;
- permit destructive testing or denial of service;
- permit brute-force/credential attacks;
- grant a model execution authority;
- prove that false evidence supplied by an operator is genuine.

The operator remains responsible for truthful permission evidence.

## 13. Revocation and expiry

Revocation/expiry must be effective before new execution and at the relevant runtime checkpoints.

A browser session, cached plan or previously approved model response cannot revive expired/revoked permission.

## 14. Browser behavior

The conversation should show an exact authorization requirement rather than generic governance jargon.

Example:

```text
Authorization required
Target  https://example.com/
Class   Public
Port    443
Path    /

No active authorization covers this exact target.
[Review authorization]
```

Once an exact active record exists, the workspace should reuse it and continue to the immutable plan rather than repeatedly asking the user for the same evidence.

## 15. CLI state

Use actual CLI help as the operational source of truth:

```bash
vulnhunter authorize create --help
vulnhunter authorize list --help
vulnhunter authorize show --help
vulnhunter authorize check --help
vulnhunter authorize revoke --help
vulnhunter authorize events --help
```

**Current limitation:** the existing generic authorization CLI target validation may still reject public targets until the public-target authorization/runtime programme updates it. Do not document a public CLI command as operational until code/tests expose it.

## 16. Acceptance

Authorization changes should test:

- expected exact-match success;
- wrong host/port/protocol/path rejection;
- expiry/revocation;
- record tampering;
- actor ownership/role restriction;
- request/profile limit enforcement;
- private/public target classification;
- mixed resolution rejection;
- public authorization cannot bypass private-only worker capability;
- public runtime containment once implemented;
- audit redaction/integrity.
