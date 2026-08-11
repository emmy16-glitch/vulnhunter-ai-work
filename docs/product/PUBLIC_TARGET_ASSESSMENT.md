# Public Target Assessment Contract

**Status:** BINDING PRODUCT AND SECURITY CONTRACT  
**Applies to:** website targets that resolve to public Internet addresses  
**Authority:** subordinate only to repository security invariants in `AGENTS.md`; equal product authority with the website assessment workflow documents  
**Product decision:** VulnHunter supports authorised public-target assessment. A public address is not permission.

---

## 1. Permanent product rule

VulnHunter may assess a public Internet target only when the backend can prove that an exact, active, time-limited authorization record covers the exact target and execution profile.

The supported shape is:

```text
public URL
→ exact target normalization
→ authorization evidence and approver identity
→ immutable authorization record
→ exact protocol / port / path / address binding
→ safe public-target transport validation
→ immutable assessment plan
→ required confirmation / approval
→ signed worker job
→ bounded execution
→ persisted live activity
→ evidence / candidate findings
→ deterministic verification
→ human review / report
```

Public-target support must never be implemented by deleting scope checks, changing `allow_public=False` to `True` globally, or removing private-network protections.

---

## 2. Authorization is mandatory

Every public target requires a persisted authorization record before any network execution.

The record must bind at minimum:

- authorization ID;
- normalized target URL;
- hostname;
- scheme;
- effective port;
- segment-aware path boundary;
- approved DNS/address set or the approved connection-time address policy;
- owner/controller identity;
- approving identity;
- purpose;
- evidence reference;
- approved scan profile(s);
- request/page/depth/rate limits where applicable;
- valid-from and expiry;
- immutable record digest;
- revocation state.

Chat text, a pasted URL, a model answer, a checkbox, a screenshot, or a user saying “I own this” is not by itself execution authority. The UI may collect the evidence and guide the operator, but the backend authorization service must create and validate the record.

---

## 3. Acceptable authorization evidence

VulnHunter supports multiple authorization bases, but the evidence type must be recorded truthfully.

### 3.1 Owner-controlled target

For a domain/deployment genuinely controlled by the operator or their organization, the product may support an owner self-attestation flow when policy permits it.

The record must still identify:

- the owner/controller;
- the approving actor;
- the exact target;
- the reason the actor is permitted to approve testing;
- an evidence reference that does not contain secrets;
- the bounded scan profile and expiry.

Self-attestation is not a bypass. It is a specific authorization basis for an owner-controlled target.

### 3.2 Client or third-party target

Use written permission, a contract, ticket, statement of work, security-testing approval, or equivalent authorization. Record the reference, not raw confidential material.

### 3.3 Bug bounty / vulnerability disclosure programme

Record the programme and exact in-scope asset/scope reference. The effective VulnHunter scope must be equal to or narrower than the programme scope.

Out-of-scope assets, prohibited test classes, rate restrictions and time windows remain binding.

---

## 4. Target classes

The scope layer must classify resolved addresses explicitly.

Allowed target classes when separately authorised:

- `private` — RFC1918/private laboratory target;
- `public` — globally routable public Internet target.

Always prohibited:

- unspecified addresses;
- multicast;
- link-local;
- cloud/container metadata addresses;
- localhost/loopback for a remote scanner worker;
- reserved/special-use addresses not explicitly supported;
- mixed public/private resolution where the target class is ambiguous;
- a redirect or DNS change that escapes the exact authorization boundary.

A public hostname must never be allowed to rebind to an internal/private/metadata address during execution.

---

## 5. Public-target network transport requirements

Public-target support is incomplete until the worker preserves these properties at execution time.

### 5.1 Connection-time revalidation

Immediately before every outbound connection, resolve/revalidate the target and fail closed if the result is outside the authorized address policy.

### 5.2 Approved-address pinning

The transport must connect only to an address accepted by the authorization decision. The underlying client/scanner must not silently perform an unrestricted second DNS resolution that bypasses the approved set.

### 5.3 Host and TLS identity preservation

When connecting to a pinned public address, preserve the original hostname for:

- HTTP `Host` semantics;
- TLS SNI;
- certificate validation;
- target identity/provenance.

Do not “solve” DNS pinning by scanning a raw IP when that changes virtual-host or TLS semantics.

### 5.4 Redirects

Automatic redirects remain disabled unless a future reviewed transport contract explicitly preserves the same guarantees. Every redirect target must be normalized and independently revalidated against the authorization.

### 5.5 Private-network pivot prevention

A public assessment may never become permission to reach private, loopback, link-local or metadata addresses. DNS rebinding, redirects, alternate addresses and tool-internal resolution must fail closed.

---

## 6. Public-target scan profiles

The first supported public-target profile should be **passive**.

Default public passive limits should remain deliberately low unless an exact authorization explicitly permits more:

```text
profile            passive
rate limit         1 request/second
concurrency        1
retries            0
redirects          disabled / manually revalidated
public OAST        disabled
cloud upload       disabled
automatic updates  disabled
headless execution disabled unless separately reviewed
code/file templates disabled unless separately reviewed
```

The actual worker policy and immutable plan remain authoritative. UI defaults do not grant execution permission.

`standard`, `intrusive`, `retest`, authenticated, state-changing, active-validation or destructive classes require separate product/security contracts and must not be enabled merely because public passive scanning is supported.

---

## 7. Worker architecture rule

The existing private-lab worker must not be weakened to obtain public support.

Public support must be represented explicitly in worker policy and validation, for example through a reviewed target-class capability such as:

```text
allowed_target_classes = private | public
```

or an equivalent typed policy.

A worker that declares private-only capability must continue to reject public jobs.

A public-capable worker must prove, through tests and runtime validation, that hostname/SNI/Host preservation and connection-time address containment cannot be bypassed by DNS rebinding, redirects or tool-internal resolution.

Do not change a private-only safety assertion into a permissive boolean without implementing the complete public transport boundary.

---

## 8. Conversation and authorization UX

The ordinary flow should remain chat/task-first:

```text
User: Assess https://example.com

VulnHunter
Checking target and authorization…

Authorization required
Target   https://example.com/
Port     443
Class    Public

No active authorization covers this exact target.
[Review authorization]
```

For an owner-controlled target, the authorization flow may collect:

- owner/controller name;
- approving name;
- authorization basis;
- evidence reference;
- purpose;
- exact target/path;
- requested passive profile;
- expiry.

For a client/third-party target, the product should require an appropriate independent/written authorization basis.

After successful creation or selection, the conversation should project:

```text
✓ Authorization verified
✓ Exact target bound
Ⅱ Plan confirmation required
○ Queue passive assessment
```

The user should not have to paste the same evidence repeatedly after a valid active record exists.

---

## 9. Immutable public assessment plan

Before execution, show an exact plan containing at minimum:

- authorization ID;
- target URL;
- target class (`public`);
- scheme and port;
- path boundary;
- scanner;
- scan profile;
- exact reviewed template set or manifest digest;
- rate limit;
- concurrency;
- redirect policy;
- prohibited actions;
- expiry;
- plan digest.

The run owner may confirm only the exact immutable plan. A changed target, profile, template set, policy or digest requires a new decision.

---

## 10. Live execution requirement

A public scan must use the same persisted live-execution contract as private website scans.

The user must be able to see truthful operational activity such as:

```text
✓ Authorization verified
✓ Plan confirmed
✓ Worker claimed job
◌ Nuclei passive assessment
  Current target: example.com:443
  Templates: 17 reviewed passive templates
  Latest receipt: HTTP probe completed
○ Evidence normalization
○ Deterministic verification
```

Do not expose hidden chain-of-thought. Do not invent progress percentages. See `docs/product/LIVE_EXECUTION_ACTIVITY.md`.

---

## 11. Evidence and findings

Public-target evidence remains bound to:

- assessment ID;
- authorization ID;
- exact target identity;
- plan digest;
- worker/tool identity and version;
- execution ID;
- timestamps;
- evidence digest/provenance.

Scanner output creates candidate observations, not automatically confirmed vulnerabilities. Deterministic verification and human review remain authoritative.

---

## 12. Revocation, expiry and cancellation

The worker must refuse or stop work when:

- authorization expires;
- authorization is revoked;
- plan expires;
- target/address class escapes the approved boundary;
- cancellation is requested and reaches a supported checkpoint;
- worker policy no longer permits public execution;
- a required integrity check fails.

A browser refresh never creates new authority or restarts a run.

---

## 13. Required public-target tests

Before public execution can be classified as implemented, tests must cover at least:

1. exact authorized public hostname succeeds;
2. same host on unauthorized port fails;
3. same host outside path boundary fails;
4. expired/revoked authorization fails;
5. missing evidence/approval basis fails where required;
6. mixed public/private DNS fails;
7. public hostname rebinding to private fails at connection time;
8. metadata/link-local/localhost targets fail;
9. redirect to another host fails unless separately authorized;
10. DNS change outside approved addresses fails;
11. Host header and TLS SNI remain the original hostname while using approved address pinning;
12. private-only worker rejects a public job;
13. public-capable worker accepts only an explicitly authorized public job;
14. plan digest changes require a new confirmation/approval;
15. rate/concurrency limits cannot be raised by browser input;
16. forbidden template/action classes remain blocked;
17. cancellation, timeout and restart preserve truthful task state;
18. activity/evidence/findings remain assessment-scoped after reconnect.

No test may replace real containment with a permissive mock that cannot detect the motivating failure.

---

## 14. Implementation status rule

Documentation may define public-target support as a product requirement before the runtime is complete, but status documents must distinguish:

- `PRODUCT CONTRACT — APPROVED`;
- `RUNTIME — PARTIAL/NOT COMPLETE`;
- `RUNTIME — IMPLEMENTED AND VERIFIED`.

Never claim public-target execution is implemented while the configured worker still rejects public targets or lacks connection-time public hostname pinning.

---

## 15. Agent stop conditions

An agent implementing public-target support must stop and report instead of weakening controls when:

- it cannot preserve Host/SNI/certificate semantics while pinning the approved address;
- the scanner performs uncontrollable second-stage DNS resolution;
- it cannot prevent public-to-private/metadata rebinding;
- authorization ownership/approval semantics are ambiguous;
- a requested scan profile is more invasive than the authorization permits;
- the only way to make tests pass is to remove a security assertion;
- the target is not exactly authorized.

The correct outcome is a bounded blocker, not a permissive workaround.
