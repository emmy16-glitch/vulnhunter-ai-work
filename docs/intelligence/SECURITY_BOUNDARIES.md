# VulnHunter Security Boundaries

**Status:** CURRENT SECURITY-BOUNDARY REFERENCE  
**Public-target contract:** `docs/product/PUBLIC_TARGET_ASSESSMENT.md`  
**Authorization contract:** `docs/intelligence/TARGET_AUTHORIZATION.md`

## 1. Core security principle

VulnHunter separates four concepts that must never be collapsed:

```text
target is syntactically valid
≠ target is technically reachable
≠ target is authorised for testing
≠ current worker is allowed/capable of executing it
```

Every executable operation must pass the relevant boundary at each layer.

---

## 2. Authorization boundary

Testing is restricted to **explicitly authorised targets**.

Supported product target classes are:

- private/laboratory;
- public Internet.

A public target is not automatically authorised because it is globally reachable.

Authorization records remain backend-owned, time-limited and integrity-bound.

They bind exact target/scope, owner/controller, approver, purpose, evidence reference, profile/limits, expiry/revocation and audit state.

A chat message, browser checkbox, model answer or user claim cannot directly grant execution permission.

---

## 3. Current runtime target boundary

The current passive Nuclei worker remains **private-target-only**.

This is a current implementation property, not the finished product boundary.

Public-target execution is an approved product requirement but remains unavailable until the public-capable worker/transport boundary in `PUBLIC_TARGET_ASSESSMENT.md` is implemented and accepted.

Do not remove the current private-only assertion merely because the product now supports authorised public targets conceptually.

---

## 4. URL / target identity boundary

An approved target establishes exact identity including:

- scheme;
- hostname;
- effective port;
- segment-aware path boundary;
- target class;
- approved resolved-address snapshot/policy.

Every derived URL, redirect or follow-up target must be revalidated according to the applicable target-class contract.

Examples:

```text
authorised /app
allows    /app
allows    /app/login
rejects   /application
```

Embedded URL credentials and malformed/traversal boundary ambiguity remain prohibited.

---

## 5. Address-class boundary

Address classification must be explicit.

Public-target support never grants access to:

- localhost/loopback;
- link-local;
- metadata service addresses;
- unsupported reserved/special-use addresses;
- private addresses reached through a public-host rebinding attempt;
- ambiguous mixed public/private resolution.

A private-target workflow remains constrained to its approved private address set/policy.

---

## 6. Connection-bound transport boundary

VulnHunter's direct bounded HTTP transport preserves connection-time scope enforcement.

Relevant properties include:

- connection-time DNS revalidation;
- approved-address-only connection attempts;
- direct connection to selected approved IP where the transport uses pinning;
- connected-peer verification;
- original hostname preserved for HTTP routing and TLS validation;
- automatic redirect avoidance/manual revalidation;
- no environment-proxy inheritance unless a separately reviewed proxy boundary exists;
- bounded request methods/counts/delays/timeouts/body sizes;
- cooperative cancellation;
- redacted audit output.

The original hostname must remain in URL/Host/TLS SNI/certificate verification when address pinning is used.

---

## 7. Public-target transport boundary

A public-capable scanner path must additionally prove:

1. exact public authorization;
2. connection-time public DNS/address revalidation;
3. no mixed public/private resolution;
4. no public-to-private/link-local/metadata rebinding;
5. approved-address pinning or equivalent reviewed containment;
6. original hostname preserved for Host/SNI/certificate validation;
7. every redirect independently revalidated;
8. tool/scanner-internal DNS behavior cannot silently bypass containment;
9. worker target-class capability is explicit and immutable for the job;
10. evidence records retain exact target and connection provenance.

If the scanner cannot provide these properties directly, the design must introduce a reviewed transport/proxy/dialer boundary rather than deleting validation.

---

## 8. HTTP method/action boundary

Default passive website assessment remains read-oriented and bounded.

Public-target support does not automatically authorize:

- destructive methods;
- state-changing form submission;
- credential brute force;
- denial of service;
- unrestricted headless/browser scripting;
- code/file templates;
- public OAST/cloud upload;
- arbitrary scanner flags.

Higher-risk profiles/actions require distinct reviewed contracts and exact authorization.

---

## 9. Scanner manager / worker boundary

The browser/manager may prepare and authorize an immutable plan/job, but does not execute arbitrary scanner subprocesses directly.

The worker independently validates:

- signed job integrity;
- authorization/approval identity;
- target class and worker capability;
- target/scope/address policy;
- template manifest/digests;
- profile/rate/concurrency/timeout/output limits;
- cancellation/expiry;
- evidence output boundary.

A browser parameter cannot turn a private-only worker into a public-capable worker.

---

## 10. Authorization-record boundary

Before executable assessment, verify applicable:

- authorization record integrity;
- active time window;
- revocation state;
- actor permission;
- exact target origin/host/port/path;
- approved address policy;
- requested profile/limits;
- worker capability.

Failure creates no executable worker job/network request.

Authorization evidence references must be safe to persist and must not contain raw secrets.

---

## 11. Live task / browser state boundary

The browser does not own execution truth.

Server/persisted state owns:

- assessment/job identity;
- authorization;
- plan/approval;
- worker/tool state;
- activity events;
- evidence/findings;
- cancellation/recovery;
- report readiness.

Browser memory may hold only ephemeral UI state such as drafts, open drawers and last-seen event cursors.

Refresh/reconnect reconstructs; it never restarts an operation automatically.

The browser must not invent progress, tool state, evidence or findings.

See `docs/product/LIVE_EXECUTION_ACTIVITY.md`.

---

## 12. Source Hunt boundary

Source processing is governed independently from website target authorization.

Source Hunt requires:

- operator-approved repository root;
- exact revision/snapshot identity;
- file/byte limits;
- exact permitted path semantics;
- remote processing approval;
- customer-data/retention attestations;
- password step-up where required;
- source path/hash/line verification.

Model output cannot expand file scope, execute repository tools through the provider path, verify a finding, apply a patch, merge or publish.

Permitted-path UI must match actual snapshot/remote-processing enforcement.

---

## 13. APK/mobile boundary

Uploading an APK does not execute it.

Static analysis is bounded to immutable validated artifacts and approved tools.

Dynamic analysis requires a separately governed disposable runtime/worker capability.

ADB/Frida/MobSF/emulator availability must remain truthful and cannot be inferred from upload success.

---

## 14. Data/redaction boundary

Raw sensitive values must not cross into logs, model prompts, persistence, exports or user-visible errors unless an explicit secure contract requires and protects them.

Protected examples include:

- passwords;
- API keys/tokens;
- authorization headers;
- cookies/session IDs;
- private keys;
- embedded URL credentials;
- unnecessary PII;
- raw authorization evidence;
- unrestricted raw response bodies.

Redact before crossing a trust/persistence boundary.

---

## 15. AI/provider boundary

Models are advisory.

They cannot:

- authorize targets or source;
- expand scope;
- approve plans;
- execute scanner/shell tools through advisory routing;
- verify findings;
- set authoritative severity;
- modify human review labels;
- merge/release/publish.

Provider/data-class routing is owned by `docs/product/AI_ROUTING.md`.

Hidden chain-of-thought/private reasoning is never rendered.

---

## 16. Evidence / finding boundary

Tool output is evidence/candidate input.

The stronger state sequence remains:

```text
tool receipt
→ evidence
→ candidate observation/finding
→ deterministic verification / abstention
→ governed human review where required
→ remediation/retest/report/release
```

A scanner severity or model confidence value never becomes final vulnerability authority by itself.

---

## 17. ML boundary

Model outputs remain advisory and provenance-bound.

They cannot:

- mutate review labels;
- resolve review disputes;
- approve findings;
- replace external holdout evidence;
- bypass dataset/release eligibility;
- claim calibrated real-world confidence without calibration evidence;
- activate themselves outside model-registry authority.

Synthetic benchmarks remain pipeline/research evidence, not real-world product performance.

---

## 18. Governance/review boundary

Campaigns/releases do not create target authorization.

They narrow/consume already authorised evidence under their own integrity/identity rules.

Governed review requires the configured identity, assignment, role, independence/conflict and attestation checks.

Review/publication authority remains separate from scanner/model authority.

---

## 19. Engineering/orchestration boundary

Repository-change approval cannot authorize a target, verify a vulnerability or alter finding/review authority.

Automated loops execute only bounded allowed actions and deterministic verifiers.

No loop/specification may inject arbitrary shell commands or weaken protected security/evaluator resources.

---

## 20. Autoresearch boundary

Research candidates remain isolated from protected evaluator/security/governance resources.

No objective-score improvement compensates for:

- authorization/scope change;
- protected-file modification;
- data leakage;
- evaluator tampering;
- regression/safety failure.

---

## 21. Unattended operations boundary

Unattended work requires explicit immutable expiring permission manifests and runtime-enforced tool/path/network/connector/secret/destructive permissions.

A prompt/model/source document never becomes unattended execution permission.

Revocation/expiry/critical security blockers halt the affected workflow.

---

## 22. Residual limitations

Application-level containment is not an operating-system/kernel sandbox.

Additional environment trust includes, depending on deployment:

- host OS integrity;
- CA/certificate store integrity;
- privileged network interception;
- container/VM isolation;
- DNS infrastructure;
- proxy/reverse-proxy configuration;
- scanner binary/template supply chain.

Production acceptance must evaluate those separately.

---

## 23. Prohibited boundary changes

Do not:

- allow arbitrary unauthorised public targets;
- treat `allow_public=True` as an authorization mechanism;
- delete private-worker checks to fake public support;
- permit public-to-private/metadata pivots;
- accept raw URLs directly into unrestricted transport/tool commands;
- enable uncontrolled redirects;
- allow caller-controlled Host/TLS identity manipulation;
- disable body/request/rate/timeout limits for convenience;
- persist raw secrets/bodies;
- weaken redaction;
- let the browser invent worker/task state;
- expose hidden model reasoning;
- make model decisions authoritative;
- weaken dataset/holdout/review integrity to improve metrics.

---

## 24. Current status note

Architecture permits authorised public targets, but current end-to-end public scanner runtime remains incomplete until the public worker/transport acceptance is implemented.

`docs/intelligence/CURRENT_STATE.md` owns that status.
