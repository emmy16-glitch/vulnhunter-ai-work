# Scanner Manager and Worker Architecture

**Status:** CURRENT SCANNER ARCHITECTURE  
**Public-target contract:** `docs/product/PUBLIC_TARGET_ASSESSMENT.md`  
**Nuclei contract:** `docs/product/NUCLEI_INTEGRATION.md`  
**Live activity:** `docs/product/LIVE_EXECUTION_ACTIVITY.md`

VulnHunter separates governance/plan authority from scanner execution.

---

## 1. Manager responsibilities

The Django/product manager owns or coordinates:

- authenticated operator/workspace identity;
- exact target authorization;
- private/public target classification;
- exact target origin/port/path/address policy;
- immutable assessment plan;
- plan digest/expiry;
- required confirmation/approval;
- signed worker-job creation;
- cancellation decisions;
- selected-assessment/task graph;
- evidence trust/verification/review/report state.

The manager does **not** accept arbitrary scanner arguments and does not run long-lived scanner subprocesses inside the web request process.

---

## 2. Worker responsibilities

A worker independently validates applicable:

- signed job integrity/invocation digest;
- job/plan/authorization/approval expiry;
- exact target authorization and scope;
- target class and worker target-class capability;
- protocol/port/path/address policy;
- scanner/adapter/profile;
- template manifest and content hashes;
- rate/concurrency/timeout/output limits;
- approved evidence path;
- cancellation state;
- worker-local activation policy.

The worker executes only a fixed bounded adapter contract.

It cannot:

- expand target scope;
- create authorization;
- approve its own plan;
- accept raw user shell/argv;
- change target class from browser input;
- return unrestricted secrets/process output;
- confirm a finding or publish it.

---

## 3. Current worker state

The current passive Nuclei pilot is deliberately **private-target-only**.

Its narrow properties include:

- one reviewed private target mapping;
- passive profile;
- rate limit `1`;
- concurrency `1`;
- reviewed/pinned Nuclei/templates;
- fixed arguments;
- minimal environment;
- process-group cancellation;
- bounded evidence/output;
- operating-system resource limits.

This is an implementation state, not the final product target policy.

Authorised public targets are an approved product class, but public execution remains unavailable until a separately reviewed public-capable worker/transport path is implemented.

---

## 4. Target-class worker capability

Worker capability must be explicit.

Conceptually:

```text
worker capability: private
→ accepts exactly authorised private jobs
→ rejects public jobs

worker capability: public
→ accepts exactly authorised public jobs
→ enforces public-host transport containment
```

A future worker may support both through an explicit typed capability set, but no browser field may grant that capability.

Do not replace a private-only assertion with a permissive boolean just to execute public hosts.

---

## 5. Public-capable execution boundary

Before a worker may accept a public hostname it must prove:

- exact active public-target authorization;
- public/private address classification;
- connection-time DNS/address revalidation;
- no mixed public/private resolution;
- no localhost/loopback/link-local/metadata destination;
- no public-to-private/metadata rebinding;
- approved-address pinning or equivalent containment;
- original hostname preserved for HTTP Host, TLS SNI and certificate validation;
- redirect revalidation;
- scanner-internal DNS behavior cannot escape containment;
- passive profile/rate/concurrency/template policy remains bounded;
- execution/activity/evidence remains bound to exact assessment/plan/job identities.

If Nuclei cannot provide those guarantees directly, use a reviewed transport/proxy/dialer boundary rather than deleting validation.

---

## 6. Signed spool

The manager persists one immutable signed/expiring job in an owner-controlled spool or equivalent queue boundary.

Queued/processing/completed/failed/cancellation states remain distinct.

Required properties include:

- atomic write/claim transitions;
- restrictive storage permissions;
- duplicate/replay detection;
- signature/invocation-digest verification;
- expiry;
- recovery after interruption;
- no raw provider/credential/password secret in job payloads.

---

## 7. Local isolated worker

Local mode keeps scanner execution outside the web process under a bounded unprivileged process boundary.

Worker policy controls:

- executable identity/version;
- template manifest/digests;
- target-class capability;
- target/address mapping/containment;
- process environment;
- fixed command arguments;
- output/time/resource limits;
- cancellation;
- evidence destination.

Current local passive worker remains private-only until the public programme lands.

---

## 8. Restricted remote worker

A restricted remote worker may move scanner process execution to an operator-owned host while manager-side governance remains local.

Conceptual boundary:

```text
Django manager
→ signed local job
→ local worker validation
→ dedicated restricted transport identity
→ forced/typed remote runner
→ independent remote policy validation
→ fixed scanner invocation
→ bounded structured response/evidence digest
→ local evidence/verification pipeline
```

Remote transport must not become an unrestricted SSH command channel.

The remote side independently validates executable/version/template/target/freshness/replay/limits according to its approved policy.

A public remote worker still needs the public-host containment contract; merely being remote does not make public scanning safe.

---

## 9. Shared scanner protocol

Scanner protocol/adapter identity is versioned and tool-independent.

A scanner adapter must reuse the same core controls:

- exact authorization;
- exact plan/approval;
- target-class capability;
- signed/immutable job;
- bounded execution;
- cancellation/recovery;
- redacted evidence;
- persisted activity;
- deterministic downstream verification;
- human review authority.

New scanners must not introduce a second ungoverned execution plane.

---

## 10. Control ownership

| Responsibility | Manager | Worker | Restricted remote runner |
| --- | --- | --- | --- |
| Target authorization | owns/validates | revalidates | never creates |
| Target class | resolves/persists | enforces capability | enforces local policy |
| Human plan decision | owns/persists | verifies binding | never owns |
| Plan digest | creates | verifies | binds request only |
| Tool/version/template policy | selects approved contract | verifies | verifies installed state |
| Scanner process | never in web request | local mode | remote mode |
| Cancellation | requests | enforces/checkpoints | terminates process where applicable |
| Activity events | task source + projection | emits execution events | returns bounded execution state |
| Evidence hashing | verifies/links | produces bounded artifacts | returns structured digests |
| Finding verification | deterministic product services | never | never |
| Human review/release | governed workflow | never | never |

---

## 11. Persisted live activity

The worker/task pipeline should persist meaningful events such as:

```text
job queued
worker claimed
policy/plan validated
tool started
tool progress where measurable
tool receipt recorded
evidence recorded
tool completed / failed
normalization started / completed
verification started / completed
recovering / cancelled / completed
```

The originating conversation renders the same persisted activity.

Do not fabricate per-template/progress counters that the worker cannot actually measure.

---

## 12. Queue/recovery

On worker restart, interrupted jobs recover according to persisted state and fail-closed policy.

The system must not assume an OS scanner process survived merely because a job file says `running`.

Recovery/cancellation updates the same assessment/task identity and preserves prior receipts/evidence where valid.

Browser reconnect is independent from worker recovery and never restarts a scanner.

---

## 13. Activation rule

Code readiness is not machine activation.

A deployment must provide reviewed worker policy, scanner binary/template identity, signing/transport secrets and environment-specific readiness before jobs can execute.

Browser input cannot:

- install a scanner;
- create signing keys;
- enable a worker;
- broaden target class;
- alter version/template policy;
- make a public worker available.

Current private-lab setup/runbooks remain valid for the private worker.

Public worker activation will require its own readiness/acceptance path.

---

## 14. Public-worker acceptance

Before public execution is marked implemented:

1. authorized public hostname succeeds;
2. unauthorized/wrong host/port/path/profile fails;
3. private-only worker rejects public job;
4. public-capable worker rejects missing/expired/revoked authorization;
5. mixed public/private DNS fails;
6. public-to-private/metadata rebinding fails at connection time;
7. redirect escape fails;
8. Host/SNI/certificate identity is preserved;
9. browser cannot broaden worker capability/limits;
10. activity/evidence remain assessment-scoped across reconnect;
11. cancellation/timeout/recovery are truthful;
12. signed job/plan tampering fails.

---

## 15. Status rule

`docs/intelligence/CURRENT_STATE.md` owns runtime status.

Do not infer public-worker availability from this architecture document alone.
