# Governed Nuclei Integration

**Status:** BINDING SCANNER INTEGRATION CONTRACT  
**Public-target requirements:** `docs/product/PUBLIC_TARGET_ASSESSMENT.md`  
**Live activity:** `docs/product/LIVE_EXECUTION_ACTIVITY.md`

VulnHunter treats ProjectDiscovery Nuclei as an external evidence producer. Nuclei is not an authorization authority, a template match is not a confirmed finding, and browser/model input never becomes unrestricted Nuclei command-line authority.

---

## 1. Current active execution path

The currently implemented/accepted worker path is a controlled **private-target passive** path:

```text
exact private-target authorization
→ immutable passive plan
→ exact human decision bound to plan digest
→ signed expiring worker job
→ isolated local/restricted remote worker
→ pinned reviewed Nuclei engine/template set
→ bounded redacted evidence
→ candidate observations
→ deterministic verification
→ human review / governed result
```

The browser cannot install Nuclei, enable worker policy, create signing keys, select arbitrary templates, expand scope or supply raw command arguments.

---

## 2. Public-target product direction

Authorised public-target assessment is a supported product requirement.

**Current status:** public-host Nuclei execution is not yet complete because the current passive worker is private-target-only.

Public support must not be achieved by weakening the private pilot.

The target public path is:

```text
exact authorised public hostname
→ exact public target authorization
→ public-target transport preflight
→ immutable passive plan
→ exact confirmation/approval
→ signed job for a public-capable worker
→ connection-time contained public hostname execution
→ bounded evidence/activity
→ deterministic verification
→ human review
```

See `PUBLIC_TARGET_ASSESSMENT.md` for the mandatory transport/authorization gates.

---

## 3. Target-class capability

Worker policy must explicitly declare which target classes it supports.

Conceptually:

```text
private-only worker   → accepts private, rejects public
public-capable worker → accepts explicitly authorised public under public transport contract
```

The browser cannot change this capability.

A generic `enabled=true` is not sufficient public-target authority.

---

## 4. Current core controls

The governed Nuclei path preserves:

- exact authorization identity;
- exact target/protocol/port/path scope;
- frozen/approved address information;
- immutable plan digest;
- reviewed template manifest and content digests;
- profile/risk-level checks;
- fixed shell-free command construction;
- rate/concurrency limits;
- timeout/cancellation;
- bounded stdout/stderr/evidence;
- no automatic updates;
- no public OAST;
- no cloud upload;
- no raw command arguments;
- signed worker jobs;
- evidence/provenance linkage;
- deterministic downstream verification.

These controls must remain in force for public execution unless a separately reviewed contract explicitly changes one.

---

## 5. Public transport requirements

A public-capable Nuclei execution path must prove:

1. exact public hostname authorization;
2. connection-time DNS/address revalidation;
3. no mixed public/private resolution;
4. no localhost/loopback/link-local/metadata target;
5. no public-to-private/metadata rebinding;
6. approved-address pinning or equivalent containment;
7. original hostname preserved for HTTP Host, TLS SNI and certificate validation;
8. every redirect independently revalidated;
9. scanner-internal DNS behavior cannot silently bypass the approved address policy;
10. evidence records retain original target identity plus approved connection provenance.

If the scanner cannot provide those properties directly, use a reviewed transport boundary/proxy/dialer design rather than deleting validation.

---

## 6. Profiles

The first public target profile is **passive**.

Recommended default execution limits remain:

```text
rate limit   1
concurrency  1
retries      0
```

`standard`, `intrusive`, authenticated, active-validation or destructive classes require separate explicit authorization and product contracts. They do not become available merely because public passive execution exists.

---

## 7. Template trust

Only templates present in the reviewed content-addressed manifest may execute.

The runtime must verify:

- exact template ID;
- enabled state;
- risk class;
- required approval level;
- reviewed identity/time;
- template release;
- file existence/path containment;
- content digest.

A UI/model cannot request an unreviewed template by name and cause execution.

---

## 8. Plan identity

A Nuclei plan binds, at minimum:

- authorization ID;
- exact target(s);
- exact profile;
- exact template-manifest fingerprints;
- output directory;
- rate/concurrency;
- expiry;
- isolation requirement where applicable;
- plan digest.

A user decision must reference the exact digest. If relevant plan state changes, the previous decision does not authorize the new plan.

---

## 9. Worker job identity

The manager creates a signed worker job only after the exact plan has the required decision.

Worker validation must re-check:

- signed job integrity/expiry;
- authorization identity/current validity;
- approval identity/digest;
- worker target-class capability;
- target scope/address policy;
- template manifest;
- compatibility pins;
- execution limits;
- output path;
- cancellation state.

---

## 10. Live activity

Nuclei execution should persist activity such as:

```text
worker_claimed
nuclei_started
template_set_validated
tool_progress / bounded current activity
tool_completed or tool_failed
evidence_recorded
evaluation_started
evaluation_completed
```

The conversation/task workspace renders these persisted events.

Do not fake per-template progress if Nuclei/worker does not emit a trustworthy counter.

See `LIVE_EXECUTION_ACTIVITY.md`.

---

## 11. Evidence semantics

Nuclei output is an observation source.

Each retained evidence/candidate should preserve:

- assessment/run ID;
- authorization ID;
- approval/plan digest;
- original target identity;
- tool/adapter/version;
- template identity/digest where available;
- execution ID;
- timestamps;
- bounded redacted evidence/provenance.

A template match alone is not a confirmed vulnerability.

---

## 12. Cancellation, timeout and recovery

Cancellation/timeouts must be checked at supported worker checkpoints.

The task remains one durable assessment across:

- queue;
- running;
- cancellation request;
- cancelled;
- failure;
- recovery;
- completion.

Browser refresh/reconnect never restarts the scanner.

Partial evidence already persisted remains visible according to the evidence contract.

---

## 13. Acceptance for public Nuclei execution

Before public execution can be marked implemented, verify at least:

- authorized public hostname succeeds;
- wrong port/path/profile fails;
- missing/expired/revoked authorization fails;
- private-only worker rejects public target;
- public-capable worker rejects unauthorized public target;
- mixed public/private DNS fails;
- DNS rebinding to private/metadata fails at connection time;
- redirect escape fails;
- Host/SNI/certificate identity remains original hostname;
- template/rate/concurrency limits remain immutable from browser input;
- signed job/plan digest tampering fails;
- cancellation/timeout state is persisted;
- live activity/evidence remain assessment-scoped across reconnect.

---

## 14. Final rule

Nuclei is a bounded tool inside VulnHunter's authorization/evidence system.

Do not trade authorization or network containment for scanner convenience. If public-host execution requires a new transport capability, build and verify that capability explicitly.
