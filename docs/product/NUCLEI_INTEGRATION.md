# Governed Nuclei Integration

The governed assessment UI connection is documented in
[`MILESTONE_30_ASSESSMENT_INTEGRATION.md`](../intelligence/MILESTONE_30_ASSESSMENT_INTEGRATION.md).
That connection creates and approves plans only; it does not activate execution.

VulnHunter treats ProjectDiscovery Nuclei as an external scanner, not as an
authorization authority or final vulnerability judge.

## Trust boundary

```text
Authorized target and exact scope
        ↓
VulnHunter action policy and approval centre
        ↓
Fixed Nuclei profile and resource limits
        ↓
Redacted JSONL evidence
        ↓
VulnHunter candidate finding normalization
        ↓
Independent verification and human confirmation
```

Nuclei matches remain `candidate` observations. They do not become
machine-verified, human-confirmed, reportable, or published findings merely
because a template matched.

## Implemented baseline

- fixed shell-free command construction;
- no raw model-supplied CLI arguments;
- JSONL evidence with selected key redaction;
- signed-template enforcement;
- automatic update checks disabled during governed execution;
- public Interactsh/OAST disabled;
- cloud and dashboard upload unavailable;
- private/local network access blocked by default;
- low-resource limits suitable for the two-core VulnHunter VM;
- passive, standard, intrusive, and retest policy profiles;
- exact filters required outside the passive profile;
- intrusive work requires explicit approval and an isolated runtime;
- code, file, self-contained, AI-prompt, DAST-server, Uncover, and local-file
  capabilities blocked from the governed wrapper;
- Nuclei-specific JSONL normalization that never copies raw request/response
  bodies into normalized finding metadata.

## Milestone 29 activation controls

- immutable, hash-audited engagement authorization records;
- exact normalized URL, port, protocol and current-resolution checks;
- mandatory redirect revalidation and fail-closed DNS rebinding protection;
- unconditional localhost, loopback, link-local and metadata rejection;
- exact reviewed template manifests with release, risk, approval and digest
  binding;
- immutable expiring command plans with no argv or shell command field;
- expiring human approval bound to the exact command-plan digest;
- explicit intrusive approval plus isolation requirement;
- approved evidence-root validation and secret-leakage verification;
- cancellation, monotonic timeout and process-group termination interfaces.

These controls end in `APPROVED_EXECUTION_DISABLED`. They are not connected to
the external-tool executor and cannot launch Nuclei.

## Operational pins

- Engine candidate: `v3.11.0`
- Template release candidate: `v10.4.5`

The pins are activation prerequisites, not automatic downloads. The readiness
script reports a mismatch but never installs or updates anything.

## Remaining implementation gates

1. Download verification with release asset SHA-256 and provenance records.
2. Populate the currently empty reviewed template trust registry through a
   separately reviewed change.
3. A private template signing key ceremony and certificate distribution.
4. A self-hosted Interactsh deployment and explicit OAST approval workflow.
5. An isolated unprivileged runtime for headless and JavaScript templates.
6. Persist and authenticate profile-specific engagement authorizations and
   approvals; the immutable in-memory contracts and ceilings now exist.
7. Authenticated scan secret injection without secrets appearing in argv,
   persisted plans, logs, or model-visible state.
8. Request/response artifact-level redaction verification before export.
9. Nuclei version and template-version checks at execution time, not only
   readiness time.
10. Web UI, queue, cancellation, progress, and finding-verification workflows.
11. Upgrade regression testing before changing either engine or template pin.
12. A local lab acceptance suite proving no scope escape, upload, public OAST,
    unsafe template execution, or secret persistence.
