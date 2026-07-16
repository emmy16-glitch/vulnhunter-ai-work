# Milestone 29 — Nuclei Activation Safety Controls

## Status

`ACTIVATION_CONTROLS_IMPLEMENTED_EXECUTION_DISABLED`

Milestone 29 adds the records and deterministic validation needed to prepare a
future controlled local-lab pilot. It does not activate Nuclei, launch a
process, resolve a hostname by default, update templates, or contact any
external service.

## Control flow

```text
immutable engagement authorization
        -> exact URL, protocol and port match
        -> caller-supplied current DNS result is an exact approved set
        -> reviewed template path and SHA-256 manifest match
        -> approved evidence directory and redaction verification
        -> immutable expiring command plan (no argv or shell string)
        -> human approval bound to the exact plan digest
        -> APPROVED_EXECUTION_DISABLED
```

Every redirect must pass the same exact target and DNS checks. Localhost,
loopback, link-local and metadata endpoints are always rejected. Private
addresses require both an exact approved address and explicit private-network
approval. Empty, mixed-class, changed or out-of-scope DNS results fail closed.

## Immutable records

`EngagementAuthorization` records the authorization ID, target owner, approving
person, normalized exact target URLs, exact addresses, ports, protocols and scan
profiles, validity interval, private-network decision, mandatory prohibited
actions, and an identity-bound audit digest. The digest covers the entire
record. Models are frozen and reject extra fields.

`NucleiTemplateManifestEntry` records a stable template ID, safe relative path,
SHA-256 digest, release, risk class, required approval level, enabled state and
review identity/time. Missing, disabled, unreviewed, symlinked, escaping or
modified templates are rejected. The repository manifest starts empty, so all
templates remain denied.

`NucleiCommandPlan` contains only exact validated targets, the authorization and
profile, template-entry hashes, evidence directory, bounded rate/concurrency,
isolation requirement, expiry and plan digest. It has no executable, argv,
command string or arbitrary argument field.

`NucleiPlanApproval` references one command-plan digest and expires. Any plan
change invalidates it. Intrusive plans additionally require an explicit
intrusive decision and a named isolated runtime. A successful decision still
returns `execution_enabled=false`.

## Evidence and lifecycle controls

Evidence directories must already exist beneath the configured approved root
and cannot be symlinks. Bounded regular evidence files are checked for central
redaction patterns, sensitive structured keys and embedded URL credentials
before a digest can be accepted.

`NucleiRunControl` supplies deterministic cancellation and monotonic timeout
checkpoints. A future runner must inject a `ProcessGroupTerminator` and terminate
the complete isolated process group. Milestone 29 provides and tests this
interface but intentionally provides no process launcher or OS signal
implementation.

## Remaining activation blockers

1. The reviewed template manifest is empty; no template is enabled.
2. Nuclei installation provenance and release checksums require human review.
3. A private signing-key ceremony and trust distribution are incomplete.
4. No isolated unprivileged runtime or process-group terminator is wired.
5. No authenticated secret-injection design has been approved.
6. No self-hosted private OAST service or approval workflow exists.
7. Execution-time engine and template release verification is not wired.
8. The local-lab acceptance suite and independent security review are pending.
9. Runtime `execution_enabled`, `nuclei.enabled`, active assessment and
   validation flags remain false.

These blockers are cumulative. Passing an earlier gate does not waive a later
one, and a plan approval is not target authorization or vulnerability proof.
