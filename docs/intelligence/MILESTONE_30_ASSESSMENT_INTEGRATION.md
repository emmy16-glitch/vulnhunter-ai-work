# Milestone 30 — End-to-end assessment integration

Milestone 30 connects the existing Django assessment workspace to the existing
authorization, agent-state, approval, activity, evidence, finding, and Nuclei
governance components. It is a planning and review milestone. It does not
activate Nuclei.

## Authoritative flow

1. An authenticated actor opens Assessments and requests the active
   authorization list.
2. The server returns only unexpired records owned by that actor and carrying a
   valid `nuclei_activation_bound` ledger event.
3. The browser presents selects for authorization, exact target, protocol,
   port, and profile. It provides no free-text target field.
4. The server reloads the authorization and immutable Milestone 29 engagement
   record, then revalidates every submitted value.
5. Scope validation uses the exact URL and the authorization's frozen address
   set. The web composition root performs no external DNS lookup. Future
   connection-time and redirect checks must inject a resolver and use the same
   Milestone 29 scope validator.
6. The server reads a local readiness report. It never invokes the Nuclei
   executable from a web request. Missing, malformed, stale, or pin-mismatched
   readiness blocks the assessment.
7. The reviewed template manifest is closed by default. Missing, disabled,
   unreviewed, modified, wrong-release, or wrong-risk templates fail closed.
8. A structured immutable `NucleiCommandPlan` is stored in the existing
   `AgentStore`. It contains no command string or arbitrary arguments.
9. The existing `ApprovalStore` records a one-time request whose action digest
   is the exact command-plan digest. Browser-modified or expired digests are
   rejected before a decision is written.
10. Approval updates the existing agent task and append-only activity stream.
    An approval moves the workflow to `execution_blocked`, because global
    execution remains disabled. Denial moves it to `denied`/cancelled.
11. SSE publishes real persisted event IDs, state, readiness, approval, and
    blocking information. The browser deduplicates IDs and never advances state
    with a timer.

## State projection

The authoritative persisted task status remains the existing `TaskStatus`.
Assessment-specific state is an immutable-update projection in task memory:

```text
draft
  -> authorization_required
  -> scope_validated
  -> readiness_checked
  -> plan_generated
  -> awaiting_approval
  -> execution_blocked
```

Exceptional projections are `readiness_blocked`, `approval_blocked`, `denied`,
`cancelled`, and `timed_out`. Each important transition creates a sanitized,
hash-chained agent audit event with the assessment ID, actor, timestamp,
previous and new state, reason, authorization reference, plan digest when one
exists, and correlation ID.

## UI and SSE behavior

- The empty state is driven by the real run queryset.
- The assessment modal loads only the actor's active authorizations from an
  authenticated no-store endpoint.
- Stage, approval, completion, and tool states come from backend data.
- The right panel distinguishes readiness from execution permission.
- The approval card appears only for a real pending request and submits with
  POST and CSRF protection.
- Activity uses sanitized text and stable event IDs. Replayed SSE snapshots do
  not create duplicate entries.
- Artifacts and candidate findings come only from persisted evidence records.
  Artifact paths and contents are revalidated before display.
- Attack-path nodes appear only when persisted evidence supplies them.

## Evidence and finding trust

Evidence must remain below the configured evidence root without traversal or
symbolic-link escape. Artifacts are bounded and must pass Milestone 29 redaction
verification. Authorization values, cookies, bearer tokens, API keys, proxy
credentials, complete request bodies, and complete raw HTTP exchanges are not
accepted as evidence.

A Nuclei match remains a candidate observation. The intended trust sequence is:

```text
NUCLEI_MATCH
  -> CANDIDATE
  -> MACHINE_VERIFIED
  -> HUMAN_CONFIRMED or REJECTED
  -> PUBLISHED
```

This integration does not automatically advance a candidate, alter a human
label, or publish a finding.

## Cancellation and timeout

The existing controller cancellation and immutable deadline interfaces update
the assessment projection to `cancelled` and `timed_out`. Milestone 29's
thread-safe cancellation checkpoint and process-group termination protocol
remain the required contract for any future isolated runner. No external worker
is connected in this milestone.

## Remaining activation blockers

All of the following remain blockers:

- `execution_enabled` is `false` in runtime and Nuclei profile configuration;
- the reviewed template manifest is empty in the repository;
- no external worker or subprocess launcher is connected;
- no isolated intrusive runtime is approved;
- no live connection-time DNS or redirect execution path is connected;
- no target-specific command plan has been consumed for execution;
- no Nuclei binary, template collection, credentials, or local readiness
  evidence is committed.

> Correction (2026-07-22): the engine version recorded by this historical
> milestone was based on an invalid release assumption. Current operational
> policy pins official Nuclei `v3.8.0`; the following old value remains only as
> historical evidence.

Readiness means only that separately generated local version evidence matches
engine `v3.11.0` and template release `v10.4.5`. It never grants execution
permission. No external target scanning, Interactsh, ProjectDiscovery Cloud,
template download, or automatic update is enabled.
