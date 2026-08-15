# Adaptive Web Hunter Coordinator

## Purpose

This layer consumes the sanitized Playwright Web Perception result from PR #152 and turns it into bounded, typed **suspicions** that can be routed to later independent verification.

It does not execute tests, send requests, generate exploit payloads, use credentials, bypass authorization, or confirm vulnerabilities.

```text
WebPerceptionResult
    -> integrity re-check
    -> HunterContext
    -> applicability routing
    -> independent deterministic specialists
    -> typed HunterHypothesis
    -> non-executing VerificationIntent
    -> deduplication and hard budgets
    -> integrity-linked HunterRunResult
```

## Authority boundary

Hunters are advisory only.

- They cannot create target authorization.
- They cannot create OpenSandbox command plans.
- They cannot access a network.
- They cannot submit forms.
- They cannot provide or guess credentials.
- They cannot bypass access controls.
- They cannot execute a shell or scanner.
- They cannot mark a finding confirmed.

`VerificationIntent` hard-codes those restrictions with `Literal[False]` execution/network/bypass fields and rejects extra fields such as payloads or commands.

The only hypothesis state emitted by this coordinator is `suspected`. `confirmed` deliberately does not exist in the enum. Later verification must be a separate authority with its own authorization contract and evidence rules.

## Prompt-injection boundary

Hunters receive the already-sanitized `BrowserPerceptionEvidence` and deterministic `ApplicationSurfaceGraph`; raw HTML, page text, headers, cookies, request bodies, storage values, screenshots, HARs, and traces remain unavailable.

Built-in hunter titles, observations, and rationales are fixed application strings. Target-controlled form field names are used only for local structural classification and are not copied into `HunterHypothesis` text. Evidence leaves the hunter only as SHA-256 graph node/edge references.

## Integrity binding

Before routing any specialist, the coordinator recomputes:

- the canonical browser evidence SHA-256;
- the application surface graph SHA-256;
- target/graph identity consistency.

Every hypothesis is then revalidated against the graph. The coordinator rejects:

- unknown node or edge references;
- a different graph digest;
- a fabricated semantic fingerprint;
- a fabricated hypothesis ID;
- a fabricated verification-intent ID.

The final run receives its own canonical SHA-256.

## Initial specialist set

### `authorization-object`

Looks only for concrete numeric or UUID-like identifiers in browser-observed endpoint paths and emits `object_authorization_candidate`.

It does not attempt another object ID or another identity. The future verification requirement remains an explicit, separately authorized read-only review.

### `request-integrity`

Looks at state-changing form declarations. When no recognizable request-integrity field is present in the sanitized form structure, it emits `csrf_control_candidate`.

This is intentionally low-confidence structural triage. Header-based, cookie-based, origin-based, framework, or server-side protections may exist and are not visible here.

### `file-upload`

Routes forms containing `input[type=file]` to `file_upload_validation_candidate` without uploading anything.

### `authentication`

Routes password-bearing form declarations to `authentication_control_candidate` without submitting, storing, guessing, or generating credentials.

### `api-access`

Routes browser-observed read-only API-like endpoint paths to `api_access_control_candidate` for later role/tenant/object-control review.

## Budgets and adaptive routing

A hunter runs only when its `applicable()` predicate sees relevant sanitized structure. Otherwise it records `abstained`.

The coordinator applies:

- a global maximum hypothesis count;
- a per-hunter maximum hypothesis count;
- deterministic priority ordering;
- semantic-fingerprint deduplication.

A specialist exception fails the run closed instead of silently degrading into a different hunter or model.

## What priority means

`priority_score` is triage priority only. It is **not** severity, exploitability, probability of compromise, confidence that a vulnerability exists, or permission to execute a test.

## Deliberately deferred

This foundation does not yet implement:

- an LLM hypothesis proposer;
- a network-capable verifier;
- authenticated browser sessions;
- two-identity access-control comparison;
- payload generation;
- XSS/SQLi/SSRF/injection execution;
- persistent Assessment memory;
- differential/continuous hunter runs;
- finding confirmation or severity assignment;
- automatic remediation.

Those must remain separate batches because they cross different authority and evidence boundaries.
