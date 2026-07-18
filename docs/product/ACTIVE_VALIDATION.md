# Controlled Active Validation

Active Validation is a nested assessment workflow for safely confirming the impact of a persisted finding. It is not a command console and does not accept operator-supplied programs, shell input, public targets, production data, or unrestricted payloads.

## Product location

The workflow is opened from an assessment finding:

```text
Assessment
→ persisted finding
→ Active Validation
→ controlled simulation
→ human review
```

The Approval Centre remains the canonical approval surface. Active Validation does not add a second approval system or a separate finding record.

## Authorization and separation

A request requires:

1. a persisted assessment and finding;
2. an existing assessment authorization reference;
3. a staff user with `settings.manage`;
4. password re-authentication bound to the request;
5. a different staff user with `campaign.approve`;
6. another password re-authentication before queueing the approved plan.

The requester cannot approve the same plan. Every approval is bound to the exact plan digest.

## Scenario boundary

The built-in scenario registry contains only reviewed simulations that operate on generated data inside a disposable local workspace:

- generated-file impact observation;
- synthetic authentication detection;
- internal generated-record transfer;
- disposable service-state observation.

Each scenario declares fixed adapters, reviewed variations, expected evidence, cleanup behavior, and prohibited operations.

## Retry loop

The system ceiling is ten trials. A plan may request fewer. The signed plan fixes:

- minimum and maximum trials;
- required consistent confirmations;
- one reviewed variation for every possible trial;
- per-trial and total time limits;
- generated-data-only policy;
- no-egress network mode;
- evidence and cleanup requirements.

Before every trial, the worker restores the baseline workspace. The loop stops when the minimum trial count and required confirmations are reached, the maximum is reached, a time budget expires, cancellation is requested, or a safety check fails.

## Genuine operational activity

The workspace displays persisted backend events, including:

- plan creation and approval request;
- authorization, scope, and policy checks;
- worker queue and start state;
- snapshot restoration;
- current trial and variation;
- evidence recording and evaluation;
- cancellation, failure, or completion;
- cleanup verification.

The moving status treatment is presentation only. It never invents progress or exposes hidden model reasoning. A terminal backend event stops the animation. Reduced-motion preferences are respected.

## Evidence and result

Every trial produces a bounded JSON evidence record and SHA-256 digest. Trial provenance remains available under the assessment, while the main finding keeps one consolidated validation state. Simulation output cannot publish, release, or human-confirm a finding.

## Worker operation

One queued run can be processed with:

```bash
python manage.py vh_run_adversary_lab_worker --once
```

A reviewed deployment may run the worker continuously:

```bash
python manage.py vh_run_adversary_lab_worker --poll-seconds 2
```

Production examples keep the worker disabled, networkless, read-only, capability-dropped, and resource-limited until the operator performs a separate deployment review.
