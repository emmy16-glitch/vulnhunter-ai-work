# Live Bounded-Agent Activity Timeline

## Purpose

The activity timeline is a human-readable operational view of real bounded-agent
transitions. It is not a chain-of-thought viewer and is not the authoritative
audit trail.

The authoritative flow is:

```text
bounded runtime -> structured event -> append-only store -> read model -> UI
```

The interface must never invent progress, infer approval, or treat evidence text
as instructions.

## Included foundation

- strict immutable activity-event models;
- append-only per-run JSONL storage;
- contiguous sequences and SHA-256 hash chaining;
- redaction of credential-like and secret values;
- omission of hidden-reasoning fields;
- safe framework-neutral endpoint read models;
- escaped server-rendered HTML fragment;
- responsive CSS and polling JavaScript;
- read-only inspection and integrity CLI;
- focused tests.

## Integration contract

The Milestone 24 application layer should create one `AgentActivityService` using
a repository-approved storage path. Real controller, policy, approval, tool, and
evaluator transitions call `record` only after the transition actually occurs.

The product interface exposes a same-origin read endpoint that returns
`snapshot_to_public_dict(service.feed(...))`. The page renders
`render_activity_timeline(...)` and serves the supplied CSS and JavaScript assets.

The UI may request a stop through the existing governed controller. Recording a
`stop_requested` event does not itself kill a process or bypass policy.

## Safety invariants

- no hidden chain-of-thought, prompts, or private reasoning;
- no passwords, tokens, cookies, credentials, or private keys;
- no raw sensitive evidence or unrestricted command output;
- no fabricated progress percentages;
- no client-side authorization decisions;
- no direct UI mutation of the event store;
- no automatic scanning, approval, adjudication, release, or model training;
- all evidence-derived text remains inert untrusted data.

## Read-only CLI

```bash
python -m vulnhunter.agent_activity verify \
  --root /path/to/activity-store \
  --run-id run-example

python -m vulnhunter.agent_activity inspect \
  --root /path/to/activity-store \
  --run-id run-example \
  --format json
```

## Remaining adapter work

This isolated foundation intentionally does not guess the in-progress Milestone 24
route, template, or application-service names. After Milestone 24 is committed, a
small reviewed adapter must connect its real run detail page and runtime transitions
to this package. That adapter must reuse Milestone 24 authorization, identity,
policy, and audit boundaries.
