# Unattended Operations Control Plane

## Purpose

The control plane permits bounded unattended work only when a human-approved, time-limited permission manifest is enforced at runtime.

It does not make VulnHunter autonomous. It narrows what a scheduled or repeated process may do and preserves evidence for every decision.

## Permission manifest

Each manifest defines:

- loop ID and repository root;
- execution mode;
- available tools;
- approved read and write paths;
- approved fixed commands;
- network class and exact public-host allowlist;
- target authorization IDs for private-lab network access;
- connector allowlist;
- named secret allowlist;
- Git push, deletion, and deployment permissions;
- runtime and iteration ceilings;
- exactly two materially identical failures before blocker isolation;
- declared independent task IDs;
- creation and expiry times;
- optional protected approval for sensitive remote data.

The creator cannot approve their own manifest. Approval is bound to the exact manifest SHA-256. Any later modification invalidates the approval.

## Runtime enforcement

Prompt instructions are not treated as permission. Runtime adapters call `PermissionEnforcer` before path, command, network, connector, secret, push, delete, or deployment actions.

The included command runner accepts only fixed command IDs and executes without a shell or arbitrary arguments:

- Git status;
- Git diff check;
- Ruff lint;
- Ruff format check;
- Python compilation;
- pytest;
- strict project audit.

Command output is bounded and redacted before evidence is stored.

## Scheduling decision matrix

| Task type | Preferred mode |
|---|---|
| Supervised substantial goal | `interactive_goal` |
| Temporary repetition | `session` |
| Recurring private repository work | `local_scheduled` |
| Deterministic checks | `ci_workflow` |
| Narrow task that genuinely requires remote execution | `remote_routine` |

Remote routines remain exceptional. By default they cannot use sensitive security data, credentials, customer data, private target inventories, Git push, deletion, or deployment.

A sensitive remote exception requires explicit approval and all of these controls:

- encryption at rest;
- encryption in transit;
- isolated runtime;
- data minimization;
- a documented data class and expiry.

## Blocker isolation

A material failure fingerprint uses the task, operation, error code, redacted normalized summary, and blocker class.

After two materially identical failures:

- retrying that item stops;
- evidence is preserved;
- the item is isolated;
- another task may continue only when it was declared independent and the blocker is non-critical.

The complete workflow halts for blockers affecting:

- security invariants;
- target authorization;
- scope enforcement;
- data integrity;
- the evaluator;
- required verifiers.

## Completion

A run cannot complete until every command listed in `required_completion_commands` has produced successful, integrity-checked evidence.

Revocation or expiry immediately blocks further runtime actions while retaining history.

## Limitations

The control plane does not yet provide:

- kernel, container, or virtual-machine isolation;
- authenticated human identities;
- cryptographic signatures backed by external keys;
- a production scheduler;
- arbitrary connector executors;
- network-capable command adapters.

These omissions are intentional. The current layer establishes enforceable permissions and evidence before broader execution adapters are added.
