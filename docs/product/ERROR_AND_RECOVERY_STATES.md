# Error and Recovery States

Errors and recovery are part of the conversation/task flow, not generic toasts and not separate dashboard state.

Every terminal or blocked error state must show, from persisted backend truth:

- what operation/stage stopped;
- a safe user-facing reason category;
- whether partial work/evidence was preserved;
- the relevant workspace/assessment/task/error reference;
- completed stages that remain valid;
- whether the system is automatically recovering;
- whether retry is supported and what retry actually restarts;
- whether authorization, approval, re-authentication or operator configuration is required;
- only the backend-supported next actions.

## Recoverable interruption

When a worker lease/session is recoverable, the same task surface should update in place with a calm state such as:

```text
Worker interrupted — recovering task
Persisted state preserved
Restoring execution context…
```

Refresh/reconnect must not convert this into a new task.

## Terminal failure

When automatic recovery is not possible, preserve the completed timeline and show a clear terminal card. Do not erase the conversation or imply that prior evidence disappeared.

## Cancellation

Cancellation is distinct from failure. Preserve the completed timeline and record the real cancellation state/actor/timestamp when available. Do not describe a cancelled task as failed.

## Prohibited output

Internal stack traces, raw secrets, unrestricted evidence and sensitive local paths must not appear in ordinary browser messages. Redacted technical diagnostics belong in permissioned activity/audit/log views.

Visual treatment must follow `docs/design/VULNHUNTER_UI_CONTRACT.md`.
