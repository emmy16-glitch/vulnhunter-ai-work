# Error and Recovery States

Errors are part of the product flow, not generic toast messages. Every error state
must show:

- what operation stopped;
- whether any partial evidence was preserved;
- the relevant authorization, scan, campaign, or release identifier;
- a safe user-facing explanation;
- the approved recovery action;
- whether human approval is required before retrying.

Internal stack traces, raw secrets, unrestricted evidence, and sensitive local paths
must not appear in browser messages. Technical diagnostics belong in permissioned
audit views and local logs.
