# ADR-0016: Bounded Security Agent Runtime Foundation

## Status

Accepted for local foundation work.

## Decision

VulnHunter will use a controller-owned agent loop. Planner output is treated as
untrusted structured input. Only explicitly registered tools may execute, and every
tool call must pass deterministic runtime and task-manifest policy checks.

State and evidence are persisted in SQLite. Runtime events form a SHA-256 chain.
Human-approval actions pause before execution and can resume only with a recorded
approval reference. Two materially identical retryable failures stop the task by
default.

## Consequences

The project gains real bounded execution and resume behavior without granting an LLM
unrestricted terminal, network, connector, secret, Git, or deployment access.
Production model and security-tool adapters remain deferred to Milestone 21.5B.
