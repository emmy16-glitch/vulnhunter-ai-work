# Bounded Security Agent Runtime

## Purpose

Milestone 21.5A adds the real execution-loop foundation required for a VulnHunter
security agent. The controller can create a task, request structured planner actions,
check deterministic policy, execute registered local tools, evaluate results, retry
bounded failures, pause for human approval, resume, persist state, and verify an
immutable audit chain.

## Runtime flow

```text
objective
→ structured planner proposal
→ deterministic policy decision
→ explicitly registered tool execution
→ deterministic result evaluation
→ continue, retry, pause, block, fail, or complete
→ hash-chained evidence and final report
```

## Implemented capabilities

- resumable SQLite task state;
- optimistic revision checks;
- hash-chained audit events;
- strict Pydantic planner-output validation;
- deterministic and model-gateway planner interfaces;
- explicit tool declarations and callable handlers;
- task-level action, tool, risk, step, call, and retry budgets;
- human-approval pause and resume;
- stop after repeated materially identical failures;
- deterministic execution reports;
- a local no-network demonstration command;
- read-only operational product summaries for bounded runs through
  `python -m vulnhunter.product runs` and `python -m vulnhunter.product run <id>`.

## Deliberately absent

This milestone does not connect a real LLM provider or the production scanner,
governance, dataset, model-training, connector, Git, secret, deployment, or shell
capabilities. Those integrations require separate adapters and approval after the
controlled pilot. The runtime cannot infer authority from a model proposal.

## Trust boundary

The planner is untrusted. Every requested action is validated against the runtime
configuration, task permission manifest, exact tool declaration, budgets, risk flags,
and human-approval requirements. A model cannot register tools, expand permissions,
edit the audit chain, or approve its own blocked action.

## Current product-console integration

Milestone 24 does not add a browser approval queue or operator stop form for
agent tasks because the repository still lacks an approved browser session and
CSRF boundary. The product layer currently exposes bounded runs as read-only
inspection surfaces and reports unsupported consequential controls as
unavailable rather than fabricating them.
