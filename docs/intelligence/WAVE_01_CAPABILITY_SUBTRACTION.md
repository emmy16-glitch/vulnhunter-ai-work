# Wave 1 Agentic Runtime Capability Subtraction

## Decision

Wave 1 extends the existing `agent`, `taskgraph`, `agent_activity`,
`orchestration`, `roles`, and `unattended` packages. It must not introduce a
parallel orchestrator or uncontrolled worker swarm.

## Current capability

| Required capability | Evidence | Status | Exact remaining work |
| --- | --- | --- | --- |
| Typed objective | `AgentTask.objective`; bounded orchestration specification | PARTIAL | Replace the unconstrained objective string at the trust boundary with immutable typed objective context while retaining compatibility. |
| Planning | `Planner`, `SequencePlanner`, `ModelPlanner`, strict `AgentProposal` | COMPLETE | Preserve schema validation and fail-closed planner errors. |
| Task decomposition | `TaskGraph` and dependency nodes | PARTIAL | Add governed decomposition that binds each node to the parent objective and manifest without granting authority. |
| Dependency-aware graph | `taskgraph` acyclic validation and ready-node calculation | PARTIAL | Add graph revision/CAS, transition validation, transactional integrity, and immutable bindings. |
| Bounded specialist workers | role/skill IDs on graph nodes | MISSING | Add orchestrator-owned worker claims, expiring leases, heartbeat, and maximum concurrency. |
| Tool selection | immutable `ToolSpec`, registry, planner-visible specs | COMPLETE | Preserve exact registered identity and no arbitrary shell path. |
| Preconditions | agent policy, manifest expiry, risk/tool/action checks | PARTIAL | Bind graph dependencies, runtime deadline, actor identity, approval consumption, and immediate pre-execution validation. |
| Approval interruption | controller pause plus stored pending proposal | PARTIAL | Bind to authoritative Approval Centre consumption rather than a caller-provided reference string. |
| Cancellation | controller terminal cancellation; scanner/unattended controls | PARTIAL | Add cooperative in-flight cancellation and graph/run propagation. |
| Pause and resume | approval/budget pause states | PARTIAL | Add explicit operator pause and guarded resume; do not classify planner pause as a budget pause. |
| Retries | deterministic evaluator, retryable errors, identical-failure limit | PARTIAL | Add explicit total/per-node retry ceilings and backoff metadata without hidden retry loops. |
| Timeout handling | unattended manifest runtime limit only | MISSING | Add immutable agent deadline and fail-closed checks before planning and tool execution. |
| Deterministic transitions | controller-owned state changes | PARTIAL | Enforce an explicit transition table in the model/store boundary. |
| Checkpoint recovery | SQLite task snapshots, revisions, hash-chained events | PARTIAL | Validate snapshot/event agreement and resume only from permitted non-terminal checkpoints. |
| Evidence correlation | tool evidence hash, audit reference, activity stream | PARTIAL | Bind results, verification, graph node, approval, and objective in one typed correlation record. |
| Result verification | deterministic `ResultEvaluator`; orchestration verifiers | PARTIAL | Require capability-specific verifier evidence before successful task completion. |
| Truthful failures | normalized tool errors and explicit blocked/failed states | COMPLETE | Preserve; do not convert unavailable integration or abstention into success. |
| Resource budgets | steps, calls, iterations, repeated failures; unattended runtime | PARTIAL | Add runtime, output, token/cost where applicable, concurrency, and per-worker budgets. |
| Activity/event stream | typed redacted activity service and hash-chained agent events | COMPLETE | Add graph/worker/lease events without private reasoning. |
| Primary orchestrator | controller plus durable graph/roles foundations | PARTIAL | Integrate bounded specialists under one orchestrator; no peer authority or swarm behavior. |
| Safe UI reasoning boundary | concise structured events exist | PARTIAL | Enforce summaries/status/evidence only; never surface hidden chain-of-thought. |
| Agentic-threat containment | preventative policy/injection foundations only | MISSING | Implement as Wave 1B after the base runtime is stable. |

## Dependency order

1. Enforce agent lifecycle transitions and immutable runtime deadline.
2. Add explicit operator pause/resume and cooperative cancellation checkpoints.
3. Add authoritative Approval Centre binding at the execution boundary.
4. Harden the task graph with atomic revision/CAS and immutable node bindings.
5. Add bounded worker claims, leases, heartbeat, expiry recovery, and concurrency.
6. Correlate objective, graph node, approval, tool result, verifier evidence, and
   activity events.
7. Add Wave 1B deterministic suspicious-sequence detection and containment.

## First implementation task

Add a model-owned transition table and immutable task deadline to the existing
agent runtime. Reject illegal transitions and expired work before planner or
tool invocation. Preserve the current public controller API where possible.

Completion requires focused success, illegal-transition, expired-before-plan,
expired-before-tool, terminal-immutability, and resumable-budget tests plus
changed-file Ruff, formatting, compile, and diff checks.

Status: `COMPLETE` on `2026-07-13`.

- Added explicit `TIMED_OUT` terminal truth state.
- Bound each task deadline to immutable creation time plus the permission
  manifest's runtime budget.
- Enforced legal transitions, terminal immutability, immutable identity and
  configuration, monotonic counters/timestamps, and exact revision advance.
- Revalidated every store update against the current SQLite snapshot inside
  the update transaction.
- Added UTC clock injection and expiry checks before planning, tool execution,
  and approval resume.
- Preserved budget-pause checkpoint recovery.
- Focused coverage: `46` unique affected tests; latest directly affected run
  `20 passed in 31.11s` (`64.11s` elapsed).
- Changed-file Ruff, formatting, scoped compileall, and diff checks passed.

Next task: explicit operator pause/resume and cooperative cancellation
checkpoints using the same transition and audit boundary.

## Second implementation task

Status: `COMPLETE` on `2026-07-13`.

- Added a distinct `PAUSED_OPERATOR` state; planner pause no longer masquerades
  as budget exhaustion.
- Added guarded operator `pause` and `resume` APIs with audit and safe activity
  events.
- Direct `run()` calls cannot bypass an operator pause.
- Added a post-planning persisted-revision checkpoint so a concurrent operator
  pause or cancellation wins before policy and tool execution.
- Focused gate: `39 passed in 46.32s` (`84.35s` elapsed); changed-file Ruff,
  formatting, and scoped compileall passed.
- Limitation: an already-running Python tool handler is not preempted. Later
  restricted adapters must implement their own bounded cancellation token or
  subprocess termination contract and must not claim this checkpoint kills
  arbitrary code.

Next task: bind approval interruption to authoritative Approval Centre
consumption rather than accepting a reference string as execution authority.

## Third implementation task

Status: `COMPLETE` on `2026-07-13`.

- Added immutable agent approval bindings for the exact action manifest,
  canonical execution plan, request, execution, and consuming actor.
- Injected the concrete `ApprovalService` at the composition boundary.
- Removed caller approval references from `approve_and_resume`; it now resumes
  only after atomic Approval Centre consumption succeeds.
- The policy accepts only the consumed approval hash written by this task and
  requires exact approved action/tool/operation identity.
- Missing integration, forged references, mismatched bindings, stale/consumed
  approvals, and requester consumption fail closed through existing Approval
  Centre contracts.
- A legacy test that expected any string reference to authorize was changed to
  assert denial; no security test was weakened.
- Focused integration: `49 passed in 56.42s` (`91.18s` elapsed). The first
  post-hardening run reported `36 passed, 1 failed` because of the legacy
  expectation; the corrected policy subset passed `13 in 13.40s` (`53.34s`).

Next task: harden the task graph with atomic revision/CAS and immutable node
bindings before adding worker leases.

## Restrictions

- Models, planners, roles, workers, and tools cannot authorize, approve, expand
  scope, grant permission, or publish a verified claim.
- Worker declarations never create runtime permission.
- No arbitrary shell command, external scan, connector, provider, model,
  dependency, or service is activated by Wave 1.
- External content and model output remain untrusted data.
