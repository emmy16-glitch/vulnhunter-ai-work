# VulnHunter Analysis Activity Trace

The conversation workspace exposes an **Analysis Activity / safe reasoning trace** as a presentation of genuine persisted operational events. It is not a model scratchpad and does not expose hidden chain-of-thought, provider-private reasoning, internal tokens, raw stdout, credentials, or unpublished evidence.

## Authority and lifecycle

Django and the existing hash-chained `AgentActivityService` remain authoritative. The activity tree is a pure projection over events that already passed the activity redaction boundary and were persisted for the assessment task. If a repository inspection, tool call, evidence-correlation step, candidate-validation step, blocker, or failure was not recorded by a backend operation, the tree does not invent a row for it.

Each projected node has a stable `activity_id`, an optional `parent_activity_id`, a concise label and summary, and one of `queued`, `running`, `completed`, `blocked`, or `failed`. Parent stages are derived from persisted child transitions. Earlier `started` events do not keep a stage running after a later persisted completion transition. Failed and blocked transitions remain visible and dominant so terminal state is truthful.

The current stage groups are authorization and scope, repository and file inspection, planning, tool execution, evidence correlation and candidate validation, and completion or blockers. The repository-inspection stage is emitted only around the existing scanner compatibility-manifest verification call during governed approval. Existing tool and evaluation events remain the source for tool and validation stages.

## Realtime contract

For production ASGI deployments, the conversation activity panel obtains a short-lived assessment-bound ticket through `POST /api/v1/realtime/ticket/` and subscribes to:

```text
/ws/api/v1/assessments/{assessment_id}/events/
```

The first client message contains the ticket and the last confirmed `after_sequence`. The consumer returns a persisted snapshot with `events`, `last_sequence`, terminal state, and `activity_tree`. It then checks the durable store for new sequences and emits only when the cursor advances or the task becomes terminal. Reconnect obtains a fresh ticket and starts from the last confirmed cursor, so provider failover or a dropped socket does not reset the task timeline.

When the local debug preview is served by Django’s WSGI `runserver`, `VULNHUNTER_REALTIME_WEBSOCKET_ENABLED` defaults to false. The activity panel then relies on the existing persisted SSE conversation stream and does not attempt a failing WebSocket handshake. Production ASGI deployments should leave the setting enabled and provide the required Redis channel layer.

## Provider failover continuity

Groq, Gemini, and Ollama are internal advisory-provider routing details. The activity identity is the assessment/task identifier and never contains a provider identity. Provider failover therefore does not create a new activity stream, clear persisted nodes, or expose provider switching in the panel. The final assistant answer is stored and rendered as a normal conversation message below or alongside the activity surface; activity answers “what VulnHunter is doing,” while the final message answers “what VulnHunter concluded.”

## Client safety rules

The browser renders values through text nodes, not HTML interpolation. It may display safe tool IDs, event summaries, statuses, timestamps, sequence numbers, and governed references that the backend has already authorized. It cannot authorize targets, activate workers, construct commands, verify findings, or change severity. APK upload and dynamic analysis remain separate governed states, and a missing runtime or approval remains visibly blocked rather than presented as successful execution.
