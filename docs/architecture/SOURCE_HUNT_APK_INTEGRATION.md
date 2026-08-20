# Source Hunt APK Integration

## Scope

This document describes how a completed APK static assessment enters Mobile Source Hunt and how its persisted report becomes visible in the VulnHunter conversation workspace. It covers only the static source-backed handoff. Dynamic execution, emulator testing, runtime network access, and endpoint interaction remain separate gated capabilities.

## Preconditions

The handoff is available only when the selected chat mobile plan has a completed governed worker execution. The plan must retain the artifact identity, artifact SHA-256, job identity, signed worker policy, intelligence receipt, and exact retained JADX workspace location. A plan that is queued, running, failed, blocked, or missing its receipt is rejected with a safe error.

The request is authenticated and uses the existing `scan.read` governance permission. Optional `seed_id` or `record_id` values narrow the investigation to an exact persisted Source Hunt seed or originating APK intelligence record. Unknown selections fail closed; the service does not synthesize a seed from arbitrary browser text.

## Handoff contract

```text
POST /workspace/mobile-source-hunt/
Content-Type: multipart/form-data or application/x-www-form-urlencoded

seed_id=<optional persisted Source Hunt seed>
record_id=<optional normalized APK record>
```

The successful response contains the persisted assistant message, the updated mobile plan, the authoritative `assessment_projection`, its `task_card`, current mobile execution state, and the serialized Source Hunt report. The server saves the report and updates the session plan before returning this response.

The response is consumed by the selected-assessment store only when the assessment ID and task-card assessment ID agree. The same response is also sent to the conversation renderer as a persisted message with `metadata.source_hunt_result`.

## Chat behavior

The conversation displays a compact Source Hunt report block beside the persisted assistant response. The block contains the coverage state, seed count, graph node and edge counts, and verified-finding count. If a safe error exists, it is shown as a limitation rather than a fabricated completion state.

The chat action is server-backed. The browser button does not run Source Hunt locally, does not read source files, and does not contact APK endpoints. After the response is returned, the browser replaces the selected assessment snapshot and appends the server-created message. Repeated rendering is idempotent because persisted message keys are deduplicated.

## APK task card behavior

A completed APK task card exposes **Investigate with Source Hunt** only when the authoritative projection contains `start_source_hunt`. When a report is already persisted, the action changes to a graph refresh/view state and the task card displays the persisted node and edge counts. The button remains subject to the projection's allowed actions; no client-side state can unlock the handoff.

The action text explicitly describes the static boundary: it traces retained JADX source and normalized APK evidence, does not execute the APK, and does not contact discovered endpoints.

## Inspector behavior

The right-side APK inspector contains a Source Hunt tab. Before handoff, it explains that the selected completed assessment can be investigated from retained source. After handoff, it renders:

| View | Persisted content |
|---|---|
| Summary | Source Hunt state, seeds examined, node and edge counts, verified finding count, and retained-source coverage. |
| Results | Up to the first bounded set of seed dispositions, including summary, evidence state, and graph references. |
| Graph preview | Persisted graph nodes with node type, state, and the first available provenance path and line. |
| Limitations | Partial source coverage and missing-evidence statements remain visible. |

The inspector is a projection consumer. It does not reconstruct graph edges from DOM state or infer findings from labels. The full graph remains available in the persisted report contract for downstream clients and future graph visualization.

## Browser loading sequence

1. The APK static worker records genuine progress and persists its completion receipt.
2. The mobile assessment projection marks Source Hunt as available and exposes `start_source_hunt`.
3. The task card renders the handoff action.
4. The operator clicks the action; the browser sends the authenticated POST with optional exact selection.
5. The service validates the receipt, resolves retained source, executes the deterministic engine, persists the report, and updates the session plan.
6. The response replaces the selected-assessment store and appends the persisted assistant message.
7. The inspector re-renders from `assessment_projection.source_hunt`.

No step emits a synthetic progress event. If the deterministic engine cannot complete, the endpoint returns a governed error and leaves the prior selected assessment intact.

## Client contracts

The React client exports `MobileSourceHuntReport`, `MobileAttackGraph`, `MobileSourceHuntResult`, `MobileGraphProvenance`, and `MobileSourceHuntProjection`. The Flutter client mirrors these concepts with JSON-preserving model classes so new node types or attributes can be carried without losing evidence fields.

Both clients treat graph provenance and coverage as data, not presentation hints. A client may display a bounded result, but it must not upgrade `inconclusive`, `evidence_required`, or `blocked` to a finding.

## Real V380 acceptance boundary

The V380 acceptance run used the real uploaded APK and retained worker outputs. It examined 37 seeds and persisted 43 graph nodes and 42 graph edges. It produced one evidence-required result, 36 inconclusive results, and zero verified findings because retained JADX coverage was partial. This integration exposes those exact states through the chat workspace; it does not relabel the run as full APK analysis and does not unlock dynamic analysis.
