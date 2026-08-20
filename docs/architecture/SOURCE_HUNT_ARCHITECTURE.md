# Mobile Source Hunt Architecture

## Purpose

Mobile Source Hunt is VulnHunter's APK-backed, code-level attack-surface discovery and validation path. It begins only after a governed static APK worker has completed and its intelligence receipt and retained JADX workspace have been persisted. The engine is deterministic and evidence-led: it can classify and correlate real APK observations, build a reconstructable attack graph, reject unsupported hypotheses, and preserve uncertainty when retained source coverage is incomplete.

The engine does **not** execute an APK, contact endpoints discovered in strings, bypass worker isolation, or treat an AI response as a verification authority. Dynamic analysis remains a separate approval-gated capability and is not implicitly unlocked by Source Hunt.

## Before and after

| Earlier APK path | Mobile Source Hunt path |
|---|---|
| Normalized static-tool receipts were visible as observations, candidates, and operational issues. | Persisted observations become deterministic Source Hunt seeds for code-level investigation. |
| Findings were reviewed as individual records. | Entrypoints, sources, transformations, guards, sinks, evidence, and remediations are connected in an attack graph. |
| A candidate could remain a flat, unresolved item. | Each candidate receives a bounded state: `verified`, `rejected`, `inconclusive`, `evidence_required`, or `blocked`. |
| Partial JADX output could be mistaken for a complete negative. | Coverage is recorded on the report, graph, node, edge, and provenance records. |
| Browser state could display a result without a durable graph identity. | The report and graph are persisted and reconstructable from the APK artifact, source identity, and analysis run. |

The Source Hunt service is therefore an extension of the APK evidence pipeline, not a second browser-only analysis implementation.

## Canonical flow

```text
completed isolated APK worker receipt
→ exact artifact and signed worker policy validation
→ retained JADX source workspace resolution
→ normalized intelligence seed classification
→ entrypoint, source, guard, sink and boundary correlation
→ provenance-bearing attack graph construction
→ deterministic validation and false-positive rejection
→ persisted report and graph
→ authoritative assessment projection
→ chat result + APK inspector graph view
```

The browser requests the handoff through `POST /workspace/mobile-source-hunt/`. The view requires an authenticated operator with read access to the selected mobile assessment. The service re-reads the selected plan, verifies the completed worker receipt, resolves the exact retained source path from the worker policy, and invokes `MobileSourceHuntEngine`. The returned report is saved before it is published to the session or conversation.

## Domain model

### Report

`MobileSourceHuntReport` is the durable top-level receipt. It contains the artifact identity, source identity, analysis run identity, coverage summary, seed and disposition counts, all `MobileSourceHuntResult` records, the `MobileAttackGraph`, creation time, and an optional safe error. Raw tool output is not copied into the browser projection.

### Seed and result

A `MobileSourceHuntSeed` is derived from a real normalized APK intelligence record or configuration surface. Seed classification uses both the normalized weakness identifier and title, so equivalent evidence remains discoverable when one upstream field is incomplete. A `MobileSourceHuntResult` retains the seed, state, safe summary, entrypoint, source and sink symbols, observed controls, missing evidence, source references, graph identifiers, bounded-negative flag, deterministic validation text, and remediation context.

A `verified` result is reserved for a deterministic path that satisfies the promotion requirements. `rejected` is a successful validation outcome when a candidate is disproven. `inconclusive` means the retained source or available evidence cannot establish or reject the path. `evidence_required` means a specific additional receipt is needed. `blocked` means policy or operational boundaries prevent the investigation.

### Attack graph

`MobileAttackGraph` contains typed nodes and typed edges. Every node and edge has provenance references, and every provenance record includes the artifact hash, source identity, source path where available, source hash where available, line range where available, analysis run, confidence, coverage state, and evidence references.

The graph can be persisted and reconstructed without browser state. Node and edge identity is derived deterministically and duplicate observations do not create duplicate graph records.

## Node and edge vocabulary

The engine supports the following node classes:

| Node family | Examples |
|---|---|
| Identity and structure | `artifact`, `manifest_component`, `source_file`, `entry_point` |
| Data and control | `source`, `transformation`, `validation`, `authentication_check`, `authorization_check`, `permission_check`, `trust_boundary` |
| Sensitive operations | `network_endpoint`, `webview`, `file_operation`, `database_operation`, `process_execution`, `deserialization`, `dynamic_loader`, `cryptographic_operation`, `security_sink` |
| Evidence and disposition | `tool_evidence`, `observation`, `security_hypothesis`, `finding`, `remediation` |

Edges express real relationships such as `exposes`, `receives`, `calls`, `flows_to`, `derives_from`, `loads_url`, `requests`, `opens`, `writes`, `executes`, `deserializes`, `loads_code`, `redirects_to`, `guarded_by`, `validated_by`, `sanitized_by`, `permissioned_by`, `crosses_trust_boundary`, `corroborates`, `evidence_for`, `candidate_for`, and `remediates`. An edge is never added merely because two labels look related; it requires source-derived or receipt-derived evidence and is stored with provenance.

## Finding promotion requirements

A Source Hunt result may be promoted to a verified finding only when all of the following are established deterministically:

1. The relevant component or code path is exported or otherwise reachable under the modeled boundary.
2. The input is attacker-controlled under the retained source and manifest evidence.
3. A source-to-sensitive-sink path is established in the graph.
4. No effective authentication, authorization, validation, sanitization, permission, or trust-boundary guard blocks the path.
5. Deterministic validation confirms the path and its security consequence.

AI may assist with prioritization or remediation language in a future governed integration, but it cannot create an edge, establish reachability, or promote a result.

## Bounded-negative semantics

Partial decompilation is a first-class state. The statement **“not found in retained source”** is never converted into **“does not exist in the APK.”** A report records source-file count, source bytes, limitations, evidence references, and coverage status. In the V380 acceptance run, the retained JADX tree was partial relative to the complete APK, so Source Hunt correctly preserved unresolved WebView and dynamic-loading candidates as inconclusive rather than inventing verified paths or declaring the APK safe.

The same semantics apply at the graph level. Node and edge provenance records retain the current coverage status, and result summaries identify missing evidence. Rejection is valid only when the relevant evidence is present and a deterministic contradiction is established.

## Persistence and projection

The report is saved through `MobileSourceHuntStore` under the configured Source Hunt report root. The session plan stores only bounded metadata and the serialized report contract; APK bytes, raw tool output, and source trees remain outside the session.

`mobile_assessment_projection()` exposes:

- handoff state and availability;
- report identity and readiness;
- selected seed and selected result;
- seed and disposition counts;
- coverage and limitations;
- graph identity, node and edge counts, node rows, and edge rows;
- governed actions `start_source_hunt` and `view_source_hunt_graph`.

The selected-assessment store requires the projection and task card to agree on the assessment identity before the browser inspector updates. This prevents stale or cross-assessment Source Hunt data from being rendered.

## Dynamic-analysis boundary

Static Source Hunt does not unlock emulator, ADB, Frida, MobSF, runtime network, or other dynamic capabilities. Those capabilities require their own deployment readiness, isolated runtime identity, network policy, approval record, and fail-closed worker path. If those prerequisites are unavailable, Source Hunt reports the boundary rather than bypassing it.

## Acceptance posture

The real V380 Source Hunt acceptance run examined 37 seeds, produced a persisted graph with 43 nodes and 42 edges, retained one `evidence_required` result and 36 `inconclusive` results, and promoted zero verified findings. That disposition is correct for the available partial JADX coverage. The acceptance artifact is the source of truth for run-specific counts; this architecture document defines the behavior and evidence contract.
