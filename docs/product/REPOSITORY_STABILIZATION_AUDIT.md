# Repository Stabilization Audit

## Scope

This audit records the initial findings from the repository authority chain and the attached stabilization specification. The repository remains a Django/ASGI backend with a server-rendered conversation workspace, shared persisted assessment projections, SSE and WebSocket transports, a React/TypeScript client foundation, and a Flutter client foundation. The real V380 APK acceptance evidence remains under `docs/acceptance/` and is not replaced by fixtures.

## Authority and state owners

The security and execution authority remains in deterministic backend services: authorization stores and scoped target validation, `AssessmentWorkflowService`, `AssessmentGraphService`, `AgentStore`, worker spool/receipt stores, evidence/finding stores, and governed approval/review services. `vulnhunter/web/conversational_views.py` and `vulnhunter/web/services.py` project owner-scoped persisted state into browser payloads; they must not become new authorities.

The browser activity contract is shared through `_conversation_stream_payload()` and `activity_payload()`. SSE and WebSocket are transport layers over the same persisted activity cursor and snapshot semantics. The Flutter realtime client already performs catch-up and cursor-preserving reconnect against the API contract, so changes should extend shared payload semantics rather than create a second mobile state machine.

## Findings requiring implementation

1. **Worker enqueue defaults are too permissive for the governed pilot.** `VULNHUNTER_NUCLEI_PILOT_ENQUEUE_ENABLED` currently defaults to `true`, while the deployment guidance requires explicit readiness checks and explicit opt-in. This causes the security-sensitive approval regression to queue a worker job in a unit environment that should remain execution-blocked.
2. **The orchestration security evaluator has a fragile changed-content scan.** The unsafe transport regex exists, but the verification path does not robustly scan the current contents of every changed text file. The security gate should scan bounded current changed-file content in addition to the Git diff, while preserving path, size, binary, and repository-root safety checks.
3. **Conversation run binding has an implicit target-based fallback.** `_authoritative_run()` can resolve a missing run ID by selecting the latest visible run for a matching target. Explicit run IDs are authoritative, but target fallback can select a stale or superseded attempt when multiple attempts share a target. This requires an explicit binding/supersession rule and regression coverage rather than browser-memory rebinding.
4. **The provider runtime is currently single-provider in practice.** `ProviderRegistry` routes only to Groq and has no health memory, cooldown, circuit breaker, fast fallback, or recovery-to-primary behavior. The provider model contracts need to remain non-authoritative and privacy-gated while the router gains provider-neutral health state and deterministic tests.
5. **The reference workspace slice is already implemented and pushed.** The three-column shell, empty dashboard, APK task projection, inspector hooks, responsive fallback, and separator correction are in commit `51d0868`. Further UI changes must consolidate existing owners rather than add late override styles, and the inspector should become contextual rather than permanently consuming width when no detail is selected.
6. **The V380 APK result must remain capability-truthful.** Androguard and YARA passed, JADX is partial, Radare2 was not applicable because no native library was present, and dynamic analysis remains blocked by the governed runtime gate. No UI or backend change may convert these states into a blanket complete/full-analysis claim.

## Stabilization sequence

The implementation will first correct the two failing security-sensitive regressions and add tests. It will then tighten current-run/attempt binding and shared snapshot semantics, consolidate conversation state and failure presentation, implement provider-neutral failover with health/circuit behavior, audit CSS ownership and mobile drawer/detail behavior, verify APK capability states, and finish with security, regression, browser, provider, reconnect, and V380 evidence. Any unsupported capability remains unavailable or blocked rather than being represented as a control or success state.

## Progress update

The first implementation slice is now applied directly. The Nuclei worker enqueue setting defaults to `false` and requires explicit deployment opt-in after readiness verification. The orchestration security-policy verifier scans both Git diff additions and bounded current text contents for all changed files, which closes the missed `trust_env=True` detection path. Conversation run resolution now requires an explicit persisted `run_id`; target-only state cannot select the latest same-target run, and a newer same-target attempt cannot replace an explicitly selected attempt.

The browser no longer performs word-by-word or timer-based assistant response reveal. Provider identity/model badges and provider-named busy copy were removed from ordinary conversation rendering. The provider-control script now only keeps automatic routing hidden and injects the backend-compatible `provider_preference=auto` field; it no longer creates synthetic elapsed-time progress stages. The canonical task failure panel now distinguishes recovering, failed safely, blocked and cancelled states using persisted failure messages, user actions and preserved-state facts.

The failover owner now has process-local health state with degraded/cooldown/probe states, repeated-failure circuit activation, cooldown skipping, success recovery, provider-neutral aggregate runtime labels, and deterministic reset coverage. Provider names remain server-side diagnostics only. Targeted regression verification currently passes for the repaired security tests, stale-state tests, failover continuity, conversation reasoning, provider runtime, provider-control UI contract, failure projection and workspace UI contract.


## Completed stabilization evidence

The shared WebSocket snapshot now carries the same normalized task fields as the SSE payload, including task state, active summary, approval state, execution state, workflow state, execution enablement, blocking reason, readiness, evaluation result, update timestamp, and activity tree. A terminal snapshot with no tree no longer falls back to a misleading `running` status. The browser and transport regression suites cover cursor resumption, terminal closure, and the normalized snapshot contract.

The APK plan and receipt projections now distinguish executable static tools from deferred dynamic capabilities. Candidate hunt receipts persist a confidence value sourced from the worker observation and retain evidence receipt identifiers. The finding inspector renders persisted severity, confidence, verification state, disposition, and evidence references only when those fields exist in the authoritative payload.

The Flutter client model and cursor-preserving realtime client now accept and republish the normalized snapshot fields. The React client types accept the same contract and its production build passes. The container does not include Dart or Flutter executables, so Flutter runtime tests were not executable in this environment; the updated Dart model test remains in the repository for the normal mobile CI toolchain.

A fresh real V380.apk acceptance run completed through the bounded signed worker pipeline. Androguard and YARA passed; JADX ran against the real APK but remained partial at the configured timeout after generating 41,711 files; Radare2 was not run because the APK contained zero native libraries; unavailable tools remained unavailable; and dynamic execution stayed blocked. The durable run report is `docs/acceptance/V380_APK_STABILIZATION_ACCEPTANCE_SUMMARY.md`.

The final verification run produced 1,783 passing Python tests with one warning and no failing tests. Django system checks reported no issues, Ruff lint and format checks passed, JavaScript syntax checks passed, the React/TypeScript production build passed, and the controlled browser acceptance passed with no page errors, a `248px 532px 380px` desktop grid, visible task panel and inspector, four empty-state shortcuts, three recent items, correct mobile hiding and no horizontal overflow. The working tree remains uncommitted until the final review and commit step.
