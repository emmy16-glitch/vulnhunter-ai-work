# APK Chat UI Refinement Summary

## Scope

This slice refines the VulnHunter conversation workspace around the supplied APK-analysis references. The goal was not to create a decorative mockup. The implementation makes the persisted mobile plan, signed worker progress, and persisted activity events appear as one evolving task projection while preserving the existing evidence and governance boundaries.

> The UI may summarize operational progress, but it must not promote a state, invent a tool result, or expose hidden model reasoning without persisted backend evidence.

## Implemented behavior

| Area | Result |
|---|---|
| APK execution surface | One canonical `data-mobile-live-execution` block per `run_id`. |
| Stage hierarchy | Real plan rounds become collapsible stage rows; real tool rows are keyed by stable tool ID. |
| In-place updates | Running and completed SSE snapshots update the same tool row. Plan hydration does not recreate a row after it moves into an active stage. |
| Technical activity | Persisted plan/progress events are consolidated inside a collapsed `Technical activity` disclosure with the actual event count. |
| Status semantics | Backend values normalize to pending, queued, running, completed, failed, blocked, or cancelled without frontend promotion. |
| Duplicate UI | The previous large prepared-hunt card was retired to a compact plan context anchor. Detailed progress exists only in the canonical task block. |
| Composer | Existing attachment, send, stop, and advanced controls remain available and responsive. |
| Inspector and finding context | Existing inspector and persisted finding bindings were preserved; no placeholder finding objects were added. |
| Safety | Dynamic execution remains governed by the existing approval/runtime policy. No APK execution or external-target probing was introduced. |

## Verification

The changed Python contract tests passed with **22 tests** in the focused mobile/conversation subset. The canonical APK browser acceptance passed, and the rapid-SSE acceptance passed after verifying that a two-burst running-to-completed sequence converges to one JADX row and retains technical activity history.

The authenticated real-app responsive matrix was run at **320, 390, 768, 1024, 1280, and 1440 pixels**. Every width reported no horizontal overflow, no page errors, a working composer, and an available inspector hook. The restored terminal V380 thread did not expose an active task block in its current server projection; the active task and rapid-SSE browser fixtures therefore verified the live canonical block separately using persisted-event-shaped fixture responses.

The full repository suite recorded **1,776 passed and 2 failures**, with total line coverage reported at **75%**. The two failures were the known unrelated tests `test_changed_plan_digest_is_rejected_and_approved_plan_stays_execution_blocked` and `test_security_policy_detects_unsafe_transport_setting`; they concern existing assessment/orchestration behavior rather than this UI slice. `git diff --check` passed, and the changed JavaScript files passed Node syntax checks.

## Durable references

The implementation contract is in [`docs/product/APK_TASK_UI_CONTRACT.md`](../product/APK_TASK_UI_CONTRACT.md). The source audit is in [`docs/product/UI_REFERENCE_AUDIT.md`](../product/UI_REFERENCE_AUDIT.md), the browser audit is in [`docs/product/UI_BROWSER_AUDIT.md`](../product/UI_BROWSER_AUDIT.md), and the responsive matrix is in [`docs/product/UI_MATRIX_RESULT.json`](../product/UI_MATRIX_RESULT.json).
