# VulnHunter SecurityTable and APK Workspace Implementation Report

**Repository:** [`emmy16-glitch/vulnhunter-ai-work`][1]  
**Branch:** `feature/reference-apk-workspace-ui`  
**Final commits:** [`308b8a1`][2] and [`d92305c`][3]  
**Report date:** 20 August 2026

> This report describes the implementation of the `pasted_content_13.txt` SecurityTable and APK workspace requirements. It distinguishes persisted evidence from planned, failed, blocked, or unavailable capabilities. The V380 acceptance run remains a **bounded static APK assessment**, not a claim of full APK analysis.

## 1. Architecture Found

VulnHunter already had a conversation-centered Django workspace with a selected-assessment store, persisted assessment projections, APK task cards, WebSocket/SSE activity infrastructure, a mobile APK workflow, Source Hunt handoff, Browser Intelligence, React/TypeScript contracts, and Flutter/Dart foundations. The right-side inspector was already contextual, but findings and APK intelligence collections did not share one canonical table behavior layer.

The authoritative mobile projection is assembled by `vulnhunter/web/assessment_projection.py`. The browser store in `workspace-state.js` owns the selected assessment snapshot. The conversation renderer owns persisted messages, while the mobile bridge owns task projection controls and refresh/retry reconciliation.

## 2. Problems Found

The primary gap was fragmentation: server-rendered findings had table markup but no shared behavior for selection, search, filters, column visibility, saved views, pagination, row expansion, or mobile cards. APK Components and Endpoints had no contextual table surfaces. Bulk Source Hunt selection could not be expressed as authoritative record IDs from the inspector.

A real browser acceptance pass found a second issue that static tests did not expose. Historical V380 messages rendered a persisted mobile-plan summary but did not carry the live task-card marker used by the bridge, so the inspector initially remained unselected. After hydration was fixed, the persisted summary still displayed `Queued` while the server projection was `Completed`. Both issues were corrected in [`d92305c`][3] and rechecked in the browser.

## 3. Architecture After

The workspace now has one framework-neutral `SecurityTable` behavior owner in `security-table.js`, one browser-side security/tool state vocabulary in `security-state.js`, one paginated mobile-record endpoint, and one authoritative selected-assessment flow. The conversation remains the primary work surface; tables are contextual evidence organizers rather than a second dashboard.

Inspector data is derived from the selected assessment projection. Browser selection is advisory only. Security-sensitive actions submit stable persisted IDs to the server, which revalidates ownership, assessment scope, artifact identity, worker receipt state, and Source Hunt policy before execution.

## 4. SecurityTable Implementation

`security-table.js` provides selection with indeterminate select-all behavior, search, up to three filters, sortable columns, Core/Technical column visibility, saved view and page-size persistence in local storage, row expansion, keyboard `/` focus, desktop tables, mobile structured cards, and pagination controls. It dispatches `vh:security-table-rendered` and `vh:security-table-selection-change` events.

The implementation normalizes both `id` and `key` column contracts, supports `savedViews` and `views`, preserves critical columns, passes action-button context to bulk handlers, and renders expanded evidence detail without injecting HTML from untrusted row values. Product ownership remains in `product.css`; conversation-specific context styling remains in `conversation.css`.

## 5. Tables Migrated

The existing findings overview table is hydrated from its server-rendered authoritative rows and receives stable column IDs plus verification/severity filters. The APK inspector now exposes Components and Endpoints tabs. Source Hunt also has a list/table representation for persisted attack paths when such records are present; it does not convert graph edges into fabricated attack paths.

| Surface | Data source | Current evidence behavior |
|---|---|---|
| Findings overview | Server-rendered persisted findings | Hydrated by SecurityTable; row links remain authoritative |
| APK Components | Selected assessment intelligence projection | Empty state when no persisted component records exist; bulk selection is governed |
| APK Endpoints | Selected assessment intelligence projection | Static references only; no network request is made from the table |
| Source Hunt paths | Persisted `attack_paths`/`paths` when supplied | List/table is empty when no persisted path records exist |

## 6. Bulk Actions

Components support **Investigate with Source Hunt**. The browser sends `record_ids` as a bounded JSON array through the existing protected POST route. The browser does not transition security state locally and does not trust display names as authority.

The server accepts at most 64 IDs per selection field, rejects malformed or oversized JSON, deduplicates IDs, and revalidates selected records against the selected APK assessment. Cross-assessment or invisible records fail closed. The successful response replaces the selected-assessment snapshot and publishes the persisted conversation message through `vh:conversation-message`.

## 7. Source Hunt Flow

`POST /workspace/mobile-source-hunt/` now accepts single or bulk seed IDs and record IDs. Record IDs are resolved server-side through `MobileSourceHuntEngine.available_seeds()`. Source Hunt still requires a completed APK evidence receipt, a matching artifact SHA-256, a verified worker policy, and an exact retained JADX source root inside the configured worker boundary.

The workflow remains deterministic and bounded. It does not execute the APK, contact endpoints found in APK strings, bypass the worker boundary, or infer findings from failed tools. The persisted report is stored before the selected-assessment projection and chat message are published.

## 8. Context Inspector

The right-side inspector now contains Summary, Activity, Findings, Components, Endpoints, Evidence, Source Hunt, and Report tabs. It remains bound to the selected assessment store and refuses to render authoritative details without matching assessment and task-card identities.

The composer-area ConversationContextBar displays the selected assessment ID and selected record IDs. It listens for SecurityTable selection events and generic context-selection events, provides a clear action, and labels the context as investigation context rather than authorization. Historical APK threads now hydrate through the persisted mobile-plan message and the server-owned refresh projection.

## 9. Chat Composer

The composer remains persistent and usable while an assessment is active. The new context bar sits immediately above it without moving the composer controls. It uses readable 12–15px-class copy, wraps IDs safely, and becomes a full-width stacked control on narrow screens.

The final browser pass confirmed that a historical V380 thread displays the persisted task summary as **Completed**, not stale **Queued**, and shows the real `8 of 8` stage progress plus the persisted activity context.

## 10. Mobile Experience

On narrow screens, SecurityTable switches from horizontal table overflow to structured cards. Selection controls remain reachable, bulk actions use full-width touch targets, pagination remains available, and the inspector is a full-width contextual surface rather than a squeezed desktop drawer. The context bar stacks its copy and clear control.

The prior responsive matrix acceptance for 390px mobile and 1440px desktop remains valid from the committed reference-workspace work. This session additionally verified the authenticated local workspace in the browser after restarting the preview with current templates and cache-busted assets.

## 11. Files Changed

The main implementation files are `security-table.js`, `security-state.js`, `product.css`, `conversation.css`, `base.html`, `findings_overview.html`, `_mobile_analysis_inspector.html`, `conversation.html`, `conversation-mobile-inspector.js`, `conversation-mobile-context.js`, and `conversation-mobile-bridge.js`.

Backend and contract files are `mobile_records_views.py`, `mobile_source_hunt.py`, `mobile_source_hunt_views.py`, `source_hunt/mobile.py`, `urls.py`, `frontend/src/api/types.ts`, `test_mobile_records_views.py`, `test_mobile_source_hunt_views.py`, `test_authoritative_mobile_inspector_contract.py`, and `test_conversation_experience.py`. Existing V380 review helper scripts were also normalized by the repository-wide Ruff pass; no APK, JADX output tree, runtime cache, or worker state was committed.

## 12. API/Backend Changes

| Route | Contract | Security behavior |
|---|---|---|
| `GET /workspace/mobile-records/` | `record_type`, `query`, `state`, `ownership`, `protocol`, `page`, `page_size` | Authenticated, `scan.read`, owner-bound selected plan, bounded page sizes 10/25/50/100 |
| `POST /workspace/mobile-source-hunt/` | Single or JSON-array `seed_id(s)` and `record_id(s)` | Authenticated, `scan.read`, maximum 64 IDs per list, server-side record-to-seed resolution |

The React contract layer now contains `SecurityState`, `ToolState`, shared state labels, `SecurityTableColumn`, pagination, table state, paginated rows, and browser-network row types.

## 13. Test Results

The final repository regression suite passed **1,813 tests** with one pre-existing Pydantic warning. Focused inspector, records, Source Hunt, and conversation tests passed **35 tests** after the hydration fix; the final inspector/conversation subset passed **24 tests**.

The final static verification passed `ruff format`, repository-wide `ruff check`, `python manage.py check`, JavaScript syntax checks for all changed browser scripts, and `frontend/pnpm exec tsc --noEmit`. Flutter verification was not run because the `flutter` executable is not installed in the sandbox; the Dart client foundation remains covered by its existing repository state and contracts.

## 14. Screenshot Acceptance

The authenticated browser acceptance run used the seeded local E2E account and the real persisted V380 conversation. It verified the three-column workspace shell, the selected APK inspector, the eight inspector tabs, real activity entries, the ConversationContextBar, the completed `8 of 8` stage summary, and the cache-busted SecurityTable runtime.

The browser viewport available in this session was approximately 892×602. The final visual evidence is attached separately as `127_0_0_1_2026-08-20_00-44-44_8932.webp`. The earlier committed matrix checks covered 390px mobile and 1440px desktop containment; no claim is made that this session produced new screenshots at those exact widths.

## 15. Performance

The SecurityTable avoids per-row network requests, uses bounded client-side rendering for the current projection, persists only small UI preferences, and limits expanded previews to the selected row. The backend records endpoint provides bounded pagination for larger evidence collections and is covered by pagination/filter tests.

A remaining optimization is that the current Components and Endpoints inspector renderers consume the selected projection arrays directly rather than asynchronously replacing them with the paginated records endpoint. The endpoint is ready for large projections, but a future slice should move those inspector fetches fully server-paginated if APK intelligence collections grow beyond the projection envelope.

## 16. Security Review

The implementation preserves the required security boundaries. Dynamic analysis remains fail-closed because MobSF, ADB, and Frida remain gated when the private service policy or disposable emulator is unavailable. APK execution was not performed on the VulnHunter host. No endpoint discovered in V380 strings was contacted.

The V380 acceptance evidence is classified as follows:

| Capability | Evidence level | Acceptance statement |
|---|---|---|
| APK identity and SHA-256 binding | **Verified** | Real V380 artifact, 12 DEX files, 0 native libraries, digest `70a48a532156cd275bbf4efdb74549153caf214d2d1be8937b66800888b3fd7c` |
| Persisted assessment lifecycle | **Verified** | Server projection reports completed lifecycle and 8/8 recorded stages |
| Chat activity timeline | **Verified** | 9 persisted activity events and 3 evidence receipts were rendered from the real assessment |
| Candidate observations | **Verified as candidates** | 16 persisted candidates; they are not all verified vulnerabilities |
| YARA execution | **Verified** | Persisted YARA receipt is completed |
| JADX execution | **Operational failure** | Persisted exit code `-24`; no finding was inferred |
| Androguard execution | **Operational failure** | Persisted exit code `1`; no finding was inferred |
| Other planned tools | **Planned/unexecuted in this receipt** | AAPT2, apksigner, APKiD, and Apktool remain planned in the selected task projection |
| Dynamic analysis | **Blocked by policy** | MobSF, ADB, and Frida remain gated; no runtime bypass was attempted |
| Source Hunt | **Available only as governed follow-up** | Requires selected persisted records and a completed exact source receipt; no automatic external contact occurs |

## 17. Remaining Limitations

This slice does not claim full APK analysis. The real V380 run had partial tool coverage, failed JADX and Androguard operations, and dynamic analysis remained correctly locked. Components and Endpoints are empty when their normalized persisted collections are absent; the UI does not fabricate rows from names or screenshots.

Flutter tests could not run in this environment because Flutter is not installed. The inspector’s large-dataset path is prepared by the backend endpoint but is not yet an asynchronous server-paginated renderer. Attack-path rows appear only when persisted attack-path records exist; graph edges are not mislabeled as paths.

## 18. Git Status

The branch is clean and pushed. The final commits are [`308b8a1`][2], which delivered the canonical SecurityTable, paginated records endpoint, bulk Source Hunt selection, inspector tabs, context bar, and tests, and [`d92305c`][3], which fixed historical APK hydration and reconciled the persisted execution summary in place.

| Item | Result |
|---|---|
| Branch | `feature/reference-apk-workspace-ui` |
| Remote | `origin` at GitHub |
| HEAD | `d92305c45186a16fa850a324228a42baf12ef26f` |
| Working tree | Clean |
| APK committed | No |
| Temporary worker/runtime state committed | No |
| Dynamic execution bypassed | No |

## References

[1]: https://github.com/emmy16-glitch/vulnhunter-ai-work/tree/feature/reference-apk-workspace-ui "VulnHunter feature branch"
[2]: https://github.com/emmy16-glitch/vulnhunter-ai-work/commit/308b8a1 "SecurityTable and governed APK record workflows"
[3]: https://github.com/emmy16-glitch/vulnhunter-ai-work/commit/d92305c "Historical APK execution state reconciliation"
