# VulnHunter APK Intelligence Implementation Report

**Branch:** `feature/reference-apk-workspace-ui`  
**Commit:** `ca1b6c6`  
**Status:** Pushed and clean

## 1. What was found

The prior APK receipt stored materially different concepts in `candidate_observations`: verified manifest configuration, evidence-required scanner surfaces, and tool failures. That made generic counts and UI copy easy to misread as vulnerability counts. The worker also lacked a durable normalized endpoint model, bounded-negative semantics for partial source review, and a structured AI context that separated facts, hypotheses, limitations, and remediation.

The first fresh post-change V380 run exposed one real robustness defect: malformed URL literals could raise while parsing an optional port and invalidate an otherwise safe worker receipt. The endpoint parser now catches malformed URL/port syntax, retains the literal as bounded evidence, and uses an unknown port instead of failing the whole analysis.

## 2. Observation model changes

| Before | After |
|---|---|
| Mixed `candidate_observations` collection | Normalized `observations` plus typed collections |
| Configuration facts and candidates counted together | `verified_configurations`, `verified_findings`, and `candidates` are distinct |
| Tool failure could enter the hunt candidate stream | `operational_issues` and partial tool results are excluded from evidence candidates |
| Partial JADX was mainly an exit-code condition | Tool execution preserves partial state, generated files, coverage limitations, downstream usability, and evidence digests |
| Endpoint strings were not a first-class record | `MobileEndpointReference` records preserve normalized endpoint, protocol, host/port where parseable, role, ownership, source references, confidence, and unknown reachability |
| Exported components were only manifest observations | `MobileComponentSurface` records include type, permission, ownership, intent-filter data when available, and bounded validation scope |
| Correlation existed mainly as candidate hypotheses | Transport correlations and bounded hypotheses reference observations, endpoint IDs, evidence IDs, ownership, property, priority, confidence, and limitations |

The legacy collection remains readable for migration compatibility. New results persist the normalized `intelligence` summary and continue binding all evidence to the authoritative artifact SHA-256.

## 3. APK intelligence changes

The intelligence layer now derives evidence-aware remediation recommendations. Cleartext configuration produces HTTPS-only, narrow-exception, and dynamic-host-validation guidance. Exported component surfaces receive component-specific validation guidance. SDK-owned records receive dependency/version and vendor-supported configuration guidance rather than generic application-only remediation.

Endpoint extraction is generic and contains no V380 hostnames or field names. It classifies protocol and likely service role, attributes ownership from available package/source evidence, deduplicates normalized literals, and preserves all contributing source references. Invalid ports and malformed URL syntax are retained with unknown port/reachability.

A reusable dynamic endpoint-assignment detector accepts bounded source snippets and emits `evidence_required` observations when network/response/configuration context influences an endpoint/server/host/URL/scheme assignment. It records source file, line, destination variable, scheme, data origin, validation evidence, and downstream-use fields where supplied. It does not claim impact or exploitability.

The AI context builder now supplies only structured artifact identity, coverage, verified configurations, verified findings, open candidates, operational issues, hypotheses, transport correlations, ownership counts, tool limitations, bounded-negative rules, and remediation recommendations. It does not include raw tool output, provider names, hidden reasoning, or provider-private prompts.

## 4. JADX and bounded-negative semantics

JADX remains a bounded partial stage. A timeout with retained generated files is represented as `partial`, with downstream usability and coverage limitations. The current implementation does not yet add DEX-by-DEX resumable processing or incremental source indexing; that remains an explicit limitation. The retained output is still consumable by downstream bounded review.

The system persists bounded-negative language rather than universal absence claims:

> No app-owned matching JavaScript bridge call was found in the retained partial source inspected; this is not whole-APK absence.

> No app-owned dynamic class-loader match was found in the retained partial source inspected; this is not whole-APK absence.

YARA remains a surface detector and validation candidate source, not verification authority. Exported configuration remains configuration evidence, not automatic exploitability.

## 5. V380 acceptance

The successful real run was `mobile-v380-final-intelligence-retry-20260819` against V380.apk with SHA-256 `70a48a532156cd275bbf4efdb74549153caf214d2d1be8937b66800888b3fd7c`. The run used the committed durable worker policy copied to an external runtime workspace. No APK was executed on the VulnHunter host and no APK-discovered endpoint was contacted.

| Capability | Status | Evidence |
|---|---|---|
| AAPT2 | Completed | Real APK capture, return code 0, output digest persisted |
| apksigner | Completed | Real APK capture, return code 0, output digest persisted |
| APKiD | Completed | Real APK capture, return code 0, output digest persisted |
| Apktool | Completed | Real APK capture, return code 0, framework containment repair active |
| Androguard | Completed | Real APK capture, return code 0, output digest persisted |
| YARA | Completed | Real APK capture, return code 0, ruleset/output evidence persisted |
| JADX | Partial | Return code 124; 41,748 generated files retained; downstream review remains bounded |
| Radare2 | Not applicable | No native libraries discovered |
| Ghidra | Not applicable | No native libraries discovered |
| Dynamic analysis | Blocked | Approved isolated runtime unavailable; fail-closed gate preserved |

Overall capability state is `completed_with_partial_stage`: 6 completed, 1 partial, 2 not applicable, 0 failed, and 1 blocked capability stage.

## 6. Verified results and normalized counts

The final V380 receipt contains **32 raw observations**. The normalized result is:

| Semantic result | Count | Interpretation |
|---|---:|---|
| Verified configuration | 18 | Manifest/configuration facts, including cleartext traffic and exported components; not automatic exploitability |
| Verified security finding | 0 | No deterministic verified vulnerability was claimed |
| Evidence required | 13 | Candidates requiring further validation |
| Operational issues | 2 | JADX partial result plus the related operational limitation record |
| Correlation hypotheses | 1 | Bounded cross-evidence hypothesis |
| Transport correlations | 1 | Cleartext manifest plus normalized HTTP source evidence |
| Exported-component surfaces | 24 | Structured validation surfaces; not 24 exploit claims |
| Deduplicated endpoint references | 450 | Normalized source references with source provenance and unknown runtime reachability |

Ownership across observations is 8 app-owned, 9 SDK-owned, and 15 unknown. The unknown category is retained where the available evidence does not justify attribution.

The strongest verified configuration remains `android:usesCleartextTraffic="true"`. App-owned HTTP source references corroborate a transport review hypothesis, but the result does not claim endpoint reachability, cleartext credential transmission, live interception, or successful exploitation.

## 7. UI changes

The desktop and mobile inspector projections now receive the normalized intelligence contract. Verified configurations are visually distinct from verified security findings and evidence-required candidates. Operational issues render outside the candidate stream. Compact tool rows show normalized status, exit code where available, output/evidence digest references, generated-file counts, downstream usability, and coverage limitations.

Partial, not-applicable, blocked, failed, and completed tool states now receive different inspector styling. Ownership and security property metadata are visible on record cards. The existing chat-first task state, persistent composer, and one-task projection model were preserved.

## 8. Flutter changes

The Flutter client remains a client of the Django control plane and does not contain the APK scanning stack. Its `MobileIntelligence` model now mirrors verified configurations, verified findings, candidates, operational issues, tool executions, endpoint references, transport correlations, exported-component surfaces, bounded-negative claims, remediation recommendations, and coverage data.

The Flutter SDK was not executable in this runtime because the Flutter command was unavailable. The model changes were made without introducing an emulator dependency.

## 9. Files changed

| File | Purpose |
|---|---|
| `vulnhunter/mobile/intelligence.py` | New normalized domain, endpoint parser/deduplicator, component surfaces, correlations, coverage, bounded negatives, remediation, and AI context |
| `vulnhunter/mobile/static_worker.py` | Persists normalized intelligence in worker results |
| `vulnhunter/mobile/static_spool.py` | Persists intelligence in signed receipts |
| `vulnhunter/mobile/static_service.py` | Adds semantic report sections and backward-compatible report caller default |
| `vulnhunter/hunt/mobile_runtime.py` | Prevents operational issues from entering the evidence hunt |
| `vulnhunter/web/assessment_projection.py` | Projects normalized intelligence while preserving legacy projection fixtures |
| `vulnhunter/web/mobile_conversation_state.py` | Truthful semantic result copy and coverage language |
| `vulnhunter/web/static/web/conversation-mobile-inspector.js` | Distinct configuration/finding/candidate/operational records and normalized tool rows |
| `vulnhunter/web/static/web/conversation-mobile-inspector.css` | Distinct partial, blocked, not-applicable, operational, and configuration styling |
| `frontend/src/api/types.ts` | React client contract updates |
| `mobile/lib/core/api/models.dart` | Flutter client contract updates |
| `vulnhunter/mobile/__init__.py` | Public mobile intelligence exports |
| `tests/unit/test_mobile_intelligence.py` | Taxonomy, detector, deduplication, malformed endpoint, AI context, coverage, and hunt tests |
| `docs/architecture/MOBILE_INTELLIGENCE_MODEL.md` | Durable domain and product contract |
| `docs/acceptance/V380_INTELLIGENCE_ACCEPTANCE_SUMMARY.md` | Real V380 intelligence-layer acceptance record |

## 10. Test results

| Check | Result |
|---|---|
| Focused intelligence/mobile/projection tests | 43 passed |
| Repository-wide pytest | **1,789 passed**, 0 failed, 1 warning |
| Django system check | Passed; no issues |
| Ruff | Passed on changed Python files |
| JavaScript syntax | Passed with `node --check` |
| React/TypeScript typecheck | Passed with `pnpm exec tsc --noEmit` |
| Flutter tests/analyzer | Not run; Flutter SDK unavailable in this runtime |
| Real V380 acceptance | Completed successfully after fixing malformed endpoint-port handling |

The one repository warning is the pre-existing Pydantic validator warning in `tests/unit/test_ml_task_contracts.py`.

## 11. Browser acceptance

No new live browser acceptance run was performed in this semantic-model slice. Existing browser/UI contracts were preserved, and the changed inspector JavaScript passed syntax validation. A full browser acceptance at 1280, 1440, 360, 390, 412, 768, and 1024 remains a follow-up verification item for the newly populated semantic cards and tool rows.

## 12. Security review

The implementation preserved the security boundaries. It did not add authorization bypasses, arbitrary APK execution, arbitrary worker command construction, cross-user artifact access, cross-workspace evidence access, unsafe evidence serving, provider-secret exposure, or dynamic-runtime gate bypass. The first final acceptance retry found and fixed a safe parser robustness issue; it failed closed with no partial receipt rather than accepting invalid normalized data.

Historical V380 receipts were not rewritten. Temporary APK copies, decompilation output, runtime databases, tool caches, secrets, and the temporary acceptance workspace remain outside the repository.

## 13. Remaining limitations

The JADX runner still uses a bounded whole-invocation timeout rather than DEX-by-DEX resumable processing. Partial evidence is preserved and usable, but the system cannot yet report authoritative processed-DEX denominators unless the worker provides them. Exported-component surfaces currently provide a structured validation scope; they do not automatically execute component-specific code-path validation. Dynamic analysis remains blocked until the exact governed isolated runtime, digest-bound approval, device identity, network policy, and other readiness requirements are present. Flutter device validation and the new semantic-card browser matrix are still outstanding.

## 14. Git status

The active branch is clean and synchronized:

```text
ca1b6c6 (HEAD -> feature/reference-apk-workspace-ui, origin/feature/reference-apk-workspace-ui) feat: normalize APK intelligence and V380 coverage semantics
```

No APK, temporary decompilation output, runtime database, API secret, Ollama model, tool cache, or evidence working directory was committed.
