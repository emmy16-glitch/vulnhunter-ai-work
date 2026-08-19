# VulnHunter Mobile APK Intelligence Model

**Status:** Active implementation contract, 2026-08-19

## Purpose

VulnHunter’s APK pipeline is a bounded, evidence-backed static-analysis workflow. Tool output is not automatically a vulnerability finding. The pipeline normalizes tool results into distinct records so the conversation, inspector, reports, and client applications can preserve the difference between a configuration fact, a validation hypothesis, a verified security finding, and an operational limitation.

The authoritative artifact identity remains the ingested APK SHA-256. Raw tool output remains inside the isolated worker workspace; persisted records carry bounded summaries, output digests, source references, evidence receipts, and analysis limitations.

## Record taxonomy

| Record | Meaning | User-facing interpretation |
|---|---|---|
| `observation` | A normalized fact produced by a tool or bounded analyzer | Something the analysis observed |
| `verified_configuration` | A configuration condition proven by manifest or equivalent deterministic evidence | Verified configuration; not automatic exploitability |
| `verified_security_finding` | A security condition supported by deterministic evidence and the verification contract | Verified finding |
| `candidate` | A real observation or cross-evidence hypothesis that needs additional validation | Evidence required; not verified |
| `operational_issue` | A tool failure, timeout, or partial-result limitation | Analysis limitation; not a vulnerability |
| `partial_tool_result` | A tool returned bounded usable output but did not cover the complete requested stage | Usable partial evidence with coverage limits |
| `not_applicable` | A capability was correctly skipped because the artifact did not contain the required input | Not applicable, not failed |
| `blocked` | A governed capability could not run because a safety prerequisite was unavailable | Blocked by policy or runtime readiness |
| `rejected` | A candidate was deterministically rejected by the evidence-hunt disposition | Not supported by the bounded evidence |
| `inconclusive` | The available evidence cannot support a stronger disposition | More evidence is required |

The legacy `candidate_observations` field remains readable for migration compatibility, but new completed worker results also persist `intelligence`, which is the semantic source for new projections and reports.

## Ownership attribution

Each normalized security record, endpoint reference, exported-component surface, and downstream client projection may carry one of four ownership values: `app_owned`, `sdk_owned`, `platform_framework`, or `unknown`. Ownership is derived only where the available package/source evidence supports attribution. Unknown remains a valid result; the system must not infer ownership from a vague class name.

Ownership affects remediation. App-owned components can usually be changed directly by the application developer. SDK-owned surfaces require dependency/version and vendor-supported configuration review. Platform/framework surfaces should not be treated as application remediation targets without additional context.

## Transport-security correlation

The intelligence layer retains normalized endpoint references with protocol, normalized endpoint, host/port, likely service role, source file/offset, ownership, static/runtime origin, confidence, and reachability status. Static endpoint literals are explicitly marked with `reachability = unknown`.

When a verified manifest cleartext condition is accompanied by HTTP source references, VulnHunter creates a bounded transport correlation. The correlation raises a transport review hypothesis; it does not claim that every endpoint is reachable, that credentials were transmitted in cleartext, that live traffic was intercepted, or that a man-in-the-middle attack succeeded.

## Exported-component surfaces

Exported components are represented as configuration surfaces with component type, name, permission, ownership, intent filters, and a validation scope. An exported component without a component-level permission is a verified configuration condition. It is not automatically exploitable. The next validation scope includes intent extras, caller validation, permission and authentication/session checks, URI/deep-link and redirect handling, and sensitive downstream action reachability.

## Correlation hypotheses

Correlations are persisted separately from findings. A hypothesis can reference observations and evidence receipts, identify ownership and security property, state a confidence level, list required validation, and remain in `open`, `evidence_required`, `reviewing`, `verified`, `rejected`, or `inconclusive` state.

Examples supported by the current model include cleartext policy plus HTTP source references, dynamic endpoint assignment requiring endpoint-integrity review, and future exported-WebView/payment/deep-link combinations when the relevant source evidence is available. Correlation never becomes an exploitability claim by itself.

## Dynamic endpoint assignment

The reusable bounded detector accepts source snippets supplied by an already-isolated source-analysis stage. It looks for network/response/configuration context where a value influences an endpoint/server/host/URL/scheme assignment and emits an `evidence_required` observation with source file, line, destination variable, scheme, data origin, validation evidence, and downstream-use fields where available. The detector is generic and does not contain V380 hostnames or field names.

## Partial, not-applicable, and blocked coverage

Tool executions preserve status, exit code, output digest, bounded duration, partial state, generated-file count where known, coverage limitations, and downstream usability. A partial JADX result can feed retained source into later bounded review, but the presence of partial source cannot support whole-APK negative claims. The system records bounded-negative language such as:

> No app-owned matching call was found in the retained partial source inspected; this is not whole-APK absence.

Native tools are `not_applicable` when no native libraries are present. Dynamic analysis remains `blocked` when the exact digest-bound authorized isolated runtime and other governed prerequisites are unavailable. A completed job therefore means the bounded workflow reached a terminal receipt; it does not mean every possible APK analysis capability completed.

## Report and client projection

The persisted intelligence summary is projected into the chat-first workspace and client contracts. It includes verified configurations, verified findings, evidence-required candidates, operational issues, tool execution status, capability coverage, endpoint references, transport correlations, exported-component surfaces, bounded-negative claims, and remediation recommendations. The composer and task timeline remain authoritative projections of persisted backend state; clients do not create findings, progress percentages, approval, or dynamic execution authority.

## V380 acceptance interpretation

The supplied V380 acceptance receipt remains immutable historical evidence. Its current bounded interpretation is: completed AAPT2, apksigner, APKiD, Apktool, Androguard, and YARA captures; partial JADX with usable retained output and bounded timeout; native analysis not applicable because no native libraries were present; dynamic analysis blocked because the approved isolated runtime was unavailable. The normalized intelligence model is generic and must derive all counts from the persisted receipt rather than hardcoding V380 values into production logic.

## Related authority

- `docs/design/VULNHUNTER_UI_CONTRACT.md`
- `docs/product/CHAT_FIRST_WORKSPACE.md`
- `docs/acceptance/V380_durable_installed_tools_acceptance_receipt.json`
- `vulnhunter/mobile/intelligence.py`
- `vulnhunter/web/assessment_projection.py`
