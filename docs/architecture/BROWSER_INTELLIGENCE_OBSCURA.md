# Browser Intelligence with Obscura

## Purpose

VulnHunter Browser Intelligence is a governed, worker-owned browser capability for collecting bounded runtime observations from an already-authorized website. It is not a vulnerability verifier and it does not replace the existing website assessment workflow. The feature places browser evidence inside the existing chat workspace and keeps the authorization, target-scope, action-policy, and evidence boundaries on the server.

## Runtime boundary

The pinned Obscura `v0.2.0` Linux x86_64 release is installed under the durable browser-tools directory and is verified against the reviewed archive SHA-256 before extraction. VulnHunter starts Obscura as a worker-owned stdio MCP subprocess with fixed arguments. The web client never receives a subprocess handle, executable path, arbitrary command, or raw MCP transport. Every browser operation is represented by a typed `BrowserAction`, validated by `BrowserPolicy`, sent through the allowlisted MCP tool map, and persisted as a receipt before it is published to the workspace.

Production activation remains fail-closed. The default runtime setting is the existing Playwright path; Obscura is only selected when the runtime feature flag, pinned binary, expected version, and archive digest are present. The private-network bypass flag is not part of normal activation. It is used only by the deterministic local acceptance fixture so the test process can target loopback without weakening production SSRF protection.

Runtime preflight validates every MCP tool that the advertised typed action contract can dispatch. A runtime is not marked ready merely because a subset of navigation/screenshot tools exists.

## Authorization and action policy

A Browser Intelligence session requires an authenticated VulnHunter actor, an active authorization record, an exact target within the authorization origin and path boundary, and a validated request budget. Public targets continue through the verified consent path where that product flow is enabled. Passive observation is the default mode. Controlled interaction and credentials require a distinct policy decision; arbitrary evaluation, request interception, response mutation, and unrestricted local-file access are not exposed by the web surface.

The initial web workspace exposes passive actions such as navigation, snapshots, link and form discovery, network request collection, console collection, and screenshots. Each action has an owner-bound session, sequence number, current URL, status, safe error category, and bounded public summary. Element attribute access requires an explicit element reference/selector and a bounded, non-empty attribute name. Screenshot evidence is limited by both screenshot count and the configured cumulative screenshot-evidence byte budget.

## Persistence, refresh and worker loss

Sessions, JSONL action receipts, network observations, console observations, report JSON, and screenshot metadata are stored below the configured Browser Intelligence root. Network and console observations are appended durably as their corresponding browser actions complete rather than being kept only in process memory until `finish()`. Screenshot bytes are content-addressed and served only through an authenticated owner/workspace-checked evidence route. Raw credentials are never included in receipts, summaries, or reports. URL observations are normalized to scheme, host, port, path, method, and status; request bodies are represented only by a boolean presence flag.

A browser refresh or a request routed to a different web process must not make the persisted session appear to have vanished. When the process-local runtime service is no longer attached, the state endpoint restores the owner/workspace-checked persisted session projection and reports `runtime_attached=false`. Existing receipts and evidence remain durable. The server does **not** silently spawn a second Obscura process or claim that browser execution is still live; new actions remain unavailable until a governed live worker/runtime is attached again.

The current implementation therefore has durable state recovery but not distributed live-runtime reattachment. Production multi-process deployments still need a worker registry/sticky-routing or equivalent explicit reattachment design before an active browser session can continue executing seamlessly across a worker-process loss.

## Reports and evidence semantics

Reports are bounded runtime-observation reports. Their limitations explicitly state that Obscura does not verify vulnerabilities. Source Hunt correlation identifiers are reserved for evidence-backed integration and are never fabricated from a browser string or page message.

Browser observations are not findings by themselves. Network requests, forms, console entries, screenshots and DOM/page observations may corroborate an existing hypothesis, but verification still belongs to deterministic validation and the existing finding/review lifecycle.

## Chat workspace flow

The chat workspace includes a collapsible Browser Intelligence panel. The panel submits the target and authorization reference to the authenticated start endpoint. The server creates the owner-bound session and returns its capabilities. The browser controller then issues one typed `navigate` action and renders each subsequent receipt in place. Snapshot, forms, network, console, and screenshot actions remain visible in the same card. Finishing persists the report and exposes a private screenshot link without creating a second dashboard.

The React and Flutter client contracts mirror the server fields for sessions, action receipts, network and console observations, screenshot artifacts, and reports. They preserve unknown fields so newer server evidence can be displayed without treating client state as an authority.

## Source Hunt and attack-graph integration status

Browser Intelligence and Source Hunt intentionally share evidence-oriented concepts, but the current production path does **not** yet claim automatic browser-runtime-to-source-code correlation. A browser endpoint or page event must not be converted into a Source Hunt edge merely because strings match. Future correlation must bind persisted browser evidence to exact source/revision identities and pass the same provenance and deterministic-validation requirements as other attack-graph edges.

The APK-backed Mobile Source Hunt path is separate and already builds a persisted evidence-backed attack graph from governed APK/source receipts. Browser Intelligence must not borrow APK Source Hunt verification state or promote a browser observation into a verified vulnerability.

## Dynamic-analysis boundary

Obscura browser observation is not APK dynamic execution, emulator testing, Frida instrumentation, or a vulnerability confirmation authority. The APK dynamic-analysis gate remains fail-closed and unchanged. Browser Intelligence must not execute APKs, contact endpoints discovered in APK strings, bypass worker isolation, or promote a Source Hunt hypothesis. Any browser-to-Source-Hunt relationship must be derived from persisted evidence and pass the existing deterministic validation requirements.

## Acceptance evidence

The real local acceptance used the pinned Obscura binary against a deterministic fixture. It performed navigation, snapshot, form discovery, interactive-element discovery, credential fill under an explicit test-only controlled policy, a real click receipt, a governed dashboard navigation, bounded wait, dashboard snapshot, network collection, console MCP invocation, screenshot capture, and current-URL collection. The dashboard snapshot proved JavaScript-rendered content, and network evidence included `/api/profile` and `/api/settings` with successful responses. Obscura returned `No console messages.` despite the page-side console marker; the acceptance records this as `runtime_returned_no_messages` rather than fabricating a console observation.

Subsequent regression coverage also verifies owner/workspace persistence, progressive network/console durability, runtime-detached refresh projection, attribute-policy validation, complete MCP-tool preflight coverage, and screenshot byte-budget rejection before evidence is written.
