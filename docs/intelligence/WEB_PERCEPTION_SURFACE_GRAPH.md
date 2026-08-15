# Web Perception and Application Surface Graph

## Status

This document defines the first passive browser-perception foundation for VulnHunter.

The implementation is intentionally isolated on its own feature branch and does not replace the
existing `SafeHttpClient` + `SiteMapper` path. It also does not change the browser UI, scan
database schema, or production worker publisher in this batch.

## Objective

Give VulnHunter a browser-derived view of an authorized private/laboratory web application
without granting the browser, target page, or a model authority to execute security actions.

The first flow is:

```text
ApprovedTarget
    -> existing explicit AuthorizationStore validation
    -> immutable BrowserPerceptionPolicy
    -> signed approved Playwright worker release
    -> immutable WebPerceptionPlan
    -> DNS revalidation
    -> OpenSandbox default-deny egress
    -> exact pinned IPv4 allow rule
    -> non-root passive Playwright worker
    -> structure-only BrowserPerceptionEvidence
    -> host-side redaction/schema validation
    -> evidence SHA-256
    -> deterministic ApplicationSurfaceGraph
    -> graph SHA-256
```

## Non-negotiable passive boundary

The worker may:

- navigate GET/HEAD pages inside the exact authorized scheme, hostname, port, and segment-aware
  path boundary;
- observe forms without submitting them;
- observe read-only browser requests;
- collect links and same-scope script URLs;
- hash DOM tag names and attribute **names**;
- follow in-scope links with a bounded breadth-first traversal.

The worker must not:

- submit forms;
- click buttons or arbitrary DOM elements;
- send POST/PUT/PATCH/DELETE/OPTIONS requests;
- upload files;
- provide credentials;
- execute generated payloads;
- bypass authentication or access control;
- open WebSockets;
- permit service workers;
- access another hostname, port, scheme, or path boundary;
- export page text, DOM HTML, response bodies, request/response headers, cookies, local storage,
  session storage, screenshots, videos, traces, or HAR files.

## Prompt-injection boundary

Target-controlled HTML and JavaScript are treated as untrusted application data.

Raw page text and HTML never cross the worker evidence schema. All exported target-controlled
strings are bounded and tagged under an evidence record whose `content_trust` is fixed to
`untrusted_target_content`.

This is a data-plane rule, not an LLM prompt convention. A future model may consume only the
validated structured graph/evidence projection and must never treat target content as system,
tool, authorization, credential, or policy instructions.

## Network confinement

The browser plan binds:

- target scheme;
- normalized hostname;
- port;
- segment-aware path boundary;
- full authorized resolution snapshot;
- one selected approved IPv4;
- worker image digest;
- signed release identity;
- request/page/depth/delay budgets.

Immediately before sandbox creation VulnHunter re-resolves the hostname. The current result must
remain a non-empty subset of the authorization snapshot and must still contain the selected IPv4.

OpenSandbox then receives:

```text
defaultAction = deny
egress = allow <approved IPv4 only>
```

The browser independently rejects any request whose scheme, hostname, port, or path leaves the
plan. Chromium receives a hostname-to-pinned-IP resolver rule so the browser does not make an
independent trust-changing DNS choice for the target.

OpenSandbox's current rule surface is IP-level rather than port-level, so the browser policy also
enforces the exact port. This limitation must remain explicit.

## Browser hardening

The worker:

- runs as UID/GID `65532`;
- runs only inside the outer OpenSandbox/Docker isolation boundary;
- keeps the outer runtime's dropped capabilities and `no_new_privileges=true` policy;
- deliberately disables Chromium's nested Linux namespace sandbox because that sandbox requires
  namespace operations blocked by the outer no-new-privileges/container profile;
- must therefore never be run directly on a host or in a broadly privileged container;
- blocks service workers;
- blocks WebSockets before connection;
- disables downloads;
- disables background networking where supported;
- uses no target-controlled command strings;
- receives its plan through a read-only JSON file;
- emits one bounded JSON result file;
- is destroyed after every execution.

Playwright documents `chromium_sandbox` as disabled by default. Its separate recommendation for
untrusted Docker crawling uses a non-root user together with a seccomp profile that explicitly
permits user-namespace operations. VulnHunter intentionally keeps a stricter outer OpenSandbox
profile instead of granting those namespace operations merely to enable an additional nested
Chromium sandbox.

The worker container pins both the Python base image by OCI SHA-256 and the Playwright Python
package version. Runtime authority remains the exact signed worker OCI digest.

## Application Surface Graph

The graph is deterministic and structure-only.

Node classes:

- `page`
- `endpoint`
- `form`
- `script`

Edge classes:

- `links_to`
- `requests`
- `submits_to`
- `loads_script`

Node and edge identifiers are SHA-256 hashes of canonical typed identities. The final graph hash
is computed over sorted canonical nodes and edges, excluding timestamps.

Forms include field names, input types, and `required` state only. **Values do not exist in the
schema.**

Network entries include GET/HEAD method, sanitized URL, resource type, and optional status code.
Bodies and headers do not exist in the schema.

## Authorization

`run_authorized_web_perception` reuses the existing `validate_scan_authorization` contract.
Requested page/depth/request/delay limits must remain within the active authorization record
before the browser backend can create a sandbox.

The existing append-only authorization events are reused:

```text
validated
-> scan_started { collector = playwright_passive_perception }
-> scan_completed | scan_failed
```

A browser plan's authorization identifier becomes part of its immutable plan fingerprint, but
the plan itself does not create permission.

## Signed worker release

The Playwright backend requires an exact `approved` worker record from the existing Ed25519
signed OpenSandbox release registry.

Local CI generates an ephemeral signed release only to prove the runtime trust path.

This batch deliberately does **not** extend the production GHCR publisher from PR #150 to
Playwright. Production publication, GitHub attestations, offline promotion, and durable release
evidence for this worker remain a separate promotion step after this foundation is reviewed.

## Acceptance proof

The private-lab acceptance target deliberately contains:

- a POST form with a secret-looking value;
- a read-only API request returning a secret-looking response body;
- a JavaScript POST request;
- an out-of-path GET request;
- a WebSocket attempt;
- an in-scope profile link.

The acceptance gate must prove:

- the exact private target is reachable;
- another otherwise reachable IP is blocked by `dns+nft`;
- the read-only API and profile page are reached;
- POST mutation, form submission, WebSocket handshake, and out-of-path request never reach the
  target;
- secret markers do not appear in exported evidence;
- form/script/endpoint/page graph nodes exist;
- plan, evidence, and graph hashes are present;
- the signed approved worker release is selected before execution;
- the sandbox is destroyed.

## Explicitly deferred

This foundation does not yet:

- persist the surface graph into the main scan/Assessment database;
- expose a browser-perception CLI or browser UI action;
- authenticate into applications;
- click application controls;
- submit any form;
- run vulnerability-specific hunters;
- send graph data to an LLM;
- perform continuous/differential rescans;
- publish the Playwright worker through the production GHCR candidate workflow.

Those capabilities should be layered only after this passive evidence boundary is stable and the
concurrent repository work has been reconciled.
