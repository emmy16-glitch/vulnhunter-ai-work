# Milestone 31 — Controlled Nuclei Execution Harness

## Purpose

Milestone 31 prepares a governed scanner execution boundary without activating
Nuclei or any other scanner. It separates scanner management from the Django
web process, introduces a versioned scanner-control protocol, and implements a
fail-closed Nuclei harness whose production runner always stops at
`blocked_execution_disabled`.

No Nuclei process, OpenVAS process, mobile-analysis process, target connection,
DNS lookup, template update, cloud upload, public OAST request, or external
scanner job is created by this milestone.

## Architecture

```text
Django assessment and approval control plane
        |
        | immutable, approved, versioned request
        v
ScannerAdapter protocol v1.0
        |
        +-- Nuclei controlled harness (implemented, execution blocked)
        +-- OpenVAS adapter (planned, unavailable)
        +-- Mobile-analysis adapter (planned, unavailable)
        |
        v
Future isolated scanner worker
        |
        +-- no web-process subprocess ownership
        +-- no unrestricted shell or argv
        +-- no process environment or raw secret persistence
        +-- no activated transport in Milestone 31
```

The common contracts live in
`vulnhunter/security_tools/scanner_protocol.py`. The Nuclei-specific harness
lives in `vulnhunter/security_tools/nuclei_execution.py`. The disabled worker
entry point and container boundary live in
`vulnhunter/security_tools/scanner_worker.py` and `deploy/scanner-worker/`.

## Scanner protocol and independent adapters

Protocol version `1.0` defines:

- scanner and adapter identities;
- adapter status and deployment mode;
- version and feed pins;
- bounded execution limits;
- lifecycle states;
- candidate observations;
- evidence references;
- terminal adapter results;
- one manager-side adapter registry.

Nuclei, future OpenVAS integration, and future mobile-analysis integration use
this same manager contract. Only the Nuclei harness adapter exists as executable
Python logic, and its production runner is still disabled. OpenVAS and mobile
entries are explicit planned adapters that return a typed blocked result.

## Central version and feed management

`config/security_tools/scanner_compatibility.json` is the central compatibility
manifest. It records:

- scanner ID;
- adapter ID and adapter version;
- protocol version;
- engine version when selected;
- feed or template release when selected;
- repository manifest path and SHA-256 when available;
- adapter status;
- intended deployment mode.

The Nuclei record pins engine `v3.11.0`, template release `v10.4.5`, and the
SHA-256 of the reviewed repository template manifest. The OpenVAS and mobile
records deliberately show that engine and feed versions have not yet been
selected. Missing pins do not silently fall back to a latest release.

## Immutable execution request

`NucleiExecutionRequest` is frozen and extra fields are forbidden. It binds:

- execution, authorization, approval, cancellation, and correlation IDs;
- exact command-plan digest;
- exact validated targets and address pins;
- exact profile;
- exact template-manifest hashes;
- approved evidence directory;
- expiry;
- bounded timeout, stdout, stderr, rate, and concurrency limits;
- compatibility-manifest digest;
- optional opaque secret-provider ID;
- `execution_enabled: false`.

It has no command string, arbitrary `argv`, process environment, credentials,
headers, proxy credentials, API token, cloud token, or raw secret field.

## Lifecycle

The closed lifecycle is:

```text
PREPARED
  -> VALIDATED
  -> BLOCKED_EXECUTION_DISABLED

Test-only deterministic paths:
VALIDATED -> STARTING -> RUNNING
  -> COMPLETED | FAILED | CANCELLED | TIMED_OUT

Cancellation path:
STARTING | RUNNING -> CANCELLING -> CANCELLED | FAILED | TIMED_OUT
```

Invalid transitions are rejected. Every state transition records:

- sequence number;
- execution ID;
- authorization ID;
- plan digest;
- previous and new state;
- timestamp;
- actor identity;
- sanitized reason;
- correlation ID;
- previous event SHA-256;
- current event SHA-256.

Transition ledgers are append-only and hash linked. Current records are written
atomically with restrictive file permissions.

## Pre-execution revalidation

Immediately before the runner boundary, the harness rechecks:

- global execution remains disabled;
- request, plan, authorization, and approval identities match;
- plan digest still matches the plan contents;
- authorization is active;
- request and plan have not expired;
- approval is active and bound to the exact plan digest;
- exact targets, protocols, ports, paths, and address pins are unchanged;
- current resolver output remains within the approved address set;
- profile remains authorized;
- template hashes remain unchanged;
- output directory remains below the approved evidence root;
- no symlink component or path traversal exists;
- request rate and concurrency equal the approved plan;
- compatibility manifest has not changed;
- engine and template versions match the central pins;
- readiness evidence is no more than 15 minutes old.

Any mismatch fails closed before a runner is called.

## Runner boundary

### DisabledNucleiRunner

The production runner:

- imports no subprocess launcher;
- opens no network connection;
- ignores no policy decision;
- returns `blocked_execution_disabled`;
- produces a typed, bounded audit summary;
- cannot be changed to enabled through request input.

### DeterministicFakeRunner

The fake runner exists only for unit tests and requires explicit test-only
construction. It performs no subprocess or network operation and supports
controlled success, failure, cancellation, and timeout paths. Fake observations
are permanently typed as `candidate`.

## Cancellation and timeout

Execution requests contain a cancellation ID and bounded timeout. Cancellation
requests are idempotent. The runner contract receives the existing
`NucleiRunControl` interface, which defines monotonic deadlines, cooperative
checkpoints, bounded termination grace, and future whole-process-group
termination.

No operating-system signal is sent in the production path because no scanner
process can exist in Milestone 31.

## Output and evidence safety

Stdout and stderr are:

- redacted before persistence;
- bounded independently;
- UTF-8 safe;
- marked when truncated;
- content addressed.

The harness writes one bounded NDJSON execution summary inside the approved
output directory using no-follow and exclusive-create semantics. The artifact
is redaction verified and SHA-256 addressed. Raw environment variables,
commands, request headers, secrets, and complete network responses are not
stored.

Scanner observations remain candidates. The harness cannot create a confirmed,
published, or human-approved finding.

## Persistence and recovery

The store persists the request, state, deadline, cancellation flag, last event
digest, bounded captures, candidate observations, and evidence references.

On restart, unfinished `prepared` or `validated` records recover to
`blocked_execution_disabled`. Records that had reached `starting`, `running`,
or `cancelling` recover to `failed`. The system never assumes an external
process survived a restart.

## Isolated container boundary

`deploy/scanner-worker/` contains a disabled deployment skeleton. It:

- runs separately from Django;
- uses a non-root user;
- uses a read-only filesystem;
- removes all Linux capabilities;
- enables `no-new-privileges`;
- limits CPU, memory, PIDs, and temporary storage;
- uses `network_mode: none`;
- contains no Nuclei or OpenVAS binary;
- starts no listener;
- validates compatibility data and exits with code `78`.

The Compose service is behind the explicit `disabled-scanner-worker` profile.
It is evidence of process separation, not scanner activation.

## Release discipline

Milestone 31 adds:

- a central compatibility manifest;
- a generated compatibility matrix contract;
- a changelog entry;
- a release and migration policy;
- versioned protocol and adapter schemas;
- documentation updates in the same change as architecture updates.

No database migration is required because the harness uses new file-backed
state and does not change an existing persistent SQL schema.

## Still disabled

- real Nuclei subprocess execution;
- worker transport or job queue;
- Nuclei binary installation;
- template download or automatic update;
- non-empty reviewed template selection;
- OpenVAS execution;
- mobile dynamic execution;
- public or private target scanning;
- public Interactsh/OAST;
- ProjectDiscovery cloud upload;
- headless, JavaScript, code, file, and self-contained template execution;
- secret retrieval;
- UI execution controls.

## Deferred

A later milestone must separately review and implement:

- authenticated manager-to-worker transport;
- signed worker images and software-bill-of-materials evidence;
- an unprivileged real Nuclei launcher that consumes only validated internal
  specifications;
- exact connection-time redirect and DNS enforcement inside the worker;
- approved template population and signature verification;
- secret-provider integration without argv, log, or model exposure;
- local-lab acceptance testing;
- OpenVAS protocol adapter and Greenbone feed lifecycle;
- mobile static and dynamic worker adapters;
- database-backed multi-worker scheduling and recovery;
- UI controls only after all execution gates are independently reviewed.
