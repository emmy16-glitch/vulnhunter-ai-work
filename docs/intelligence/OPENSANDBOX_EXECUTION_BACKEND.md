# OpenSandbox Execution Backend

## Status

This document describes the first fail-closed OpenSandbox integration for VulnHunter.
It is an execution backend only. It does not replace VulnHunter authorization,
scope validation, command planning, evidence hashing, review, or reporting.

The implementation is intentionally limited to offline, regular-file workloads in
this first batch. Network-target, container-image, Android-device, and directory-
artifact execution remain blocked by the backend.

## Security objective

The existing `SecurityToolExecutor` already provides governed command plans,
pre-execution authorization, shell-free local execution, output limits, redaction,
and evidence hashing. Its local process path still shares the host operating-system
boundary unless the operator provides an external isolated runtime.

The OpenSandbox backend adds a disposable execution boundary while preserving the
existing control-plane contract:

```text
request
  -> target and authorization validation
  -> immutable CommandPlan + SHA-256 fingerprint
  -> pre-execution authorization revalidation
  -> OpenSandbox backend
  -> non-root fixed runner
  -> shell=False tool argv
  -> bounded evidence transfer
  -> existing redaction + hashing
  -> review/reporting
```

## Why network scanners are blocked initially

VulnHunter's network authorization boundary is address-aware and is designed around
loopback and approved private laboratory address ranges. The OpenSandbox Python SDK
currently documents egress rules in terms of FQDN and wildcard-domain targets.
That is not sufficient evidence that the sandbox can enforce VulnHunter's exact
approved IP/CIDR set for scanners such as Nmap or Nuclei.

Therefore the OpenSandbox backend currently fails closed for:

- `ToolTargetKind.NETWORK`;
- `ToolTargetKind.CONTAINER_IMAGE`;
- `ToolTargetKind.ANDROID_DEVICE`.

Do not remove that block merely to make a network scanner run. Network activation
requires a reviewed design that proves destination-IP confinement, redirect and DNS
behavior, and compatibility with VulnHunter's existing target authorization model.

## Shell boundary

OpenSandbox's command API accepts a command string. VulnHunter must not convert
model/user-controlled argv into shell text.

The backend therefore sends only this fixed command to OpenSandbox:

```text
python3 /tmp/vulnhunter/control/runner.py
```

The authorized argv is transferred separately as JSON. The fixed runner reads that
JSON and invokes the tool with `subprocess.Popen(..., shell=False)`. Target paths and
output paths are translated to sandbox-local paths before transfer.

## Runtime image contract

Every activated tool requires an explicit `OpenSandboxRuntimeSpec`.

The first implementation requires:

- an image reference pinned by `@sha256:<digest>`;
- an absolute executable path inside the worker image;
- a non-root UID and GID;
- explicit CPU and memory limits;
- Python 3 available as `python3` for the fixed runner.

Tagged images such as `scanner:latest` are rejected.

The worker image itself remains a VulnHunter supply-chain responsibility. Before a
production runtime is registered, record and verify at minimum:

- image digest;
- build source/commit;
- SBOM;
- scanner binary digest and version;
- feed/template/ruleset provenance where applicable;
- signature/provenance verification result;
- rollback image digest.

## Network policy

The first backend creates sandboxes with OpenSandbox egress `defaultAction=deny` and
no allow rules. This is intentional for offline static analysis.

## File staging

Only an exact regular-file target under one of `approved_input_roots` is staged.
Symlink targets, directory targets, oversized inputs, and additional absolute host
input paths fail closed.

Current directory-output tools (`apktool` and `jadx`) remain blocked until bounded,
symlink-safe recursive artifact transfer is implemented and tested.

## Evidence behavior

The sandbox runner records:

- return code;
- timeout state;
- bounded stdout/stderr files;
- declared regular-file outputs and exact sizes;
- runner/artifact failures.

The host backend accepts only declared planned artifacts, then passes stdout/stderr
back through the existing VulnHunter redaction pipeline and passes artifacts through
the existing output-root and hashing checks.

The sandbox is destroyed in a `finally` path. A destruction failure prevents a
successful backend return.

## Installation

OpenSandbox is optional for normal VulnHunter development:

```bash
python -m pip install -e '.[opensandbox]'
```

The extra pins the OpenSandbox Python SDK to `0.1.15` for this integration contract.

The SDK reads its API key from `OPEN_SANDBOX_API_KEY`. The control-plane domain may
be supplied by `OpenSandboxConnection` or `OPEN_SANDBOX_DOMAIN`; the SDK default is
`localhost:8080`.

Do not commit API keys or other sandbox credentials to the repository.

## Initial activation sequence

1. Run the normal VulnHunter unit and quality gates with no OpenSandbox service.
2. Build one minimal offline worker image for a single static file scanner.
3. Sign it, generate an SBOM, and pin the verified image digest.
4. Register that image through `OpenSandboxRuntimeSpec`.
5. Run an end-to-end laboratory test against a synthetic file fixture.
6. Confirm sandbox destruction, non-root execution, network denial, evidence hashes,
   and failure behavior.
7. Expand one workload at a time.

## Not yet complete

This batch does **not** claim to resolve all sandbox-related technical debt.
Remaining work includes:

- production worker image builds and provenance;
- bounded directory staging/output transfer;
- an IP/CIDR-capable network confinement design for authorized scanners;
- unattended-runner migration;
- repository/autoresearch worktree migration;
- stronger runtime profiles such as gVisor/Kata/Firecracker where required;
- production scheduler/worker transport integration;
- end-to-end tests against a real self-hosted OpenSandbox service.
