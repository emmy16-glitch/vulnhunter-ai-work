# OpenSandbox Execution Backend

## Status

OpenSandbox is VulnHunter's isolated **execution plane**. It does not replace
VulnHunter authorization, scope validation, immutable command planning, evidence
hashing, human review, or reporting.

The base backend supports offline regular-file workloads. The first real worker
activation is **Bandit 1.9.4** for governed Python source-file scanning. Network,
container-image, Android-device, and directory-artifact execution remain blocked.

## Security objective

The existing `SecurityToolExecutor` provides governed command plans,
pre-execution authorization, shell-free local execution, output limits, redaction,
and evidence hashing. OpenSandbox adds a disposable operating-system execution
boundary while keeping VulnHunter authoritative:

```text
request
  -> target and authorization validation
  -> immutable CommandPlan + SHA-256 fingerprint
  -> pre-execution authorization revalidation
  -> OpenSandbox backend
  -> digest-pinned non-root worker
  -> fixed sandbox runner
  -> shell=False tool argv
  -> bounded evidence transfer
  -> existing redaction + hashing
  -> deterministic normalization
  -> review/reporting
```

Models, chat input, and browser requests never receive authority to bypass this
chain.

## Backend-aware planning

A managed execution backend may provide the executable identity used to build a
command plan. This removes the old requirement that a scanner also be installed on
the VulnHunter web/control host.

For the first activated backend:

```text
bandit -> /usr/local/bin/bandit
```

If a configured backend does not provide a runtime for a requested tool, planning
fails closed. It does not silently fall back to a host scanner.

Local execution and older backends without a managed executable resolver preserve
the previous catalog-detection behavior.

## First worker: Bandit 1.9.4

The image definition lives at:

```text
deploy/opensandbox-workers/bandit/Containerfile
```

The worker is deliberately narrow:

- Bandit is pinned to version `1.9.4` at build time;
- execution uses numeric UID/GID `65532:65532`;
- runtime CPU is limited to `1` and memory to `512Mi`;
- the scanner target is one already-approved regular file;
- the runtime has deny-by-default OpenSandbox egress;
- no scanner credentials are present in the image;
- output is accepted only at declared evidence paths;
- the disposable sandbox is destroyed after success or failure.

Bandit was selected as the first bundled worker because it is an offline static
scanner already supported by VulnHunter and is Apache-2.0 licensed. APKiD remains a
possible later externally provided worker, but its GPL/commercial dual-license model
requires an explicit distribution/licensing decision before VulnHunter bundles it.

## Runtime image contract

Every activated tool requires an explicit `OpenSandboxRuntimeSpec` with:

- an image reference pinned by `@sha256:<digest>`;
- an absolute executable path inside the worker image;
- a non-root UID and GID;
- explicit CPU and memory limits;
- Python 3 available as `python3` for the fixed runner.

Tagged images such as `scanner:latest` are rejected at activation time.

The final built image digest is the runtime identity. Production image publication
still has additional supply-chain responsibilities. Before production promotion,
record and verify at minimum:

- immutable worker image digest;
- build source/commit;
- base-image digest;
- SBOM;
- scanner package/binary version and digest where practical;
- signature/provenance attestation;
- rollback image digest.

The current worker Containerfile pins Bandit but names the Python base image by tag;
therefore a signed production image-publish workflow with a resolved base digest,
SBOM, and provenance is still required before treating the image as a released
production artifact.

## Activation configuration

Activation is environment-controlled and **disabled by default**:

```text
VULNHUNTER_OPENSANDBOX_ENABLED=false
VULNHUNTER_OPENSANDBOX_DOMAIN=localhost:8080
VULNHUNTER_OPENSANDBOX_PROTOCOL=http
VULNHUNTER_OPENSANDBOX_BANDIT_IMAGE=
VULNHUNTER_OPENSANDBOX_MAX_INPUT_BYTES=50000000
```

When enabled, `VULNHUNTER_OPENSANDBOX_BANDIT_IMAGE` must be an immutable repository
digest. A mutable tag is rejected.

Plain HTTP is accepted only when the OpenSandbox control plane is loopback. A remote
control plane must use HTTPS. The OpenSandbox SDK obtains its optional API key from
`OPEN_SANDBOX_API_KEY`; secrets are not stored in VulnHunter runtime configuration.

`build_opensandbox_backend_from_environment()` returns `None` when disabled and a
strict `ConfiguredOpenSandboxExecutionBackend` when the activation contract is
satisfied.

## Shell boundary

OpenSandbox's command API accepts command text. VulnHunter must not convert
model/user-controlled argv into shell text.

The backend sends only this fixed command to OpenSandbox:

```text
python3 /tmp/vulnhunter/control/runner.py
```

The authorized argv is transferred separately as JSON. The fixed runner reads the
JSON and invokes the tool with `subprocess.Popen(..., shell=False)`. Target paths and
output paths are translated to sandbox-local paths before transfer.

## Network policy

Offline workers are created with OpenSandbox egress `defaultAction=deny` and no allow
rules. The genuine acceptance workflow uses the OpenSandbox Docker runtime in bridge
mode with the official execd/egress components so this network policy crosses the
real control-plane boundary rather than a fake SDK.

Network scanners remain blocked. VulnHunter's target authorization is address-aware;
network activation requires proof that sandbox egress can enforce the exact approved
IP/CIDR destination set, including DNS, redirects, TLS/Host identity, and connection-
time behavior. Do not weaken that rule just to run Nmap or Nuclei inside a sandbox.

The backend therefore fails closed for:

- `ToolTargetKind.NETWORK`;
- `ToolTargetKind.CONTAINER_IMAGE`;
- `ToolTargetKind.ANDROID_DEVICE`.

## File staging and evidence

Only an exact regular-file target under one of `approved_input_roots` is staged.
Symlink targets, directory targets, oversized inputs, and unstaged additional host
paths fail closed.

The sandbox runner records:

- return code;
- timeout state;
- bounded stdout/stderr files;
- declared regular-file outputs and exact sizes;
- runner/artifact failures.

The host accepts only planned artifacts, then applies the existing VulnHunter
redaction, output-root checks, hashing, and normalization pipeline. A sandbox
destruction failure prevents a successful backend return.

Directory-output tools such as `apktool` and `jadx` remain blocked until bounded,
symlink-safe recursive artifact transfer is implemented and tested.

## Genuine acceptance

`scripts/opensandbox_bandit_acceptance.py` exercises the intended product path:

```text
synthetic authorised source fixture
  -> SecurityToolRequest
  -> SecurityToolExecutor.plan
  -> backend executable identity (no host Bandit required)
  -> immutable CommandPlan
  -> OpenSandbox server
  -> digest-pinned Bandit worker
  -> Bandit JSON evidence
  -> VulnHunter evidence hashing
  -> normalize_execution_findings
  -> acceptance receipt
```

`.github/workflows/opensandbox-worker.yml` adds two checks:

1. a hardened Docker smoke test using no network, read-only root filesystem,
   dropped capabilities, no-new-privileges, non-root execution, and a read-only
   fixture mount;
2. a genuine OpenSandbox acceptance that builds the worker, pushes it to an
   ephemeral local registry, resolves the repository digest, starts a local
   OpenSandbox Docker control plane, and executes the complete VulnHunter path.

The acceptance-only authorizer in that script is restricted to the synthetic CI
fixture. It is not a production authorization mechanism.

## Installation

OpenSandbox remains optional for normal VulnHunter development:

```bash
python -m pip install -e '.[opensandbox]'
```

The project currently pins the OpenSandbox Python SDK to `0.1.15` for the backend
adapter. The genuine worker workflow exercises the integration against a separately
pinned OpenSandbox server version and must remain green before that server version is
promoted as the tested deployment pair.

## Not yet complete

OpenSandbox integration does **not** resolve every isolation requirement. Remaining
work includes:

- signed production worker publication, SBOM, provenance, and rollback records;
- bounded directory staging/output transfer;
- an IP/CIDR-capable confinement design for authorized network scanners;
- unattended-runner migration;
- repository/autoresearch worktree migration;
- stronger runtime profiles such as gVisor/Kata/Firecracker where required;
- production scheduler/worker transport and health/readiness integration;
- additional scanner workers added one at a time with their own acceptance evidence.
