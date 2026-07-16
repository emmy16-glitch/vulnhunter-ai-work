# Governed Security Tool Integration

This integration registers the installed VulnHunter toolchain without enabling unrestricted execution.

## Registered direct adapters

- Network and web: Nmap, ProjectDiscovery httpx, Nuclei, ffuf, testssl.sh.
- Source and secrets: Bearer CLI, Bandit, detect-secrets, Gitleaks.
- Dependencies and SBOM: Trivy, Syft, Grype, OSV-Scanner.
- Binary capability analysis: capa.
- Existing Android static adapters remain available under their original gates.

Semgrep is no longer part of the active catalog because the installed binary cannot run on the current QEMU CPU model. Bearer is the primary multi-language SAST adapter.

## Activation boundary

`config/security_tools/runtime.json` deliberately keeps `execution_enabled` false. Installation and registration do not authorize scans. A later reviewed activation must supply:

- an execution authorizer;
- approved input and evidence roots;
- exact scope and role/skill validation;
- consumed approvals for network, image-pull, or sensitive actions;
- isolated runtime confirmation where required.

## Environment

Start VulnHunter from a shell that loads the tools path:

```bash
. .local/vulnhunter-web.env
. .local/vulnhunter-tools.env
.venv/bin/python manage.py runserver --insecure 127.0.0.1:8000
```

The registry page performs only bounded version probes and reports `ready`, `unusable`, `timed_out`, `detected_unverified`, or `not_detected`.

## Readiness probe policy

Bulk version checks use one ordered, CPU-aware policy shared by the catalog,
standard-tool report, and dependency report. The worker count is always at least
one and never exceeds two. This deliberate limit matches the two-core VM and avoids
resource-contention timeouts observed with the previous eight-worker fan-out.

The default version-probe timeout remains 20 seconds. Existing documented
exceptions remain bounded for tools with slower startup; measured `capa` startup
exceeded 20 seconds even in the two-worker batch. Bearer has no timeout exception.
Every probe remains shell-free, non-interactive, output-captured, and restricted to
the probe environment. Missing, timed-out, or non-zero probes are never reported as
ready, and readiness does not change `execution_enabled`.
