# OpenSandbox Nuclei Worker

This image is VulnHunter's first live website-scanning workload for the OpenSandbox execution plane.
It is deliberately narrow: passive HTTP/HTTPS assessment of one already-authorized URL using the
reviewed VulnHunter template bundle baked into the image.

## Security contract

- Nuclei is pinned to `3.8.0`; the Linux amd64 release archive is verified against the reviewed
  SHA-256 before it enters the runtime image.
- The worker image itself is accepted by VulnHunter only as `repository@sha256:<digest>`.
- The reviewed template manifest identity is bound into the immutable `CommandPlan`.
- The template bundle is copied into `/opt/vulnhunter/templates` at image build time and is not
  updated or downloaded during a scan.
- User/model input cannot provide raw Nuclei arguments, template URLs, headers, proxies, public
  OAST, cloud upload, local-file access, DAST server mode, code templates, or file templates.
- The first OpenSandbox network worker forces the reviewed `vulnhunter` tag and HTTP protocol
  templates, disables redirects and httpx probing, and uses the fixed low-concurrency policy from
  VulnHunter's existing Nuclei adapter.
- Before authorization, a hostname target is resolved to one deterministic IPv4 destination and
  that destination, scheme, hostname, port, worker image, and template manifest are fingerprinted
  in the command plan.
- Immediately before sandbox creation, hostname DNS is resolved again. If the pinned IPv4 is no
  longer present, execution fails closed.
- Nuclei receives an IP-based connection URL. For hostname URLs, VulnHunter derives the `Host`
  header and HTTPS SNI internally; user-provided headers remain blocked.
- OpenSandbox receives a default-deny network policy with only the pinned IPv4 destination
  allowed. The OpenSandbox server must run egress mode `dns+nft`; `dns` mode alone is not accepted
  for this worker deployment.
- The fixed in-sandbox Python runner launches the authorized argv with `shell=False` as
  UID/GID `65532:65532`.
- Output is bounded, copied back only for declared evidence paths, hashed by VulnHunter, and the
  disposable sandbox is destroyed after success or failure.

## Current network limitation

The current OpenSandbox `NetworkRule` API binds a network target but does not expose a separate
port field. Therefore the kernel/network boundary is exact-IP, while the immutable Nuclei argv
binds the exact scheme and port and redirects are disabled. VulnHunter does **not** claim a
kernel-level port allowlist in this iteration. A future target relay or an upstream port-aware
network rule can strengthen this without changing authorization semantics.

## Build

```bash
docker build \
  -f deploy/opensandbox-workers/nuclei/Containerfile \
  -t vulnhunter-opensandbox-nuclei:3.8.0 \
  .
```

For activation, push the image to a registry and configure the immutable repository digest:

```bash
export VULNHUNTER_OPENSANDBOX_ENABLED=true
export VULNHUNTER_OPENSANDBOX_DOMAIN=localhost:8080
export VULNHUNTER_OPENSANDBOX_PROTOCOL=http
export VULNHUNTER_OPENSANDBOX_NUCLEI_IMAGE='registry.example/vulnhunter/nuclei@sha256:...'
```

Remote OpenSandbox control planes must use HTTPS. The OpenSandbox API key remains environment-only
through `OPEN_SANDBOX_API_KEY` and must not be committed.

## Deliberately not enabled here

- unrestricted community-template execution
- Nmap or arbitrary network tools
- intrusive/headless/JavaScript Nuclei profiles
- redirects to additional hosts
- public OAST/Interactsh
- scanner/template self-update
- arbitrary headers or proxy configuration
- IPv6 targets
- port-level nftables policy
- automatic public-target execution without VulnHunter authorization
