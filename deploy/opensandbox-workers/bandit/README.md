# OpenSandbox Bandit Worker

This image is the first real scanner workload for VulnHunter's OpenSandbox execution backend.
It is deliberately narrow: one offline, read-only Bandit scan against an approved regular Python
source file.

## Security contract

- Bandit is pinned to `1.9.4` at image build time.
- Runtime execution is non-root (`uid=65532`, `gid=65532`).
- VulnHunter accepts the built image only as `registry/repository@sha256:<digest>`.
- The OpenSandbox backend creates the sandbox with deny-by-default egress.
- The VulnHunter host stages only the already-approved regular target file.
- The worker receives immutable argv data through the fixed in-sandbox Python runner; model or
  user text is never interpolated into the OpenSandbox shell command.
- Output remains bounded and is copied back only when it matches a declared evidence path.
- VulnHunter performs redaction and evidence hashing after transfer.
- The sandbox is destroyed after success or failure.

This image is not a network scanner and must not be used for Nuclei, Nmap, public targets,
containers, Android devices, JADX, Apktool, or arbitrary command execution.

## Build

```bash
docker build \
  -f deploy/opensandbox-workers/bandit/Containerfile \
  -t vulnhunter-opensandbox-bandit:1.9.4 \
  .
```

A production or acceptance build must be pushed to a registry and consumed by its immutable
repository digest, for example:

```text
registry.example/vulnhunter/bandit@sha256:<64 hex characters>
```

Do not configure `:latest` or another tag as `VULNHUNTER_OPENSANDBOX_BANDIT_IMAGE`.

## Activation

OpenSandbox remains disabled unless explicitly enabled:

```bash
export VULNHUNTER_OPENSANDBOX_ENABLED=true
export VULNHUNTER_OPENSANDBOX_DOMAIN=localhost:8080
export VULNHUNTER_OPENSANDBOX_PROTOCOL=http
export VULNHUNTER_OPENSANDBOX_BANDIT_IMAGE='registry.example/vulnhunter/bandit@sha256:...'
```

Plain HTTP is accepted only for a loopback OpenSandbox control plane. A remote control plane must
use HTTPS. The OpenSandbox SDK reads its API key from `OPEN_SANDBOX_API_KEY`; VulnHunter does not
store that key in repository configuration.

## Licensing

Bandit is Apache-2.0 licensed. APKiD was intentionally not selected as the bundled first worker
because its upstream project uses a GPL/commercial dual-license model; APKiD can be integrated
later only after the chosen distribution model is reviewed.
