# Manual Installation Runbook

## Safety gate

No command in this document has been executed. Manual installation is allowed
only after the canonical roadmap reconciliation passes and a distinct human
approves the exact dependency, version, hashes, license, resource budget, and
rollback. Installation never authorizes a target or activates an adapter.

## Graphify CLI learning dependency

### Purpose

Install an isolated, pinned Graphify CLI only for a bounded code-only learning
period. Graphify output is advisory and may not control authorization, scope,
policy, code modification, shell execution, or final findings.

### Preconditions

1. Restore and reconcile the non-empty canonical master plan.
2. Independently inspect tag `v0.9.12`, its dependency lock/metadata, package
   hashes, security policy, and MIT license.
3. Record the approved wheel SHA-256. Do not proceed without it.
4. Confirm at least 500 MiB free under `/mnt/vulnhunter-data`.
5. Confirm no provider API keys are exported in the installation/run shell.

### Estimated impact

- Core wheel: approximately 1-2 MB based on adjacent official releases.
- Isolated environment: conservatively budget up to 200 MB before inspection.
- Generated graph/cache: repository-dependent; cap at 500 MB for the learning
  period.
- Runtime: potentially CPU-heavy; use one worker on this 2-CPU VM.
- RAM: cap the process at 2 GiB.
- Network: required for package installation only; code-only extraction must
  run without a remote backend.
- Sudo: not required.
- Credentials: prohibited for the code-only learning period.

### Exact installation command

Replace `<APPROVED_WHEEL_SHA256>` only with the independently recorded official
wheel digest. The placeholder intentionally makes this command non-executable
until provenance review is complete.

```bash
python3 -m venv /mnt/vulnhunter-data/tools/graphify-0.9.12 && \
  /mnt/vulnhunter-data/tools/graphify-0.9.12/bin/python -m pip install \
    --require-hashes \
    "graphifyy==0.9.12 --hash=sha256:<APPROVED_WHEEL_SHA256>"
```

Expected result: an isolated `graphify` executable exists only under
`/mnt/vulnhunter-data/tools/graphify-0.9.12/bin/`; no project files, shell
profiles, agent skills, Git hooks, MCP configuration, services, or providers are
modified.

### Verification command

```bash
env -i HOME="$HOME" PATH="/mnt/vulnhunter-data/tools/graphify-0.9.12/bin:/usr/bin:/bin" \
  GRAPHIFY_QUERY_LOG_DISABLE=1 \
  /mnt/vulnhunter-data/tools/graphify-0.9.12/bin/graphify --version
```

Expected result: exactly the approved `0.9.12` version is reported. Any network
call, hook installation, skill installation, MCP registration, daemon start, or
provider selection fails the readiness gate.

### Learning-period execution constraints

- Use only the upstream code-only extraction mode after confirming the exact
  installed CLI syntax with `graphify extract --help`.
- Run against an approved copy or read-only repository root.
- Write only to a dedicated untracked output directory.
- Use a clean environment with provider keys removed.
- Set `GRAPHIFY_QUERY_LOG_DISABLE=1`.
- Do not run `graphify install`, hook commands, MCP service commands, URL/media
  ingestion, PR commands, remote backends, graph database pushes, or HTTP mode.
- Hash every input snapshot and output graph; record omissions and errors.
- Compare Graphify relations with deterministic repository facts before use.

### Rollback command

After preserving approved learning evidence outside the tool directory:

```bash
rm -rf -- /mnt/vulnhunter-data/tools/graphify-0.9.12
```

Verification after rollback:

```bash
test ! -e /mnt/vulnhunter-data/tools/graphify-0.9.12
```

### Readiness state

`MANUAL_INSTALL_REQUIRED`. It is not installed, approved, activated, or ready.

## Large and system dependencies

Docker/Podman, Android emulator images, MobSF, Frida, Ghidra, local model
weights, PostgreSQL, Redis, a privileged broker, reverse proxy, and production
services remain manual or resource-deferred. Exact commands are intentionally
withheld until a concrete version/source/license/security decision is recorded;
the current VM does not need them for safe local code progress.
