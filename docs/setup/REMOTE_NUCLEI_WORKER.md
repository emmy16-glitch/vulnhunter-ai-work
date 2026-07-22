# Milestone 33 — Restricted Remote Nuclei Worker

## Purpose

Milestone 33 lets the existing signed VulnHunter worker spool keep its governance
and evidence pipeline inside the QEMU application while the pinned Nuclei process
runs on a separately restricted Ubuntu host. This exists because the QEMU software
CPU cannot reliably execute the pinned Nuclei binary.

The remote bridge does not create a second authorization system. It reuses the
existing sequence:

```text
exact authorization
→ immutable passive plan
→ digest-bound human approval
→ signed expiring worker job
→ restricted SSH request
→ fixed host-side Nuclei command
→ bounded candidate observations
→ evidence verification
→ human review and governed release
```

## Security boundary

The guest controls authorization, approval, job signing, cancellation, evidence,
verification, findings, review, and release. The host forced command controls only
the fixed process invocation.

The host command accepts no shell text, arbitrary command, target, template,
header, cookie, credential, proxy, environment variable, or scanner flag. Both
sides independently bind the request to:

- one worker identity;
- one logical private-lab target;
- one loopback transport target;
- Nuclei `v3.8.0`;
- one reviewed passive template and SHA-256 digest;
- rate limit `1` and concurrency `1`;
- retries `0`, no redirects, no Interactsh, no update check, and no stdin;
- bounded runtime, response size, and candidate count.

Zero candidate observations is a successful completed scan, not a failure.
Scanner output remains candidate evidence and never becomes a confirmed finding
without deterministic verification and governed human review.

## Files

- `vulnhunter/security_tools/remote_nuclei_models.py` — typed contracts and policy.
- `vulnhunter/security_tools/remote_nuclei_worker.py` — restricted SSH runner.
- `vulnhunter/security_tools/remote_nuclei_service.py` — signed-spool integration.
- `vulnhunter/web/management/commands/vh_verify_remote_nuclei_worker.py` — readiness only.
- `vulnhunter/web/management/commands/vh_run_remote_nuclei_worker.py` — process one signed job.
- `scripts/remote_nuclei_forced_command.py` — host forced command.
- `scripts/install_remote_nuclei_worker.sh` — owner-only, no-sudo installer.
- `config/security_tools/remote_nuclei_worker.example.json` — guest policy example.
- `config/security_tools/remote_nuclei_host.example.json` — host policy example.

## Installation

Copy the two example policies outside Git and replace every placeholder. Keep both
files owner-private (`chmod 600`). Set `enabled` to `true` only after the exact
paths, target mapping, engine version, and template digest have been verified.

On the host, run the no-sudo installer from the repository root:

```bash
bash scripts/install_remote_nuclei_worker.sh \
  --host-policy "$HOME/.config/vulnhunter/remote_nuclei_host.source.json" \
  --public-key /path/to/vulnhunter_guest_to_host_ed25519.pub
```

The installer:

- copies the forced command under `~/.local/libexec`;
- copies the policy under `~/.config/vulnhunter` with mode `0600`;
- backs up `authorized_keys`;
- preserves unrelated keys;
- installs one forced-command key with forwarding, PTY, agent, user-RC, and X11 disabled;
- never uses sudo.

## Guest configuration

Point the guest application at its owner-private policy:

```bash
export VULNHUNTER_REMOTE_NUCLEI_WORKER_POLICY="$HOME/.config/vulnhunter/remote_nuclei_worker.json"
```

Keep the existing manager-side prerequisites configured:

```bash
export VULNHUNTER_NUCLEI_PILOT_ENQUEUE_ENABLED=true
export VULNHUNTER_NUCLEI_WORKER_SIGNING_KEY_FILE=/absolute/owner-private/key
export VULNHUNTER_NUCLEI_WORKER_SPOOL_ROOT=/absolute/spool
```

The browser cannot activate these settings.

## Readiness verification

Readiness verifies SSH host-key pinning, dedicated-key authentication, the host
policy, executable, Nuclei version, template file, and template digest. It does
not contact the target:

```bash
python manage.py vh_verify_remote_nuclei_worker
```

A valid response contains genuine request and result SHA-256 digests.

## Process one signed job

After an authorized plan has been approved and enqueued:

```bash
python manage.py vh_run_remote_nuclei_worker
```

The command claims at most one signed job. It verifies the signature, expiry,
authorization, approval, pins, limits, template selection, and remote response
binding before producing evidence or candidate findings.

## Current private-lab mapping

The reviewed local laboratory used during development is:

```text
logical target:   http://10.0.2.15:8002
host transport:   http://127.0.0.1:18002
```

That mapping belongs in machine-local policy, not committed source. Public targets,
hostnames, intrusive templates, cloud upload, OAST, headless execution, code
templates, destructive testing, and arbitrary scanner flags remain prohibited.

## Recovery after shutdown

The SSH port forward and QEMU host forward can disappear after a host restart.
Restore the existing private forwards before running readiness. Do not weaken
`StrictHostKeyChecking`, replace the dedicated identity with a general-purpose
key, or expose the QEMU service publicly.
