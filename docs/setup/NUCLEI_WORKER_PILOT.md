# Passive Nuclei Worker Pilot

This runbook activates one passive private-laboratory worker after the code release has passed independent review. It does not authorize a target or install a scanner automatically.

## Preconditions

- the target is owned or explicitly authorized;
- the target uses a literal RFC1918 address;
- the authorization contains the exact protocol, port, address and passive profile;
- the reviewed Nuclei executable matches the compatibility manifest;
- the reviewed pilot template directory matches `nuclei_template_manifest.json`;
- the worker runs separately from the Django web process;
- the operator can stop and destroy the worker environment;
- backup and evidence-retention rules are approved.

## 1. Prepare worker files

Copy these reviewed files into the worker boundary:

- the pinned Nuclei executable;
- `config/security_tools/pilot_templates/`;
- `config/security_tools/nuclei_template_manifest.json`;
- `config/security_tools/scanner_compatibility.json`;
- a reviewed copy of `nuclei_worker_pilot.example.json`.

Set the real executable and template-root paths in the worker policy. Keep `enabled=false` until every remaining step passes.

## 2. Create the signing key

Create the key as the unprivileged application/worker identity. Do not place it in the repository or command history.

```bash
umask 077
python -c 'import secrets,sys; sys.stdout.buffer.write(secrets.token_bytes(48))' \
  > "$HOME/.vulnhunter-nuclei-worker-key"
chmod 600 "$HOME/.vulnhunter-nuclei-worker-key"
```

Mount the same key read-only into the manager and worker. The job file contains only an HMAC signature, never the key.

## 3. Configure paths

Set deployment environment variables to private persistent paths:

```text
VULNHUNTER_NUCLEI_WORKER_SIGNING_KEY_FILE=/run/secrets/vulnhunter-nuclei-worker-key
VULNHUNTER_NUCLEI_WORKER_SPOOL_ROOT=/srv/vulnhunter/state/nuclei-worker-spool
VULNHUNTER_NUCLEI_WORKER_POLICY=/etc/vulnhunter/nuclei-worker-pilot.json
VULNHUNTER_NUCLEI_EXECUTION_ROOT=/srv/vulnhunter/state/nuclei-executions
VULNHUNTER_VERIFICATION_ROOT=/srv/vulnhunter/state/verification
VULNHUNTER_SCANNER_COMPATIBILITY_MANIFEST=/srv/vulnhunter/app/config/security_tools/scanner_compatibility.json
```

The manager’s enqueue flag must remain false during readiness checks.

## 4. Verify readiness

Run:

```bash
python scripts/validate_scanner_compatibility.py
python manage.py check
python -m pytest -q tests/unit/test_milestone32_worker_pilot.py
```

Verify that the worker policy, executable and template files are regular files, not symbolic links, and are not writable by untrusted users.

## 5. Enable the worker policy

Change only the worker-local reviewed policy to `enabled=true`. Do not expose that policy through the browser or assessment form.

Start the worker with:

```bash
python manage.py vh_run_nuclei_worker --once
```

With no pending job it must print that no signed job is pending and perform no network activity.

## 6. Enable manager enqueue

After the worker readiness check succeeds, set:

```text
VULNHUNTER_NUCLEI_PILOT_ENQUEUE_ENABLED=true
```

Restart the manager. Create one passive assessment for the authorized literal private address and approve the exact plan digest. The manager writes a signed job; it does not run Nuclei itself.

Run the worker once to process that job.

## 7. Acceptance evidence

Confirm all of these:

- the assessment changes from `awaiting_approval` to `queued`, then a terminal state;
- activity contains real `tool_execution_started` and terminal events;
- the worker receipt contains a terminal state and result hash;
- stdout and stderr are redacted and bounded;
- evidence exists only below the approved evidence root;
- scanner matches remain candidates;
- deterministic verification creates a proof capsule;
- the Findings page shows one consolidated finding record;
- Stop cancels a pending job or requests cancellation of a running job;
- restarting the worker fails stranded processing records closed;
- no secret, environment dump, raw authorization or signing key appears in evidence or logs.

## Rollback

1. Set `VULNHUNTER_NUCLEI_PILOT_ENQUEUE_ENABLED=false`.
2. Set the worker policy to `enabled=false`.
3. Stop the worker process.
4. Preserve signed jobs, receipts, evidence and audit records.
5. Revoke and replace the signing key when compromise is suspected.
6. Re-run readiness and integrity tests before any later activation.

Do not use this pilot against public Internet targets.
