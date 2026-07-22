# Governed Nuclei Integration

VulnHunter treats ProjectDiscovery Nuclei as an external evidence producer. It is
not an authorization authority and a template match is never a confirmed finding.

## Active private-lab path

The current implementation supports one controlled execution path:

```text
exact RFC1918 authorization
→ immutable passive plan
→ independent human approval bound to the plan digest
→ signed expiring worker job
→ isolated local worker or restricted remote worker
→ pinned Nuclei v3.8.0 and one reviewed template set v10.4.5
→ bounded, redacted JSONL evidence
→ candidate finding
→ deterministic verification
→ human review and governed release
```

A browser request cannot install a scanner, enable a worker policy, create a
signing key, expand scope, select arbitrary templates or supply command-line
arguments. Those are operator-owned deployment inputs.

## Implemented controls

- fixed shell-free command construction;
- exact target, protocol, port and frozen-address checks;
- literal RFC1918 private target requirement for the passive pilot;
- rate limit `1`, concurrency `1`, retries `0` and redirects disabled;
- official engine pin `v3.8.0`;
- reviewed template release `v10.4.5` with per-file SHA-256 verification;
- automatic updates, cloud upload and public Interactsh/OAST disabled;
- code, file, headless, JavaScript and generated templates blocked from the pilot;
- signed manager-to-worker spool with expiry and replay protection;
- process-group cancellation, timeout and bounded output;
- content-addressed evidence and candidate-finding normalization;
- deterministic verification and separate human review.

## Deployment states

Installation, activation and authorization are distinct:

1. **Installed** — the exact executable and template files are present.
2. **Verified** — the engine version, manifest release and file digests match.
3. **Worker enabled** — an owner-private policy and signing key are configured.
4. **Authorized** — the exact private target and passive profile are approved.
5. **Approved job** — a different identity approves the exact immutable plan.
6. **Executed** — the worker claims the signed job and produces evidence.

The normal repository checkout does not automatically contact a target. The
Codespaces phone-lab setup deliberately performs steps 1–3 during environment
creation, then creates a narrowly scoped local authorization when the operator
starts the lab. A real scan begins only after the operator creates a plan and an
independent approver approves it.

## Prohibited scope

Public Internet scanning, destructive testing, intrusive profiles, arbitrary
scanner flags, credentials in command arguments, public OAST, cloud upload and
unreviewed templates remain prohibited by the passive pilot.

See:

- `docs/setup/PHONE_ONLY_PRIVATE_LAB.md`
- `docs/setup/NUCLEI_WORKER_PILOT.md`
- `docs/setup/REMOTE_NUCLEI_WORKER.md`
- `docs/product/SCANNER_ARCHITECTURE.md`
