# VulnHunter AI

VulnHunter AI is an authorised, laboratory-only security assessment and verification platform.

## Current milestone

Milestone 32 provides:

- exact target, protocol, port, address and profile authorization;
- immutable Nuclei plans and digest-bound human approval;
- a signed local manager-to-worker spool;
- a passive-only isolated Nuclei worker pilot;
- bounded timeout, cancellation, redaction and restart recovery;
- evidence normalization into candidate findings;
- deterministic verification and proof capsules inside each assessment;
- one unified finding lifecycle with human review and release gates;
- optional sanitized Groq advisory analysis that is disabled by default;
- a networkless, read-only mobile static-analysis worker;
- a controlled synthetic Active Validation workspace with up to ten clean-snapshot trials;
- responsive operational pages for assessments, findings, approvals, review, reports and audit;
- loopback-only production deployment examples with mounted secret files.

The active assessment path is:

```text
Authorization
→ immutable plan
→ exact human approval
→ signed worker job
→ passive private-lab scan
→ bounded evidence
→ candidate finding
→ deterministic verification
→ optional controlled active validation
→ human review
→ governed release
```

Scanner output, deterministic verification, optional controlled validation and optional advisory analysis are consolidated into one finding record. Tool and provider details remain available as evidence provenance and audit metadata rather than separate competing findings.

## Default safety state

The repository does not automatically:

- enable the Nuclei worker pilot;
- install or start a Nuclei binary;
- contact a target;
- provision a signing key;
- activate Groq or store its API key;
- execute an uploaded APK;
- start an emulator or dynamic Android laboratory;
- enable the controlled validation worker in production;
- deploy PostgreSQL, TLS, DNS or a reverse proxy;
- publish a finding without human review.

The default manager harness remains fail-closed. A browser request cannot enable scanner execution.

## Scope boundary

The passive worker pilot accepts exactly one approved literal RFC1918 address, one reviewed passive template, rate limit `1`, concurrency `1`, and no redirects, public OAST, cloud upload, automatic updates, headless execution, code templates or file templates.

Public Internet scanning and destructive testing remain prohibited.

## Local web startup

Follow [`docs/product/WEB_APPLICATION.md`](docs/product/WEB_APPLICATION.md). The local development surface binds to loopback and uses Django’s development server only for local testing.

## Worker pilot

The manager/worker architecture is documented in:

- `docs/product/SCANNER_ARCHITECTURE.md`
- `docs/product/SCANNER_COMPATIBILITY.md`
- `docs/setup/NUCLEI_WORKER_PILOT.md`
- `config/security_tools/nuclei_worker_pilot.example.json`
- `deploy/scanner-worker/`

The operator must provide the pinned Nuclei executable, reviewed worker policy, owner-private signing key and authorized private laboratory target before activation.

## Mobile analysis

APK upload validates and stores an artifact without executing it. The static worker can run fixed read-only metadata tools against a read-only copy when its worker policy is enabled. Dynamic APK execution remains a separate disposable-laboratory prerequisite.

See `docs/product/MOBILE_APPLICATION_SECURITY.md`.

## Controlled active validation

A persisted finding can open a nested Active Validation workspace. The built-in worker uses reviewed synthetic scenarios, generated test data, no network egress, independent approval, password re-authentication, clean-snapshot retries, a hard maximum of ten trials, evidence hashes, cancellation checkpoints and verified cleanup.

The workspace displays genuine persisted activity such as policy checks, snapshot restoration, trial state, evidence processing and cleanup. It does not display hidden reasoning or fabricated progress.

See `docs/product/ACTIVE_VALIDATION.md`.

## Advisory analysis

Groq is the only optional remote advisory provider. It is disabled by default, receives sanitized bounded content only, has no tools, cannot authorize or verify a finding, and returns non-authoritative proposals or `ABSTAIN`.

Deterministic verification and human review continue when Groq is unavailable.

## Production preparation

`deploy/production/compose.example.yaml` is a reviewed deployment example, not an active deployment. It keeps the web service on loopback, uses an internal database network, mounted secret files, a read-only application filesystem, dropped capabilities and resource limits. The controlled validation worker remains disabled and has no network namespace in the example.

Complete the separate TLS, DNS, PostgreSQL, backup, restore, monitoring and independent security-review gates in `docs/setup/DEPLOYMENT_READINESS.md` before production use.
