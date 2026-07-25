# VulnHunter

VulnHunter is an authorised, laboratory-only security assessment and verification platform. It combines deterministic tools, evidence provenance, human authority and a conversational workspace without granting an AI model execution or approval power.

## Current product state

The repository currently provides:

- one responsive assessment workspace for authorised website and APK work;
- exact target, protocol, port, address and profile authorization;
- immutable Nuclei plans with digest-bound confirmation or approval;
- a signed manager-to-worker spool with replay and expiry protection;
- a passive-only private-lab Nuclei worker pilot;
- a restricted SSH bridge for an operator-owned worker host;
- bounded timeout, cancellation, redaction and restart recovery;
- evidence normalization into candidate findings;
- deterministic verification and proof capsules;
- one finding lifecycle with independent review, adjudication and release gates;
- optional sanitized Groq advisory analysis that is disabled by default;
- resumable APK upload and a networkless, read-only mobile static-analysis worker;
- a controlled synthetic Active Validation workspace;
- shared desktop, tablet and mobile product styling;
- automated Python, browser, conversational and genuine private-lab acceptance checks.

The canonical website-assessment path is:

```text
Pre-existing authorization or self-controlled private-lab authorization
→ immutable passive plan
→ exact plan confirmation
→ signed worker job
→ passive private-lab scan
→ bounded evidence
→ candidate finding
→ deterministic verification
→ optional controlled active validation
→ human review
→ governed release
```

Exact passive-plan confirmation is limited to the immutable, authorised passive plan displayed to the run owner. Higher-risk actions, public-target authorization, active validation, review, adjudication and publication retain their separate human-control requirements.

Scanner observations, deterministic verification, optional controlled validation and optional advisory analysis are consolidated into one finding record. Tool and provider details remain evidence provenance and audit metadata rather than separate competing findings.

## Authorization boundary

Conversational authorization creation is restricted to self-controlled private-network laboratory targets. Public targets cannot be authorised from chat. They must already be covered by an exact, independently approved authorization record before VulnHunter can prepare a plan.

The default passive worker accepts a reviewed literal RFC1918 target and reviewed passive template with rate limit `1`, concurrency `1`, no redirects, no public OAST, no cloud upload, no automatic updates, no headless execution, and no code or file templates.

Public Internet scanning and destructive testing remain prohibited.

## Default safety state

A normal repository checkout does not automatically:

- install, enable or start a Nuclei worker;
- contact a target;
- create authorization for a public target;
- provision a signing key or SSH identity;
- alter `authorized_keys`;
- activate Groq or store its key;
- execute an uploaded APK;
- start MobSF, an emulator, ADB or Frida;
- enable controlled learning;
- enable the controlled validation worker in production;
- deploy PostgreSQL, TLS, DNS or a reverse proxy;
- publish a finding without human review.

The manager remains fail-closed. A browser request cannot install a scanner, enable a worker, change reviewed template trust, expand scope or grant itself authority. The Codespaces devcontainer is an explicit operator-selected private-lab environment that prepares local prerequisites outside the browser.

## Unified web workspace

Assessment-capable accounts enter the conversational workspace at `/`. Website and APK work begin there. The former standalone New Assessment route redirects to it, while the historical Mobile APK Analysis URL remains only as a compatibility alias that renders the same workspace, navigation and backend flow.

The shared authenticated shell provides:

- role-aware navigation;
- exact authorization, scope, approval and active-state visibility;
- chat-based planning and status requests;
- exact passive-plan confirmation;
- assessment history;
- a website/APK assessment inspector;
- evidence, findings, verification and remediation disclosures;
- responsive desktop, tablet and mobile behaviour.

The interface must display persisted values only. Unknown progress, unavailable tools, empty evidence and blockers are shown explicitly rather than replaced with fabricated counts or percentages.

Follow [`docs/product/WEB_APPLICATION.md`](docs/product/WEB_APPLICATION.md) for local startup and web architecture.

## Phone-only private laboratory with Codespaces

A private GitHub Codespace can prepare the complete passive private-lab path for an authenticated phone browser. The environment checksum-verifies the pinned Nuclei release, prepares the reviewed template set, owner-private signing key, signed spool, separate worker process, deliberate RFC1918 test target and real evidence pipeline. Termux is used only to control the private Codespace; no desktop is required.

Follow [`docs/setup/PHONE_ONLY_PRIVATE_LAB.md`](docs/setup/PHONE_ONLY_PRIVATE_LAB.md) and [`docs/setup/CODESPACES_PHONE.md`](docs/setup/CODESPACES_PHONE.md).

## Worker architecture

The manager/worker architecture is documented in:

- `docs/product/SCANNER_ARCHITECTURE.md`
- `docs/product/SCANNER_COMPATIBILITY.md`
- `docs/setup/NUCLEI_WORKER_PILOT.md`
- `docs/setup/REMOTE_NUCLEI_WORKER.md`
- `config/security_tools/nuclei_worker_pilot.example.json`
- `config/security_tools/remote_nuclei_worker.example.json`
- `config/security_tools/remote_nuclei_host.example.json`
- `deploy/scanner-worker/`

The operator must provide the pinned executable, reviewed policy, owner-private signing key, restricted transport identity when remote transport is used, and an authorised private-laboratory target before activation.

## Mobile analysis

APK upload is resumable, validates the final archive and SHA-256 digest, and stores the artifact without executing it. The static worker can run fixed, bounded, read-only tools against a private copy when its worker policy is enabled.

The worker records each tool receipt independently. A single tool failure does not create a finding and does not automatically stop later tools; integrity and resource-boundary failures stop the assessment safely.

Large-APK support includes staging quotas, free-disk preflight, abandoned-upload cleanup and explicit storage-full failures. A full medium or large APK acceptance run is still required before claiming that every configured mobile tool completes successfully in a particular Codespace.

MobSF and dynamic APK execution remain separate private-service and disposable-emulator prerequisites. ADB and Frida remain gated until an authorised runtime identity is registered.

See `docs/product/MOBILE_APPLICATION_SECURITY.md`.

## Controlled learning

Controlled learning is disabled by default. New memory candidates always enter as `pending_review`; promoted retrieval requires a real promotion record after human review and deterministic evaluation. Learning records remain advisory and cannot authorize, execute, verify, change severity or publish.

Do not enable learning in an environment that has not completed its governance identity, retention, metadata-redaction and database-recovery review.

## Controlled active validation

A persisted finding can open a nested Active Validation workspace. The built-in worker uses reviewed synthetic scenarios, generated test data, no network egress, independent approval, password re-authentication, clean-snapshot retries, a hard maximum of ten trials, evidence hashes, cancellation checkpoints and verified cleanup.

The workspace displays genuine persisted activity such as policy checks, snapshot restoration, trial state, evidence processing and cleanup. It does not display hidden reasoning or fabricated progress.

See `docs/product/ACTIVE_VALIDATION.md`.

## Advisory analysis

VulnHunter is model-provider neutral. Optional remote advisory providers are non-authoritative. Groq is the currently implemented provider; it is disabled by default, receives sanitized bounded content only, has no tools, cannot authorize or verify a finding, and returns proposals or `ABSTAIN`.

Deterministic verification and human review continue when no model is configured. See `docs/intelligence/ADR_003_MODEL_PROVIDER_NEUTRALITY.md`.

## Verification expectations

A green CI run proves only the behaviours exercised by that run. The repository quality gates cover Python 3.11 and 3.12, linting, formatting, repository policy, responsive browser behaviour, conversational workflows and a genuine private-lab Nuclei acceptance.

Before production or public use, complete additional acceptance for the intended deployment, including:

- the actual medium or large APK and complete configured static toolchain;
- private MobSF when enabled;
- disposable emulator, ADB and Frida when enabled;
- public-authorization independence;
- database backup and restore;
- TLS, DNS, PostgreSQL, monitoring and incident response;
- an independent security review.

## Production preparation

`deploy/production/compose.example.yaml` is a reviewed deployment example, not an active deployment. It keeps the web service on loopback, uses an internal database network, mounted secret files, a read-only application filesystem, dropped capabilities and resource limits. Controlled validation remains disabled and networkless in the example.

Complete `docs/setup/DEPLOYMENT_READINESS.md` before production use.
