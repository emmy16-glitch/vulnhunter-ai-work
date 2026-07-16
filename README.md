# VulnHunter AI

VulnHunter AI is an authorised, laboratory-only security research project.

## Current milestone

The current repository now includes:

- Safe target-scope validation
- Passive website mapping
- Non-destructive HTTP inspection
- Sanitised observation storage
- Governed campaign and review workflows
- Bounded agent runtime and activity timeline foundations
- Controlled pilot-plan validation
- A local authenticated Django operational web surface
- A controlled scanner-manager protocol and disabled Nuclei execution harness
- Central scanner version/feed compatibility tracking
- A disabled, networkless isolated scanner-worker container boundary

It does not exploit vulnerabilities, perform public scanning, or train a model
automatically.

## Safety boundary

The tool will only permit localhost, loopback addresses, RFC1918 private networks,
and explicitly approved laboratory targets.

Public Internet scanning and destructive testing are rejected by design.

## Local web startup

The authenticated browser surface runs on loopback only. Follow
[`docs/product/WEB_APPLICATION.md`](docs/product/WEB_APPLICATION.md) for the
exact startup sequence, including a locally generated
`VULNHUNTER_WEB_SECRET_KEY`, database migration, local user creation, and
`python manage.py runserver --insecure 127.0.0.1:8000`.

Here, `--insecure` is only Django's loopback local-development static-file
option. It must not be used for public or production deployment.

## Governed security operations foundation

Milestone 26 adds disabled-by-default foundations for persistent human approvals,
hash-bound action manifests, durable task graphs, evidence integrity, local-first
provider routing, owner break-glass contracts, and a registry of free security
assessment tools. The installer does not download tools, run scans, enable
connectors, create credentials, or change the laboratory-only authorization
boundary.

See:

- `docs/adr/0018-governed-security-tool-orchestration.md`
- `docs/product/GOVERNED_SECURITY_OPERATIONS.md`
- `config/security_tools/runtime.json`

## Governed Android APK analysis

The same milestone also adds a disabled-by-default mobile application security
foundation. An authenticated operator can upload an APK into content-addressed
storage, after which the mobile analysis planner can select fixed adapters for
JADX, Apktool, Android SDK metadata tools, APKiD, YARA, Androguard, MobSF,
radare2, Ghidra, ADB, and Frida.

Uploading an APK does not execute it. Static tools remain disabled until a
reviewed runtime configuration enables them. Dynamic analysis requires an
explicit approval and a disposable isolated Android runtime; the uploaded APK
must never be executed directly on the VulnHunter host.

See:

- `docs/adr/0019-governed-android-apk-analysis.md`
- `docs/product/MOBILE_APPLICATION_SECURITY.md`
- `config/security_tools/runtime.json`

## Milestone 27 integrated intelligence foundations

Milestone 27 adds contract-only foundations for Machine Oracle verification, proof capsules, disabled-by-default `pentest-ai` authenticated response validation, repository coverage, deterministic-first AI routing, attack-path graphs, analyst feedback, improvement proposals, and protected report artifacts. These foundations do not activate external tools, APK execution, model providers, live connectors, privileged brokers, or scans.

## Manual completion package

The post-Milestone-27 completion modules are validated with:

```bash
python3 scripts/validate_manual_completion.py
```

Optional external tool readiness can be inspected without installing or
activating anything:

```bash
python3 scripts/dependency_readiness.py
```

See `docs/intelligence/MANUAL_COMPLETION_RELEASE.md` for delivered code and
`docs/setup/POST_INSTALL_ACTIVATION_PLAN.md` for remaining manual activation
steps.

## Hosting preparation

Production hosting is deliberately external to this repository. Use
[`docs/setup/DEPLOYMENT_READINESS.md`](docs/setup/DEPLOYMENT_READINESS.md) and
`.env.example` to configure exact hosts/origins, HTTPS/proxy trust, persistent
state, readiness checks, backups, and rollback without enabling scanners or
other deferred integrations.

## Milestone 31 controlled scanner harness

Milestone 31 separates scanner management from the future isolated worker, adds
a shared scanner protocol for Nuclei, planned OpenVAS, and planned mobile
analysis, and implements a persistent Nuclei lifecycle with bounded redacted
evidence. Production execution remains blocked and no scanner process or target
connection is created.

See:

- `docs/intelligence/MILESTONE_31_CONTROLLED_NUCLEI_EXECUTION_HARNESS.md`
- `docs/product/SCANNER_ARCHITECTURE.md`
- `docs/product/SCANNER_COMPATIBILITY.md`
- `config/security_tools/scanner_compatibility.json`
- `deploy/scanner-worker/`
