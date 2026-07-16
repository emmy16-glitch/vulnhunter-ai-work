# Security Tool Integration and Deployment-Readiness Audit

Date: 2026-07-15
Branch: `milestone-27-integrated-intelligence-machine-oracle`
Recorded baseline: `c0f853275bf0b9598f962e0dd81cc997aa13fc01`

## Installation evidence

- Package integrity: every `checksums.sha256` and manifest payload record passed.
- Dry run: exact target verified; 17 files pending; no file changed.
- Installer: exited 0; automatic backup retained; rollback did not occur.
- Installer gates: compile passed; 32 focused tests passed; Django check passed;
  migration drift check reported no changes; all 14 required tools reported ready.
- Readiness report: `var/readiness/security-tool-integration.json`.
- Safety state: execution, scans, connectors, and external activation remain disabled.

## Repair phase evidence

### Phase 1 — bounded execution output and artifact integrity

Confirmed defect: the disabled-by-default executor used `capture_output=True`,
which buffered tool output before truncation, and artifact hashing used unbounded
`read_bytes()` while permitting tool-created symlink traversal.

Repair: stdout and stderr now spool to temporary files and are accepted only
within the plan byte limit. Artifact hashing is streaming and bounded, rejects
non-regular files and symlinks, rejects artifacts outside both the governed
working directory and approved evidence root, and keeps execution disabled by
default.

Evidence: `27 passed in 6.74s`; changed-file Ruff passed; changed-file format
check passed; `git diff --check` passed.

### Phase 2 — explicit deployment trust and readiness

Confirmed defect: deployment host and CSRF origin trust were hard-coded to a
wildcard tunnel domain even though an environment-list parser already existed.
Malformed boolean settings also silently evaluated false, which could disable a
requested HTTPS control without an operator-visible configuration failure.

Repair: host/origin trust is now environment-controlled with loopback-only
defaults; malformed booleans and bounded integers fail settings initialization;
trusted proxy handling is explicit and off by default; static/log settings are
deployment configurable; `.env.example` contains no credential; and `/ready/`
returns 503 unless the Django database and security-tool runtime configuration
are usable. Deployment and backup/rollback boundaries are documented in
`docs/setup/DEPLOYMENT_READINESS.md`.

Evidence: six changed-path deployment tests passed (17 deselected); changed-file
Ruff and format checks passed; `git diff --check` passed. A production-like Django system check
reported no issues. `django check --deploy` reported `security.W021` because
HSTS preload remains deliberately false until a real domain has met the browser
preload programme's difficult-to-reverse operational requirements. HSTS
subdomains were subsequently made explicit and default-off for the same reason;
the final deployment check must report its exact warning set.

### Phase 3 — bounded APK integrity verification

Confirmed defect: duplicate APK and isolated-workspace integrity checks loaded
the complete APK with `Path.read_bytes()`, despite the accepted artifact limit
being as high as 1 GB on a 9 GB VM.

Repair: APK integrity hashes now stream in 1 MiB chunks. Intake remains
content-addressed; archive validation, read-only workspace copies, and the rule
that APKs are never executed on the host are unchanged.

Evidence: the first focused command stopped during test collection because the
new test imported a non-exported helper from the package root. The test import
was corrected to the defining module without changing the public API. The rerun
passed all 15 focused mobile tests in 6.20s; Ruff, format, and `git diff --check`
then passed.

## Detailed capability map

| Capability | Current implementation | Entry point | Service/package | Persistence model | API or web route | Template/UI | Authorization gate | Scope gate | Approval requirement | Evidence output | Audit event | Tests | Configuration | Operational status | Remaining blocker |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Identity and roles | Authenticated governance identities plus versioned product roles/skills | Governance CLI; web login | `governance`, `roles`, `web.services` | SQLite identities/events; JSON registry | Authenticated role/skill routes | Roles, skills, denied page | Active mapped identity and allowed product action | Not applicable | Sensitive role actions retain policy approval points | Identity/role records | Governance event ledger | governance, role, web tests | `config/roles`, Django auth | CODE_READY | Deployment user provisioning and secret management |
| Target authorization | Explicit expiring/revocable authorization records and limit checks | Authorization CLI/service | `authorization` | SQLite records and append-only events | Campaign/service paths; no public mutation API | Campaign/readiness pages | Named issuer/actor contracts | Authorization target/path/limit matching | Authorization is separate from approval | Authorization decision and events | Redacted authorization events | authorization and governance workflow tests | Authorization DB path | CODE_READY | Real authorized target records |
| Technical scope | Approved target and derived URL validation with connection-time pinning | Scanner/scope services | `scope`, `scanner` | Immutable models plus request audit records | Existing CLI/service scan paths | Readiness blockers | Authorization checked separately before scan creation | Scheme/host/port/path, DNS and peer pinning | Consequential actions remain approval controlled | Bounded HTTP evidence | Connection/request audit events | scope, redirect, safe-client and pinning tests | Scanner policy | CODE_READY | Live target authorization and controlled network environment |
| Action policy and manifests | Immutable hash-bound actions, limits, roles, skills and deterministic decisions | Advanced/mobile planners and policy service | `actions` | Pydantic contracts | Read-only planning surfaces | Advanced/mobile profile pages | Role/skill/action checks | Exact target/authorization references bound | Consequential/sensitive classes require approval | Manifest and decision hashes | Downstream ledgers carry manifest hash | governed-action and planner tests | Advanced/mobile profiles | CODE_READY_DISABLED | Concrete activation workflow |
| Approval Centre | Maker-checker decisions, expiry, conditions, one-time exact-hash consumption | Approval service/store; `/approvals/` | `approvals` | Transactional SQLite plus per-request hash chain | Authenticated list/detail/POST decision routes | Approval Centre/detail forms | Active governed identity; store rejects requester self-approval | Canonical plan facts revalidated at consumption | Human decision required where manifest says so | Approval/evaluation hashes | Hash-chained approval events | approval centre/condition/web tests | Approval DB path | CODE_READY | Human approvers and production retention policy |
| Evidence and audit | Hash-chained evidence records, artifact hashes, governance/agent/activity audit ledgers | Evidence store and runtime services | `evidence`, `agent_activity`, `governance` | JSONL, SQLite and append-only files | Authenticated dashboard/activity/status | Dashboard, run timeline, readiness | Read permissions plus active identity | Artifact must remain inside evidence root | Evidence does not substitute for approval | Hashed artifacts/records | Multiple integrity-checked ledgers | evidence, activity, governance tests | Evidence/activity roots | CODE_READY | Persistent storage, backup and retention policy |
| Independent review and release | Two-reviewer consensus, distinct adjudication, immutable attestations and release manifest | Governance/review CLI/services | `review`, `governance`, `observations` | SQLite review decisions, attestations, manifest | Campaign/readiness views | Campaign/readiness pages | Assigned active reviewers; conflicts excluded | Campaign/scan/authorization bindings | Human review and release gates mandatory | Final labels and release manifest | Governance events/attestations | review, governance and readiness tests | Governance/scan DBs | CODE_READY | Human reviewers and real campaign evidence; publication remains human-gated |
| Finding lifecycle | Deduplicated candidates, verification state, remediation and CAS retest history | Finding service/store | `findings` | SQLite with fingerprint uniqueness and revision CAS | Read-only overview | Findings overview | Read route gated; mutation service not exposed publicly | Campaign/evidence references | Human analyst decision required for meaning/severity | Finding/evidence references | Store revision history in current record | finding lifecycle tests | Deployment DB choice required | CODE_READY_FOUNDATION | Live tool-to-finding ingestion activation and human workflow |
| Task graph | Immutable node bindings, DAG validation, revision CAS, atomic writes, bounded leases/recovery | Task graph store and planners | `taskgraph` | Locked atomic JSON | No public mutation API | Run views consume agent state | Lease never grants authorization | Manifest hash is immutable per node | Waiting-for-human state supported | Node/graph fingerprints | Graph history via revisioned state | taskgraph tests | Task graph root | CODE_READY_FOUNDATION | Supervised worker activation only if needed |
| Agent runtime | Bounded proposals, policy, retries, stale binding checks, pause/stop/cancel and evidence-bound completion | Agent CLI/controller | `agent` | SQLite task/audit store plus activity ledger | Run list/detail/activity/stop | Assessment run pages | Permission manifest and governed web actor | Tool contracts receive bounded context | Approval-bound actions pause; caller references rejected | Tool/evaluation records | Hash-checked agent/activity audit | agent controller/policy/store/web tests | `config/agent_runtime` | CODE_READY_LOCAL | No external model/tool activation |
| Security-tool catalog/readiness | Definitions, discovery, bounded version probes and ordered two-worker bulk policy | Status/dependency scripts; `/security-tools/` | `security_tools.catalog` | Machine-readable readiness JSON | Authenticated registry route | Security Tool Registry | Read route requires audit/scan read | No scan target involved | Readiness never grants approval | Version/status report | Install/readiness report | 32 installer tests plus integration regressions | Tools root; runtime JSON | READY_DISABLED | None for readiness; execution activation remains separate |
| Command planning/execution | Fixed shell-free adapters, target validation, disabled executor, injected authorizer, isolation, time/output/artifact bounds | `SecurityToolExecutor.plan/execute` | `security_tools.adapters`, `executor`, `targets` | Immutable request/plan/result models | No execution route | Registry truthfully says no scan starts | Mandatory production authorizer; disabled without it | Approved input/output roots; activation authorizer must enforce canonical scope | Plan approval flag and one-time consumption input | Bounded captures and hashed artifacts | Result carries manifest/plan/evidence hashes | governance/integration executor tests | `execution_enabled=false` | CODE_READY_DISABLED | Reviewed authorizer/evidence recorder, authorized targets and explicit activation |
| Parsing and normalization | Nmap XML, JSONL and structured parsers produce candidate findings tied to source hash | `normalize_execution_findings` | `security_tools.integration`, `parsers` | Immutable normalized records; raw artifact remains authority | No direct route | Findings overview is status-only | Only accepted execution results should enter activation pipeline | Target reference retained | Normalization cannot approve/confirm | Candidate finding records | Execution evidence hash retained | parser/integration tests | Tool output formats | CODE_READY_FOUNDATION | Activation-time durable EvidenceStore/FindingStore transaction |
| Advanced assessment | Hash-bound multi-tool action manifests and sequential DAGs | `AdvancedAssessmentPlanner` | `advanced` | Contract/task graph | `/advanced-assessment/` is read-only | Advanced profile cards | Planned roles/skills | Target and authorization references bound | Profile/tool classes drive approval | Planned manifests/graph | Downstream only | advanced-assessment tests | `config/advanced/profiles.json` | PLANNING_FOUNDATION | Governed request/persistence/execution activation |
| Mobile/Android | Safe content-addressed APK intake, static/native/dynamic planning, connector contracts, parsers/correlation | `/mobile-analysis/`; mobile planner | `mobile`, security-tool adapters | Read-only APK plus JSON metadata; planned DAG | Authenticated GET/POST upload | Mobile upload, profile and artifact list | Governed identity/action gate | Exact APK ID/hash/path binding; dynamic device/runtime refs | Dynamic/MobSF/Ghidra/ADB/Frida require approval/isolation | APK hashes, metadata, mobile findings | Planned manifest hashes | 15 focused mobile tests plus web tests | Mobile roots/profiles/runtime flags | STATIC_INTAKE_READY_EXECUTION_DISABLED | Mobile-tool readiness, isolated emulator/device and explicit activation |
| Machine Oracle | Proof capsules, deterministic verifier, authenticated connector contract, durable replay/session CAS | Oracle services | `oracle` | Transactional SQLite sessions/replay state | `/machine-oracle/` read-only | Oracle readiness page | Oracle cannot authorize/approve | Capsule target/scope/evidence bindings | Human confirmation remains mandatory | Capsule/verdict hashes | Session history/replay ledger | Machine Oracle tests | Disabled connector contract | CODE_READY_DISABLED | External verifier, protected authentication keys and isolation |
| Reports | Protected-field rejection and deterministic JSON/HTML/SARIF/ZIP/SVG artifacts | Report exporter/service | `reports` | Files plus immutable artifact metadata | `/reports/` read-only | Report format status | Report read action | Approved evidence roots for ZIP | Publication still governed elsewhere | Artifact SHA-256 and provenance | Caller must attach to campaign audit | report export tests | Deployment output root not globally activated | CODE_READY_FOUNDATION | Authenticated download/publishing workflow and optional PDF renderer |
| Web application | Django auth, CSRF, CSP, secure cookies, role-gated routes, error/empty states, liveness/readiness | WSGI, `/health/`, `/ready/` and authenticated routes | `web`, `product` | Django DB plus domain stores | Named web routes; activity JSON only | 28 templates; no missing/dead template references found | Login, active identity and role action | Service-specific | Approval POST delegates to store enforcement | Read-only status and governed mutations | Domain stores | web/template/service tests | Strict env settings; `.env.example` | CODE_READY_FOR_HOSTING | Hosting, exact hosts/origins, TLS/proxy, secret and persistent volumes |
| External providers/Graphify/MCP/broker | Fail-closed contracts only; no credentials or command broker | Package services only | `providers`, `repository_graph`, `privileged_broker` | Typed records/local state where present | Status documentation only | Truthful status pages | Explicit activation policy | Project/path/action binding contracts | Human approval required | Contract evidence only | Contract audit fields | focused provider/graph/broker tests | Disabled/default absent | INTENTIONALLY_DISABLED | Credentials, reviewed installs, learning period, local MCP decision, privileged service |

## Targeted defect search summary

- Critical: none confirmed.
- High, repaired: readiness probe over-concurrency; unbounded executor capture and
  artifact/symlink acceptance.
- Medium, repaired: implicit wildcard tunnel trust and permissive environment
  parsing; whole-APK integrity reads on a constrained VM.
- Expected `pass` hits were exception classes; expected `return None` hits were
  optional-value/model helpers. No `shell=True`, unjustified skipped tests, or
  missing rendered templates were found.
- Template audit compiled all 28 templates, found 26 rendered templates with no
  missing or unreferenced application template, and found 22 URL names with no
  missing route.
- Project audit inventoried 306 Python files, 93 test files and 88 Markdown files;
  its only warning was the intentionally dirty review worktree.

## Explicitly deferred operational requirements

| Requirement | Status | Why it is not a code-readiness claim |
| --- | --- | --- |
| Hosting, domain/DNS, TLS and reverse proxy | EXTERNAL_PREREQUISITE | No deployment or public exposure was authorized. |
| Production secret and operator accounts | CREDENTIAL_REQUIRED | Credentials must be generated and stored outside Git. |
| Database/storage volumes, monitoring and tested backups | EXTERNAL_PREREQUISITE | Deployment topology and retention policy are operator choices. |
| Security-tool execution | ACTIVATION_REQUIRED | Readiness does not provide target authorization, scope, approval or authorizer wiring. |
| Authorized live targets | CREDENTIAL_REQUIRED | Permission and current scope evidence must be created by humans. |
| Dynamic APK/emulator/device/MobSF/Frida/Ghidra | RESOURCE_DEFERRED | Requires isolated resources, tool readiness and exact approval. |
| Machine Oracle / pentest-ai | ACTIVATION_REQUIRED | Requires an independent service, isolation and protected authentication keys. |
| Local/cloud models and provider APIs | CREDENTIAL_REQUIRED / RESOURCE_DEFERRED | No model download, provider credential or privacy approval was authorized. |
| Graphify learning period | MANUAL_INSTALL_REQUIRED | Installation and learning evidence precede any native reliance. |
| Restricted MCP service | LATE_STAGE_GATED | Optional after the learning period; public MCP remains excluded. |
| Privileged broker | MANUAL_INSTALL_REQUIRED | Separate service/allowlist/human grant required; no sudo path exists here. |
| Finding publication | ACTIVATION_REQUIRED | Human confirmation, severity decision and release gate remain authoritative. |

### Phase 4 — completion-validator environment detection

Confirmed defect: `scripts/validate_manual_completion.py` looked for a standalone
`pytest` executable on `PATH`, so it returned 2 and skipped tests even when run
with a project interpreter that could import and execute pytest.

Repair: validator dependency detection now uses `importlib.util.find_spec`, then
continues to invoke the fixed `python -m pytest` command. The initial failure is
retained as evidence. The rerun compiled the source, passed all 25 completion
tests in 10.14s, passed Django check, and exited 0.

## Final acceptance evidence

- Full repository suite: `636 passed in 888.44s (0:14:48)`; exit 0.
- Repository-wide Ruff: all checks passed.
- Repository-wide Ruff format check: 393 files already formatted.
- `git diff --check`: passed.
- `python -m compileall -q vulnhunter`: passed with an external bytecode cache.
- Django system check: no issues.
- Migration drift: no changes detected.
- Static asset lookup: `web/app.css` resolved; collectstatic dry-run passed.
- Production-like `django check --deploy`: exit 0 with expected warnings W005
  and W021 because HSTS subdomains/preload remain explicit, domain-dependent,
  difficult-to-reverse hosting choices.
- Final standard-tool readiness: all 14 ready; `not_ready=[]`; execution remains
  false; report refreshed at `var/readiness/security-tool-integration.json`.
- Package integrity: every top-level checksum and manifest payload digest passed
  after target-style import/format corrections; focused test count remains 32.

## Verdict

`CODE_READY_WITH_DOCUMENTED_EXTERNAL_PREREQUISITES`

The code, local web surface, governed foundations, standard-tool registration,
and disabled execution boundary pass their deterministic gates. Hosting and the
explicit operational items above remain because they require infrastructure,
credentials, isolated resources, authorized targets, and independent human
decisions—not because they have been simulated or silently enabled.
