# Total Programme Repository Evidence Catalogue

## Status and scope

This is a preparatory inventory of the 50 capabilities and 25 phases explicitly
named in the total-programme prompts. It is derived from current repository
evidence and does not replace the missing non-empty canonical future master
plan. It does not pass the canonical reconciliation gate or claim
`UNMAPPED=0`.

## Explicit capability evidence

| ID | Capability | Repository evidence | Tests | Current classification | Missing work or activation gate |
| --- | --- | --- | --- | --- | --- |
| 1 | Model-agnostic Project Intelligence Pack | `AGENTS.md`; `docs/intelligence/`; `docs/product/`; `docs/adr/` | `test_project_audit.py`, documentation contract tests | PARTIAL | Restore the canonical master plan and add a machine-readable cross-document index. |
| 2 | Root AGENTS.md operating manual | `AGENTS.md` | `test_project_audit.py` | COMPLETE | Keep synchronized with enforced product boundaries. |
| 3 | Architecture, security-boundary, and product documentation | `SYSTEM_ARCHITECTURE.md`, `SECURITY_BOUNDARIES.md`, product blueprints | project audit and product specification tests | COMPLETE | Wave-specific status must remain truthful. |
| 4 | ADRs, experiments, roadmap, and technical debt | `docs/adr/0001` through `0020`; `EXPERIMENT_LOG.md`; `ROADMAP.md`; `TECHNICAL_DEBT.md` | project audit | COMPLETE | Continue append-only maintenance. |
| 5 | Controlled source ingestion | `vulnhunter/knowledge`; `SOURCE_INGESTION.md`; ADR 0005 | `test_knowledge_ingestion.py`, `test_knowledge_cli.py` | COMPLETE | Operational data remains local and human governed. |
| 6 | Immutable original-source preservation | `KnowledgeStore.register`; `knowledge/raw`; content hashing and restrictive writes | `test_knowledge_ingestion.py` | COMPLETE | External object storage is not required for local mode. |
| 7 | Source provenance and trust levels | `SourceManifest`, `TrustLevel`, source register | knowledge tests | COMPLETE | Connector provenance must later reuse this boundary. |
| 8 | Prompt-injection screening | `knowledge/injection.py`; review queue | prompt-injection ingestion tests | COMPLETE | Machine screening remains advisory and non-executing. |
| 9 | Contradiction tracking | source manifest contradictions and contradiction queue | knowledge ingestion tests | COMPLETE | Cross-source resolution workflow can be extended without deleting disagreement. |
| 10 | Human-reviewed knowledge publication | knowledge review and publish CLI/store gates | knowledge CLI and ingestion tests | COMPLETE | Authenticated web publication remains future work. |
| 11 | Controlled analyst feedback and learning | governed review/adjudication plus `analyst_feedback` records | review/governance tests; `test_milestone27_contracts.py` | PARTIAL | Bind feedback records to authenticated governed decisions and versioned datasets. |
| 12 | Bounded agent loop standard | `vulnhunter/agent`; `vulnhunter/orchestration`; ADRs 0008/0016 | agent and orchestration test families | COMPLETE | Production adapters remain separately gated. |
| 13 | Maker/checker separation | orchestration builder/verifier/reviewer/approver identities; governance reviewer separation | orchestration and governance workflow tests | COMPLETE | Preserve actor separation in all new waves. |
| 14 | Durable multi-agent task graph | `vulnhunter/taskgraph`; agent SQLite tasks; orchestration manifests | `test_taskgraph.py`, agent/orchestration tests | PARTIAL | Add one-primary-orchestrator specialist-worker ownership, leases, and recovery binding. |
| 15 | Role and skill registry | `vulnhunter/roles`; `config/roles`; ADR 0014 | role registry tests | CONTRACT_ONLY | All entries remain planned/untrusted until authenticated runtime activation. |
| 16 | Third-party skill import and trust framework | `ExternalDependency`, pinned references, hashes, connector policy | role model/loading/policy tests | CONTRACT_ONLY | No controlled import pipeline or quarantine/review executor exists. |
| 17 | Deterministic repository security-review harness | orchestration fixed verifiers; repository coverage inventory | orchestration and repository coverage tests | PARTIAL | Add incremental symbols/relationships, review rules, and impact queries. |
| 18 | Candidate observation versus verified finding separation | observations, governed review, Oracle verdicts, attack-path states | observations, review, governance, Oracle tests | COMPLETE | Unified finding lifecycle and UI remain incomplete. |
| 19 | Machine Oracle | `vulnhunter/oracle`; transactional session store | `test_machine_oracle.py` | PARTIAL | Production keys, authenticated live connector, and independent operational verifier are inactive. |
| 20 | Proof capsules | immutable `ProofCapsule` with evidence and authorization/scope bindings | Oracle tests | COMPLETE | External transport activation remains separate. |
| 21 | Pentest-ai interoperability | disabled `PentestAiConnector`, authenticator protocol, replay ledger | Oracle connector tests | ACTIVATION_REQUIRED | Install, authenticate, version-check, contract-test, and readiness-test externally. |
| 22 | Local-first Qwen provider architecture | provider registry/privacy gate plus deterministic `ai_routing` decisions | provider privacy and Milestone 27 contract tests | CONTRACT_ONLY | No Qwen runtime/model is installed or loaded. |
| 23 | Specialist cybersecurity model registry | generic provider and role registries only | provider/role tests | MISSING | Define model identity, provenance, capability, resource, privacy, and evaluation records. |
| 24 | Reproducible specialist-model benchmark harness | generic reviewed-data benchmark and grouped ML pipeline | benchmark/model-selection tests | PARTIAL | Add specialist model task suites without weakening hidden holdouts. |
| 25 | Controlled Groq fallback | documented disabled route/dependency only | AI routing tests | CREDENTIAL_REQUIRED | Provider implementation, credential isolation, privacy approval, budgets, and readiness are absent. |
| 26 | Graphify CLI adapter | no implementation found | none | MANUAL_INSTALL_REQUIRED | Inspect provenance/license, install manually if approved, then add shell-free read-only adapter. |
| 27 | Graphify repository-graph learning period | no implementation found | none | EXTERNAL_PREREQUISITE | Requires approved CLI adapter and recorded non-authoritative usage evidence first. |
| 28 | VulnHunter-native repository graph | coverage inventory is file-level only | repository coverage tests | MISSING | Add deterministic nodes/edges, incremental identity, query API, and stale-index detection. |
| 29 | Optional restricted local Graphify MCP service | no implementation found | none | LATE_STAGE_GATED | May follow CLI learning only; must remain local, read-only, allowlisted, and non-authoritative. |
| 30 | Context broker | provider privacy and source manifests are adjacent foundations | provider/knowledge tests | MISSING | Add typed context requests, deterministic source selection, budgets, provenance, and redaction. |
| 31 | Context routing and compression | deterministic provider routing exists; no context compression | provider tests | PARTIAL | Add non-lossy security-fact preservation and bounded summarization contracts. |
| 32 | Approved embedding retrieval | no embedding store or approved retrieval policy | none | RESOURCE_DEFERRED | Optional only after deterministic graph facts; model download requires manual approval. |
| 33 | Source freshness and confidence labels | publication/ingest dates and trust levels exist | knowledge tests | PARTIAL | Add freshness state, expiry/staleness checks, and evidence-backed confidence semantics. |
| 34 | Unattended operations control plane | `vulnhunter/unattended`; ADR 0011; operations doc | unattended test family | PARTIAL | Production scheduler, external identities/signatures, and isolation are absent. |
| 35 | Runtime permission manifests | immutable expiring manifests and runtime `PermissionEnforcer` | unattended model/policy/workflow tests | COMPLETE | New adapters must call the enforcer at execution time. |
| 36 | Scheduling, leases, heartbeats, and safe recovery | scheduling recommendations and failure isolation exist | unattended workflow tests | PARTIAL | Durable leases, worker ownership, heartbeat expiry, and production scheduler are missing. |
| 37 | Pause, cancellation, and kill switch | agent pause/resume; scanner cancellation; unattended revocation/expiry | agent, scanner, unattended tests | PARTIAL | Add unified run cancellation and global fail-closed kill control across adapters. |
| 38 | Agentic-threat detection and containment | prompt-injection and runtime policy controls are preventative foundations | knowledge/agent policy tests | MISSING | Add typed threat events, containment states, evidence, and independent clearance. |
| 39 | Sequence-based suspicious-behaviour detection | hash-chained activity exists; no behavioral sequence detector | activity/orchestration tests | MISSING | Add deterministic sequence rules and bounded alert/containment workflow. |
| 40 | Outbound allowlists and secret isolation | unattended network/connector/secret allowlists and redaction | unattended policy and redaction tests | COMPLETE | No new connector may bypass these controls. |
| 41 | Controlled analyst-feedback learning | `analyst_feedback` metrics and governed reviews | Milestone 27/review tests | PARTIAL | Version feedback datasets and track suggestion acceptance/rejection without automatic training. |
| 42 | Reinforcement fine-tuning and reward governance | transactional research safety exists; no RL training | research tests | LATE_STAGE_GATED | Requires separate approval, frozen evaluator, reward policy, data rights, and isolated resources. |
| 43 | Frozen validation and hidden holdout sets | scan-group splits, locked holdout, immutable evaluator resources | ML/model-selection/research tests | COMPLETE | Real diverse governed data is still required for meaningful performance claims. |
| 44 | Reward-hacking and prompt-injection evaluations | prompt-injection screening and protected evaluator boundaries exist | knowledge/research tests | PARTIAL | Add specialist adversarial evaluation suites before any reward optimization. |
| 45 | Evaluation and release gates | ML data gates, release manifests, research regression/safety gates | governance, ML, research tests | PARTIAL | Extend to specialist models/providers and operational pilot release. |
| 46 | Hosting and storage principles | local SQLite, atomic stores, production limitations docs | storage, web, governance tests | PARTIAL | Production DB/object store/queue abstractions and deployment hardening remain. |
| 47 | Local-only operating mode | all implemented foundations operate locally; remote providers disabled | broad focused tests | COMPLETE | Preserve as a first-class degraded mode. |
| 48 | Constrained-resource model strategy | deterministic-first routing and no automatic model loads | AI routing tests | PARTIAL | Add measured model profiles and explicit 2-CPU/9-GB routing ceilings. |
| 49 | Explicit exclusions | AGENTS.md and security boundaries prohibit exploitation, public scans, bypass, and automatic authority | policy/scope/authorization tests | COMPLETE | Exclusions must remain non-negotiable. |
| 50 | External dependency inspection and provenance rules | role `ExternalDependency`; research integrity; no silent installs | role/research tests | COMPLETE | Populate per-tool installation evidence before any activation. |

## Explicit 25-phase evidence

| Phase | Canonical prompt phase | Current classification | Evidence and exact next task |
| --- | --- | --- | --- |
| 1 | Canonical project documentation and AGENTS.md | PARTIAL | Documentation and root manual exist; restore the non-empty canonical master plan. |
| 2 | Stable authorization and scope model | COMPLETE | `authorization`, `scope`, pinned transport, governance; preserve fail-closed boundaries. |
| 3 | Bounded task specification | COMPLETE | agent/orchestration typed specs and budgets. |
| 4 | Deterministic tool contracts | PARTIAL | security-tool catalog/plans/executor exist; finish adapter-specific readiness and authorization bindings. |
| 5 | Audit and event model | COMPLETE | hash-chained agent/orchestration/approval/governance records. |
| 6 | Candidate observation schema | COMPLETE | observations and passive evidence contracts. |
| 7 | Human-review workflow | COMPLETE | two-reviewer consensus, adjudication, attestations, release gates. |
| 8 | Machine Oracle interface | PARTIAL | deterministic interface exists; live authenticated verifier inactive. |
| 9 | Proof-capsule schema | COMPLETE | immutable evidence-bound schema and tests. |
| 10 | Local Qwen provider interface | CONTRACT_ONLY | routing/privacy foundations only; define adapter/readiness without model download. |
| 11 | Context broker | MISSING | implement typed deterministic broker after repository graph foundations. |
| 12 | Graphify CLI adapter | MANUAL_INSTALL_REQUIRED | dependency review/manual install, then restricted read-only argv adapter. |
| 13 | Repository graph learning period | EXTERNAL_PREREQUISITE | record Graphify usage only after Phase 12 readiness. |
| 14 | Deterministic repository review harness | PARTIAL | coverage inventory exists; add incremental graph and security review mapping. |
| 15 | Specialist-model benchmark harness | PARTIAL | reuse grouped ML/research gates; add task-specific suites and provenance. |
| 16 | Controlled Groq fallback | CREDENTIAL_REQUIRED | keep disabled pending provider contract, privacy approval, credentials, and real readiness. |
| 17 | Multi-agent task graph | PARTIAL | durable graph exists; add bounded specialist worker ownership/leases. |
| 18 | Role and skill registry | CONTRACT_ONLY | declarations are planned/untrusted; bind authenticated runtime identities later. |
| 19 | Third-party skill import pipeline | MISSING | add quarantine, pin/hash, review, tests, and rollback without automatic activation. |
| 20 | Restricted local MCP services | LATE_STAGE_GATED | no service exists; allow only narrow local read-only services after adapters mature. |
| 21 | Native VulnHunter knowledge graph | MISSING | define from real graph usage, then migrate security-critical deterministic relations. |
| 22 | Agentic-threat detection | MISSING | add deterministic threat events, sequence rules, containment, and human clearance. |
| 23 | Controlled analyst-feedback learning | PARTIAL | feedback records exist; bind governance provenance and versioned datasets. |
| 24 | Unattended control plane | PARTIAL | runtime enforcement exists; add leases/heartbeats/scheduler/isolation readiness. |
| 25 | Reinforcement fine-tuning and reward governance | LATE_STAGE_GATED | no automatic training; requires a separately approved future programme. |

## Reconciliation constraints retained

- Graphify order remains CLI adapter, learning period, native graph definition,
  security-critical migration, optional accelerator, then optional restricted
  local MCP.
- Graphify, models, providers, and connectors cannot authorize, expand scope,
  alter policy, execute repository instructions, or become single points of
  failure.
- Existing complete foundations must be extended rather than duplicated.
- Operational and external capabilities remain disabled until their explicit
  readiness, approval, credential, resource, and manual-install gates pass.
