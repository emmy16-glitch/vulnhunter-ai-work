# Milestone 27 Existing Capability Map

Baseline: `c0f853275bf0b9598f962e0dd81cc997aa13fc01`.

| Capability | Classification | Existing module | Existing tests | Persistence | Boundary | Planned extension |
| --- | --- | --- | --- | --- | --- | --- |
| Action manifests and policy | COMPLETE | `vulnhunter/actions` | `test_governed_actions.py` | hash-bound Pydantic records | exact action hash | Reused unchanged. |
| Approval Centre | PARTIAL | `vulnhunter/approvals` | `test_approval_centre.py` | SQLite ledger | human maker-checker | Typed condition context added; executed state remains later. |
| Security-tool orchestration | PARTIAL | `vulnhunter/security_tools` | `test_security_tool_governance.py` | command plan/result records | disabled by default | Add deeper executable health policy later. |
| Evidence store | FOUNDATION_ONLY | `vulnhunter/evidence` | `test_evidence_store.py` | append-only JSONL | immutable hashes | Extend with finding lifecycle and Oracle references. |
| Durable task graph | FOUNDATION_ONLY | `vulnhunter/taskgraph` | `test_taskgraph.py` | atomic JSON | safe graph identifiers | Reuse for Oracle sessions and unattended work. |
| Mobile APK static analysis | FOUNDATION_ONLY | `vulnhunter/mobile` | mobile unit tests | artifact records | static only, no execution | Add richer static correlation later. |
| Knowledge system | PARTIAL | `vulnhunter/knowledge`, `knowledge/` | knowledge tests | source register and manifests | imported text untrusted | Add reviewed Oracle facts later. |
| Bounded orchestration | PARTIAL | `vulnhunter/orchestration` | orchestration tests | JSON/SQLite stores | deterministic verifiers | Reuse for future loop integration. |
| Autoresearch | FOUNDATION_ONLY | `vulnhunter/research` | research tests | candidate worktree records | evaluator separation | Reuse for proposal evaluation. |
| Unattended operations | FOUNDATION_ONLY | `vulnhunter/unattended` | unattended tests | durable task records | manifest permission gates | Extend with Oracle pause reasons later. |
| Roles and skills | COMPLETE | `vulnhunter/roles`, `config/roles` | role tests | JSON registry | role/skill validation | Reuse unchanged. |
| Provider privacy | FOUNDATION_ONLY | `vulnhunter/providers` | provider privacy tests | provider registry | privacy fail closed | Extended by `vulnhunter/ai_routing`. |
| Machine Oracle | MISSING | none | new tests | atomic JSON capsules, durable replay ledger, session history | verifier cannot approve/authorize | Added as `vulnhunter/oracle`; production verifier keys remain deferred. |
| Attack-path graph | MISSING | none | new tests | contract only | unverified paths cannot be confirmed | Added as `vulnhunter/attack_paths`. |
| Repository coverage | MISSING | `scripts/project_audit.py` adjacent | new tests | path-sensitive deterministic inventory model | real counts only | Added as `vulnhunter/repository_coverage`. |
| AI routing | MISSING | provider privacy adjacent | new tests | decision records | deterministic first, cloud privacy gated | Added as `vulnhunter/ai_routing`. |
| Analyst feedback | MISSING | review adjacent | new tests | contract only | actual records only | Added as `vulnhunter/analyst_feedback`. |
| Improvement proposals | MISSING | research adjacent | new tests | contract only | no automatic activation | Added as `vulnhunter/improvements`. |
| Reports and exports | PARTIAL | CLI/export functions | new tests | artifact metadata | no protected fields | Added as `vulnhunter/reports`. |
