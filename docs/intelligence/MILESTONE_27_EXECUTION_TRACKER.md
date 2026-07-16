# Milestone 27 Execution Tracker

## Baseline Verification

- Objective: Verify completed Milestone 26 before creating Milestone 27 worktree.
- Baseline commit: `c0f853275bf0b9598f962e0dd81cc997aa13fc01`.
- Commands run: branch, HEAD, status, diff checks, focused regression tests, focused Milestone 26 tests, project audit.
- Results: branch and worktree clean; 13 regression tests passed; 65 focused tests passed; project audit warnings `0`.
- Limitation: `/tmp/verify_m26_final_safety_corrections.sh` is stale because it expects the pre-commit hash `442e7b971532ca6f78be2e4b769e5c34addf558b`.

## Phase 1 of 18 Verified

- Objective: Add domain and persistence foundations for Machine Oracle and adjacent Milestone 27 contracts without duplicating existing systems.
- Existing components reused: action hashes, approval boundaries, evidence hashes, task graph concepts, provider privacy boundary, research/unattended governance docs.
- Identified gap: no proof-capsule, Oracle session, attack-path graph, repository coverage, AI route decision, analyst feedback, improvement proposal, or protected report contract existed.
- Files changed: new `oracle`, `attack_paths`, `repository_coverage`, `ai_routing`, `analyst_feedback`, `improvements`, `reports` packages; new focused tests; new intelligence docs.
- Schema changes: additive Pydantic schema-versioned contracts only; no database migration.
- Tests added: `tests/unit/test_machine_oracle.py`, `tests/unit/test_milestone27_contracts.py`.
- Operational activation: none.
- Commands run: `python -m pytest -q -x --tb=short -o cache_dir=/tmp/pytest-cache-m27 tests/unit/test_machine_oracle.py tests/unit/test_milestone27_contracts.py`; `python -m ruff check ...`; `python -m ruff format --check ...`; `git diff --check`.
- Exact results: 12 focused tests passed in 10.97s; Ruff check passed; Ruff format check reported 23 files already formatted; `git diff --check` passed.
- Unresolved risks: later phases still need deeper integration with existing Approval Centre, web pages, CLI reports, and full final verification.
- Next phase: integrate approval condition validation and richer execution grants with existing Approval Centre.

## Phase 2 of 18 Verified

- Objective: Complete the next Approval Centre foundation without replacing the existing store.
- Existing components reused: `ApprovalRequest`, `ApprovalDecision`, `ApprovalStore.consume`, existing SQLite ledger and event history.
- Identified gap: conditional approvals failed closed but had no typed machine-validation path.
- Files changed: `vulnhunter/approvals/conditions.py`, `vulnhunter/approvals/__init__.py`, `vulnhunter/approvals/store.py`, `tests/unit/test_approval_conditions.py`.
- Schema changes: additive in-memory Pydantic `ApprovalConditionContext`; no database migration.
- Tests added: typed condition validation success and fail-closed unknown condition coverage.
- Commands run: focused approval/Milestone 27 tests, Ruff check, Ruff format check, `git diff --check`.
- Exact results: 19 tests passed in 26.14s; Ruff check passed; Ruff format check reported 29 files already formatted; `git diff --check` passed.
- Unresolved risks: additional stale-authorization, role, skill, target, scope, policy, and permission revalidation hooks still need richer integration with governance stores.
- Next phase: extend security-tool readiness and command-plan contracts without activating external tools.

## Final Review Checkpoint

- Objective: Prepare Milestone 27 integrated intelligence, operations, and Machine Oracle foundations for human review without committing or pushing.
- Existing components reused: Approval Centre, governance store, evidence/action hash concepts, provider privacy boundaries, existing web/static checks, project audit, and Milestone 26 governed security-operation foundations.
- Identified gap closed in this pass: deterministic Machine Oracle proof capsules, disabled pentest-ai connector contract, typed AI routing decisions, repository coverage inventory, attack-path state labelling, analyst feedback metrics, improvement proposals, protected report exports, and typed approval-condition validation.
- Files changed: additive Milestone 27 packages, focused tests, product/ADR/intelligence documentation, Approval Centre condition hook, governance SQLite connection hardening, `.gitignore` source/artifact pattern correction.
- Schema changes: additive Pydantic schema-versioned contracts only; no Django migration and no SQLite data migration.
- Tests added: `tests/unit/test_approval_conditions.py`, `tests/unit/test_machine_oracle.py`, `tests/unit/test_milestone27_contracts.py`.
- Commands run: focused governance and Milestone 27 tests; Ruff check; Ruff format check; Python compilation; Django system check; Django migration dry-run; static asset lookup; Git whitespace check; project audit; full repository pytest suite.
- Exact focused result: `30 passed in 368.83s (0:06:08)`.
- Exact full-suite result: `509 passed in 1954.32s (0:32:34)` with local shell soft descriptor limit raised by `ulimit -n 4096` after repeated late SQLite open failures at the default soft limit `1024`.
- Exact static/build results: Ruff check `All checks passed!`; Ruff format `30 files already formatted`; `python -m compileall -q vulnhunter` passed using `PYTHONPYCACHEPREFIX=/tmp/vulnhunter-m27-pycache`; Django check reported `System check identified no issues (0 silenced).`; migration dry-run reported `No changes detected`; `findstatic web/app.css --verbosity 0` resolved the static CSS path; `git diff --check` passed.
- Exact audit result: `python scripts/project_audit.py` exited `0`; warnings `1`; warning was `Working tree is not clean`, expected before staging the review patch.
- Operational activation: none. No scans, APK execution, connector activation, external verifier calls, model calls, credential creation, privileged broker installation, deployment, commit, push, merge, or rebase occurred.
- Unresolved risks: live security tools, dynamic APK analysis, isolated emulator/ADB/Frida/MobSF/Ghidra automation, live pentest-ai, cloud AI providers, GitHub connectors, and privileged broker installation remain intentionally deferred and require separate authorization and environment setup.
- Next phase: human review of the staged patch and explicit commit decision.

## Security Review Corrections

- Objective: Correct independent review findings before commit without activating external systems or discarding the staged milestone.
- Existing components reused: Approval Centre ledger, authorization store, Oracle proof-capsule models, Oracle JSON store, repository coverage inventory, report artifact contracts, and project audit workflow.
- Findings corrected: conditional-approval callback bypass removed; external Oracle responses require an injected authenticator; Oracle response replay protection moved to a durable atomic ledger; report protected-data checks recurse through nested structures; malformed capsule evidence references remain validation failures; Oracle session creation/update now validates transitions and terminal immutability; AuthorizationStore now closes SQLite connections; report timestamps use per-instance UTC defaults; repository coverage root hashes are path/state/exclusion sensitive.
- Files changed: `vulnhunter/approvals/store.py`, `vulnhunter/approvals/service.py`, `vulnhunter/oracle/connectors.py`, `vulnhunter/oracle/store.py`, `vulnhunter/oracle/service.py`, `vulnhunter/oracle/__init__.py`, `vulnhunter/authorization/store.py`, `vulnhunter/reports/models.py`, `vulnhunter/reports/service.py`, `vulnhunter/repository_coverage/service.py`, affected tests, and affected documentation.
- Schema changes: no Django migrations; additive in-code contracts only.
- Tests added or expanded: approval-condition typed-context failures, external Oracle authentication and durable replay, Oracle session transition history, recursive report protected-data rejection, authorization descriptor closure, report timestamp defaults, and path-sensitive repository coverage hashing.
- Exact focused correction result: `57 passed in 59.19s`.
- Exact full-suite result: `535 passed in 1954.37s (0:32:34)` under `ulimit -n 1024`.
- Operational activation: none. No scans, APK execution, connector activation, external verifier calls, model calls, credential creation, privileged broker installation, deployment, commit, push, merge, or rebase occurred.
- Remaining deferred dependencies: live `pentest-ai`, production response signatures or protected keys, security-tool installation, dynamic APK isolation, AI providers, GitHub connectors, privileged broker installation, and deployment remain deferred.

## Final Security Delta

- Objective: close the three remaining independent-review blockers without expanding Milestone 27 scope.
- Authoritative approvals: removed caller-created `ApprovalConditionContext` from consumption. A concrete evaluator now derives immutable facts from the exact manifest and canonical execution plan, binds the evaluation to approval, manifest, execution, and plan hashes, and enforces evaluator identity/version and short-lived freshness. The store independently compares every derived fact before transactional one-time consumption.
- Oracle integrity: replaced independently written session/history files with a single SQLite transaction boundary. Creation is queued-only; identity and configuration are immutable; attempts, heartbeats, and evidence are monotonic; terminal state is immutable; every load/update validates the complete typed history; updates use atomic expected-status and expected-snapshot compare-and-swap.
- Repository safety: replaced following `rglob` inventory with non-following traversal. Symlinks and nested generated directories are excluded before reads. Regular files are canonically contained, opened with no-follow semantics, streamed through SHA-256, and checked for disappearance or replacement.
- Focused tests: `18 passed in 21.27s` for approval conditions and Approval Centre (`51.84s` process elapsed); `37 passed in 31.97s` for Machine Oracle (`64.49s` process elapsed); `24 passed in 20.29s` for repository coverage and Milestone 27 contracts (`53.72s` process elapsed). These 79 tests are distinct and were not rerun after success.
- Static gates: changed-file Ruff passed; changed-file format check reported 12 files formatted; compileall for `vulnhunter/approvals`, `vulnhunter/oracle`, and `vulnhunter/repository_coverage` passed in `18.54s`; staged and unstaged Git diff checks passed.
- Operational activation: none. No external verifier, provider, security tool, scan, APK, binary, connector, broker, model, deployment, commit, push, merge, or publication was activated or executed.
- Milestone status: technically complete after the focused Stage A security gate; external integrations remain explicitly deferred.

## Controlled Graphify Compatibility and Governance Integration — 2026-07-15

- Root cause: the QEMU virtual CPU exposes SSE/SSE2/SSE3 but not SSSE3, SSE4,
  AVX, or AVX2. Graphify's isolated environment had resolved `numpy==2.5.1`;
  importing NumPy alone reproduced SIGILL with exit `132` before graph analysis.
  RapidFuzz and Graphify version probing remained healthy.
- Compatibility repair: the official dependency was pinned only inside the uv
  Graphify tool environment to `numpy==2.2.6`, which satisfies Graphify's declared
  `numpy>=1.21` constraint. NumPy import and a small linear-algebra operation then
  exited `0`. The VulnHunter virtualenv and system Python were not modified.
- Tiny corpus: one-worker `--code-only --no-viz` extraction produced 9 nodes and
  10 edges. `cluster-only --no-label --no-viz` produced non-empty `graph.json` and
  `GRAPH_REPORT.md` without credentials or an external semantic provider.
- Repository corpus: one-worker code-only extraction processed 415/415 code files,
  produced 4,501 nodes and 13,277 edges, and completed the former crash phase.
  Local no-label clustering produced 172 communities and a non-empty report.
- Governance integration: the existing `repository_graph` adapter now enforces an
  approved non-symlinked repository root and output root, allowlisted operations,
  absolute executable binding, one operation at a time, shell-free/minimal-env
  subprocesses, time/byte/node/edge limits, streaming hash reads, JSON structure,
  ignored/secret path rejection, revision freshness, and explicit SIGILL
  classification. Hook, MCP, watch, install, serve, and global operations are
  rejected. Execution remains disabled without a concrete authorizer.
- Context integration: the existing context broker selects bounded Graphify nodes
  and edges, records graph hash/revision provenance, rejects cross-repository and
  stale graphs, filters secret/runtime paths, and falls back to bounded deterministic
  file/native-graph context without fabricating graph data.
- Focused validation: `25 passed in 6.71s`; affected Ruff check passed; affected
  Ruff format check reported 9 files formatted; `git diff --check` passed.
- Activation: Graphify hooks and MCP remain disabled. Graph generation is not part
  of Django startup. The graph remains advisory runtime intelligence ignored by Git.
