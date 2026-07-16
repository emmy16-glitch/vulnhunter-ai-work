# VulnHunter Total Programme Handoff

## Completed work

- Verified the required worktree, branch, baseline HEAD, review-patch digest,
  staged baseline, and absence of initial unstaged changes.
- Completed Stage A authoritative conditional approval evaluation.
- Completed Stage A transactional Oracle session integrity and atomic CAS.
- Completed Stage A repository inventory symlink, containment, generated-path,
  disappearance, permission, and replacement-race safety.
- Passed 79 distinct focused tests without repeating successful subsets.
- Passed changed-file Ruff and formatting, scoped compileall, and both Git diff
  checks.
- Created both required Stage A checkpoint patches.
- Catalogued the 50 prompt-named capabilities and 25 prompt phases against
  current repository evidence without claiming canonical coverage.
- Recorded current dependency availability and the manual-only Graphify
  learning runbook; no installation or activation occurred.
- Verified the restored `27179`-byte canonical roadmap once and recorded its
  SHA-256 `3ffac0a5b441c7eb6877e2fa7c3d5a4eeb243808d6f0eb2002f49202d0dcf265`.
- Generated and validated `608` one-to-one canonical rows across all 26
  sections, all subsections, and all 25 phases with `UNMAPPED=0`.
- Passed the reconciliation gate and its two new regression tests.
- Completed Wave 1 capability subtraction and selected lifecycle/deadline
  enforcement as the first implementation dependency.
- Completed Wave 1.1 lifecycle transitions, immutable deadlines, transactional
  snapshot revalidation, and focused regression coverage.
- Completed Wave 1.2 explicit operator pause/resume and pre-tool concurrent
  pause/cancel checkpoints; in-flight handler preemption remains unimplemented.
- Completed Wave 1.3 real Approval Centre consumption and eliminated
  caller-supplied approval references as execution authority.

## Active wave

- Stage: `STAGE_B_WAVE_1_AGENTIC_ENGINEERING_RUNTIME`
- Current task: harden the existing task graph with atomic revision/CAS and
  immutable node bindings before bounded worker leases are added.
- Blocker: none for code-only Wave 1 work.
- External integrations, tools, providers, models, and connectors remain
  disabled and are not required for this task.

## Exact next command

```bash
sed -n '1,240p' vulnhunter/taskgraph/models.py && \
  sed -n '1,260p' vulnhunter/taskgraph/store.py && \
  sed -n '1,260p' tests/unit/test_taskgraph.py
```

Then add revision/CAS and immutable binding validation before lease fields.

## Files modified in Stage A

- `vulnhunter/approvals/{__init__,conditions,service,store}.py`
- `vulnhunter/oracle/{__init__,models,store}.py`
- `vulnhunter/repository_coverage/service.py`
- `tests/unit/test_approval_centre.py`
- `tests/unit/test_approval_conditions.py`
- `tests/unit/test_machine_oracle.py`
- `tests/unit/test_repository_coverage.py`
- Milestone 27 Machine Oracle, repository coverage, gap, and execution docs.
- Total programme tracker, coverage blocker, handoff, state, and runtime ledger.
- Total programme repository evidence catalogue and setup dependency/runbook
  documents.

## Tests already run and not to repeat

- Approval conditions plus Approval Centre: `18 passed in 21.27s`.
- Machine Oracle: `37 passed in 31.97s`.
- Repository coverage plus Milestone 27 contracts: `24 passed in 20.29s`.
- Canonical reconciliation final run: `2 passed in 4.71s` (`40.48s` elapsed).
- Two earlier reconciliation harness runs failed before the final pass; exact
  durations and causes are recorded in `TEST_RUNTIME_LEDGER.md` and must not be
  repeated.
- Wave 1.1 affected agent set: `40 passed in 35.53s` (`68.24s` elapsed).
- Wave 1.1 final controller/activity set: `20 passed in 31.11s` (`64.11s`
  elapsed). Do not repeat unless those files change.
- Wave 1.2 controller/model/activity set: `39 passed in 46.32s` (`84.35s`
  elapsed). Do not repeat unless those files change.
- Wave 1.3 integration: `49 passed in 56.42s` (`91.18s` elapsed); final policy
  correction: `13 passed in 13.40s` (`53.34s` elapsed). The intervening legacy
  expectation failure is recorded in the runtime ledger.

## Checkpoint artifacts

- `/home/okunlola_labs/vulnhunter-total-programme-continuation.patch`
  - size: `695786 bytes`
  - SHA-256: `7a00cab30e6d818440191f7f692ced7da4449c787b95a49077458cd2ca85c257`
- Canonical coverage matrix
  - size: `336125 bytes`
  - SHA-256: `67722af1ac52bfef268397312dadf75c51eb94d09ed4757941eb6fc38c80b97e`

- `/home/okunlola_labs/milestone-27-final-security-delta.patch`
  - size: `105351 bytes`
  - SHA-256: `49d88c694f72143789e17c02382414c15e97dc2f34ab49c05f2106dbe1763f07`
- `/home/okunlola_labs/milestone-27-complete-checkpoint.patch`
  - size: `183858 bytes`
  - SHA-256: `8883f446f93d669a7f4f2a12e09768c4455fb7024cdfd1e1471252a970f77972`

## Manual dependency

Graphify remains `MANUAL_INSTALL_REQUIRED`, its learning period remains
`EXTERNAL_PREREQUISITE`, and its optional MCP service remains
`LATE_STAGE_GATED`. None is required for Wave 1 and none may be installed or
activated automatically.

## Prohibited or unperformed actions

No commit, push, merge, deployment, publication, external scan, APK/binary
execution, package installation, connector/provider activation, or model
training occurred.

## Current `git status --short`

```text
M  .gitignore
M  README.md
A  docs/adr/0020-machine-oracle-and-integrated-intelligence-foundations.md
M  docs/adr/README.md
AM docs/intelligence/MILESTONE_27_EXECUTION_TRACKER.md
A  docs/intelligence/MILESTONE_27_EXISTING_CAPABILITY_MAP.md
AM docs/intelligence/MILESTONE_27_GAP_MATRIX.md
A  docs/product/AI_ROUTING.md
AM docs/product/MACHINE_ORACLE.md
A  docs/product/PROOF_CAPSULE_SPECIFICATION.md
AM docs/product/REPOSITORY_COVERAGE.md
MM tests/unit/test_approval_centre.py
AM tests/unit/test_approval_conditions.py
M  tests/unit/test_authorization_store.py
AM tests/unit/test_machine_oracle.py
A  tests/unit/test_milestone27_contracts.py
M  tests/unit/test_web_app.py
A  vulnhunter/ai_routing/__init__.py
A  vulnhunter/ai_routing/models.py
A  vulnhunter/ai_routing/service.py
A  vulnhunter/analyst_feedback/__init__.py
A  vulnhunter/analyst_feedback/models.py
A  vulnhunter/analyst_feedback/service.py
MM vulnhunter/approvals/__init__.py
AM vulnhunter/approvals/conditions.py
MM vulnhunter/approvals/service.py
MM vulnhunter/approvals/store.py
A  vulnhunter/attack_paths/__init__.py
A  vulnhunter/attack_paths/models.py
M  vulnhunter/authorization/store.py
M  vulnhunter/governance/store.py
A  vulnhunter/improvements/__init__.py
A  vulnhunter/improvements/models.py
AM vulnhunter/oracle/__init__.py
A  vulnhunter/oracle/connectors.py
AM vulnhunter/oracle/models.py
A  vulnhunter/oracle/service.py
AM vulnhunter/oracle/store.py
A  vulnhunter/reports/__init__.py
A  vulnhunter/reports/models.py
A  vulnhunter/reports/service.py
A  vulnhunter/repository_coverage/__init__.py
A  vulnhunter/repository_coverage/models.py
AM vulnhunter/repository_coverage/service.py
?? docs/intelligence/TEST_RUNTIME_LEDGER.md
?? docs/intelligence/TOTAL_PROGRAMME_CANONICAL_COVERAGE_MATRIX.md
?? docs/intelligence/TOTAL_PROGRAMME_EXECUTION_TRACKER.md
?? docs/intelligence/TOTAL_PROGRAMME_GAP_MATRIX.md
?? docs/intelligence/TOTAL_PROGRAMME_HANDOFF.md
?? docs/intelligence/TOTAL_PROGRAMME_REPOSITORY_EVIDENCE_CATALOGUE.md
?? docs/intelligence/total_programme_state.json
?? docs/setup/
?? scripts/generate_total_programme_coverage.py
?? tests/unit/test_repository_coverage.py
?? tests/unit/test_total_programme_coverage.py
```

## Manual completion package handoff — 2026-07-15

The post-Wave-1.3 code-only completion package now includes task-graph CAS,
worker leases, threat detection, native repository graph, context broker, skill
inspection, findings lifecycle, exports, provider runtime, static binary
analysis, privileged-broker contracts and the unified web workspace.

Run `python3 scripts/validate_manual_completion.py` after installation. Then run
`python3 scripts/dependency_readiness.py` to obtain a read-only environment
report. External integrations remain disabled until separately reviewed and
activated.
