# Manual Completion Handoff — 2026-07-15

Generated from the repository, Git, local logs and fresh non-destructive checks.

> This report cannot recover Codex's private reasoning or reliably separate
> one Codex session from earlier uncommitted work. It documents the complete
> present working-tree state and marks unverified claims honestly.

## 1. Repository and branch

- Repository: `/mnt/vulnhunter-data/Projects/vulnhunter-ai-integrated-future`
- Branch: `milestone-27-integrated-intelligence-machine-oracle`
- HEAD: `c0f853275bf0b9598f962e0dd81cc997aa13fc01`

## 2. Exact git status

```text
MM .gitignore
 M AGENTS.md
MM README.md
 M config/advanced/profiles.json
A  docs/adr/0020-machine-oracle-and-integrated-intelligence-foundations.md
M  docs/adr/README.md
AM docs/intelligence/MILESTONE_27_EXECUTION_TRACKER.md
A  docs/intelligence/MILESTONE_27_EXISTING_CAPABILITY_MAP.md
AM docs/intelligence/MILESTONE_27_GAP_MATRIX.md
AM docs/product/AI_ROUTING.md
AM docs/product/MACHINE_ORACLE.md
A  docs/product/PROOF_CAPSULE_SPECIFICATION.md
AM docs/product/REPOSITORY_COVERAGE.md
 M docs/product/WEB_APPLICATION.md
 M pyproject.toml
 M tests/unit/test_agent_controller.py
 M tests/unit/test_agent_models.py
 M tests/unit/test_agent_policy.py
 M tests/unit/test_agent_store.py
MM tests/unit/test_approval_centre.py
AM tests/unit/test_approval_conditions.py
M  tests/unit/test_authorization_store.py
AM tests/unit/test_machine_oracle.py
A  tests/unit/test_milestone27_contracts.py
 M tests/unit/test_mobile_artifacts.py
 M tests/unit/test_security_tool_governance.py
 M tests/unit/test_taskgraph.py
MM tests/unit/test_web_app.py
 M vulnhunter/advanced/service.py
 M vulnhunter/agent/__init__.py
 M vulnhunter/agent/cli.py
 M vulnhunter/agent/controller.py
 M vulnhunter/agent/models.py
 M vulnhunter/agent/policy.py
 M vulnhunter/agent/store.py
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
 M vulnhunter/mobile/artifacts.py
AM vulnhunter/oracle/__init__.py
A  vulnhunter/oracle/connectors.py
AM vulnhunter/oracle/models.py
A  vulnhunter/oracle/service.py
AM vulnhunter/oracle/store.py
 M vulnhunter/product/service.py
 M vulnhunter/providers/__init__.py
 M vulnhunter/providers/models.py
AM vulnhunter/reports/__init__.py
AM vulnhunter/reports/models.py
A  vulnhunter/reports/service.py
A  vulnhunter/repository_coverage/__init__.py
A  vulnhunter/repository_coverage/models.py
AM vulnhunter/repository_coverage/service.py
 M vulnhunter/security_tools/__init__.py
 M vulnhunter/security_tools/adapters.py
 M vulnhunter/security_tools/catalog.py
 M vulnhunter/security_tools/executor.py
 M vulnhunter/security_tools/models.py
 M vulnhunter/security_tools/parsers.py
 M vulnhunter/security_tools/targets.py
 M vulnhunter/taskgraph/__init__.py
 M vulnhunter/taskgraph/models.py
 M vulnhunter/taskgraph/store.py
 M vulnhunter/web/operations_views.py
 M vulnhunter/web/services.py
 M vulnhunter/web/settings.py
 M vulnhunter/web/static/web/activity.css
 M vulnhunter/web/static/web/app.css
 M vulnhunter/web/static/web/app.js
 M vulnhunter/web/templates/web/agent_run_detail.html
 M vulnhunter/web/templates/web/agent_runs.html
 M vulnhunter/web/templates/web/base.html
 M vulnhunter/web/templates/web/dashboard.html
 M vulnhunter/web/templates/web/security_tools.html
 M vulnhunter/web/urls.py
 M vulnhunter/web/views.py
?? .codex/
?? .env.example
?? .graphifyignore
?? .local.unexpected-backup-20260715T103931Z
?? .playwright-cli-config.json
?? .playwright-validate.cjs
?? .vulnhunter-install-backups/
?? config/deployment/
?? docs/intelligence/CONTROLLED_RUNTIME_BASELINE_20260715.md
?? docs/intelligence/MANUAL_COMPLETION_HANDOFF_20260715.md
?? docs/intelligence/MANUAL_COMPLETION_RELEASE.md
?? docs/intelligence/SECURITY_TOOL_INTEGRATION_AUDIT_20260715.md
?? docs/intelligence/TEST_RUNTIME_LEDGER.md
?? docs/intelligence/TOTAL_PROGRAMME_CANONICAL_COVERAGE_MATRIX.md
?? docs/intelligence/TOTAL_PROGRAMME_EXECUTION_TRACKER.md
?? docs/intelligence/TOTAL_PROGRAMME_GAP_MATRIX.md
?? docs/intelligence/TOTAL_PROGRAMME_HANDOFF.md
?? docs/intelligence/TOTAL_PROGRAMME_REPOSITORY_EVIDENCE_CATALOGUE.md
?? docs/intelligence/VULNHUNTER_FUTURE_MASTER_PLAN.md
?? docs/intelligence/WAVE_01_CAPABILITY_SUBTRACTION.md
?? docs/intelligence/total_programme_state.json
?? docs/setup/
?? scripts/create_safe_demo_workspace.py
?? scripts/dependency_readiness.py
?? scripts/generate_total_programme_coverage.py
?? scripts/run_local_preview.py
?? scripts/security_tool_status.py
?? scripts/validate_manual_completion.py
?? scripts/validate_security_tool_integration.py
?? tests/unit/test_binary_analysis.py
?? tests/unit/test_context_broker.py
?? tests/unit/test_findings_lifecycle.py
?? tests/unit/test_privileged_broker.py
?? tests/unit/test_provider_runtime.py
?? tests/unit/test_report_exports.py
?? tests/unit/test_repository_coverage.py
?? tests/unit/test_repository_graph.py
?? tests/unit/test_security_tool_integration.py
?? tests/unit/test_skill_import.py
?? tests/unit/test_threat_detection.py
?? tests/unit/test_total_programme_coverage.py
?? tests/unit/test_web_settings.py
?? var/
?? vulnhunter/binary_analysis/
?? vulnhunter/context_broker/
?? vulnhunter/findings/
?? vulnhunter/privileged_broker/
?? vulnhunter/providers/ollama.py
?? vulnhunter/providers/runtime.py
?? vulnhunter/reports/export.py
?? vulnhunter/repository_graph/
?? vulnhunter/security_tools/integration.py
?? vulnhunter/skill_import/
?? vulnhunter/threat_detection/
?? vulnhunter/web/management/commands/vh_init_agent_store.py
?? vulnhunter/web/static/web/app.css.backup-20260715T144236Z
?? vulnhunter/web/templates/web/agent_run_detail.html.backup-20260715T144236Z
?? vulnhunter/web/templates/web/base.html.backup-20260715T144236Z
?? vulnhunter/web/templates/web/findings_overview.html
?? vulnhunter/web/templates/web/governance_overview.html
?? vulnhunter/web/templates/web/oracle_overview.html
?? vulnhunter/web/templates/web/reports_overview.html
?? vulnhunter/web/templates/web/settings_overview.html
```

## 3. Exact diff statistics

```text
 .gitignore                                         |   1 +
 AGENTS.md                                          |  13 +
 README.md                                          |  27 +
 config/advanced/profiles.json                      |   2 +-
 .../intelligence/MILESTONE_27_EXECUTION_TRACKER.md |  43 ++
 docs/intelligence/MILESTONE_27_GAP_MATRIX.md       |   4 +-
 docs/product/AI_ROUTING.md                         |  15 +-
 docs/product/MACHINE_ORACLE.md                     |   6 +-
 docs/product/REPOSITORY_COVERAGE.md                |  24 +
 docs/product/WEB_APPLICATION.md                    |  33 +-
 pyproject.toml                                     |   4 +
 tests/unit/test_agent_controller.py                | 308 ++++++++-
 tests/unit/test_agent_models.py                    |  47 ++
 tests/unit/test_agent_policy.py                    |   5 +-
 tests/unit/test_agent_store.py                     |  92 ++-
 tests/unit/test_approval_centre.py                 |   4 +-
 tests/unit/test_approval_conditions.py             | 342 ++++++----
 tests/unit/test_machine_oracle.py                  | 308 ++++++++-
 tests/unit/test_mobile_artifacts.py                |  17 +
 tests/unit/test_security_tool_governance.py        |  91 ++-
 tests/unit/test_taskgraph.py                       | 111 ++++
 tests/unit/test_web_app.py                         | 100 +++
 vulnhunter/advanced/service.py                     |   4 +-
 vulnhunter/agent/__init__.py                       |   2 +
 vulnhunter/agent/cli.py                            |   6 +-
 vulnhunter/agent/controller.py                     | 176 ++++-
 vulnhunter/agent/models.py                         | 154 ++++-
 vulnhunter/agent/policy.py                         |  34 +-
 vulnhunter/agent/store.py                          | 166 ++++-
 vulnhunter/approvals/__init__.py                   |  12 +-
 vulnhunter/approvals/conditions.py                 | 272 +++++++-
 vulnhunter/approvals/service.py                    |   7 +-
 vulnhunter/approvals/store.py                      |  53 +-
 vulnhunter/mobile/artifacts.py                     |  14 +-
 vulnhunter/oracle/__init__.py                      |   2 +
 vulnhunter/oracle/models.py                        |  87 ++-
 vulnhunter/oracle/store.py                         | 386 ++++++++---
 vulnhunter/product/service.py                      |  35 +-
 vulnhunter/providers/__init__.py                   |  29 +-
 vulnhunter/providers/models.py                     | 109 +++-
 vulnhunter/reports/__init__.py                     |  20 +-
 vulnhunter/reports/models.py                       |  36 ++
 vulnhunter/repository_coverage/service.py          | 173 ++++-
 vulnhunter/security_tools/__init__.py              |   4 +
 vulnhunter/security_tools/adapters.py              | 100 ++-
 vulnhunter/security_tools/catalog.py               | 269 +++++++-
 vulnhunter/security_tools/executor.py              | 151 ++++-
 vulnhunter/security_tools/models.py                |  15 +
 vulnhunter/security_tools/parsers.py               | 231 +++++++
 vulnhunter/security_tools/targets.py               |   8 +-
 vulnhunter/taskgraph/__init__.py                   |  20 +-
 vulnhunter/taskgraph/models.py                     | 161 ++++-
 vulnhunter/taskgraph/store.py                      | 441 +++++++++++--
 vulnhunter/web/operations_views.py                 |   6 +-
 vulnhunter/web/services.py                         | 140 +++-
 vulnhunter/web/settings.py                         | 155 ++++-
 vulnhunter/web/static/web/activity.css             |  85 +--
 vulnhunter/web/static/web/app.css                  | 716 +++++++++++----------
 vulnhunter/web/static/web/app.js                   | 109 +++-
 vulnhunter/web/templates/web/agent_run_detail.html | 165 ++---
 vulnhunter/web/templates/web/agent_runs.html       |  43 +-
 vulnhunter/web/templates/web/base.html             | 106 ++-
 vulnhunter/web/templates/web/dashboard.html        |  41 +-
 vulnhunter/web/templates/web/security_tools.html   |  24 +-
 vulnhunter/web/urls.py                             |   6 +
 vulnhunter/web/views.py                            | 151 +++++
 66 files changed, 5399 insertions(+), 1122 deletions(-)
```

### Staged diff

```text
 .gitignore                                         |   3 +-
 README.md                                          |   4 +
 ...acle-and-integrated-intelligence-foundations.md |  29 ++
 docs/adr/README.md                                 |   1 +
 .../intelligence/MILESTONE_27_EXECUTION_TRACKER.md |  66 ++++
 .../MILESTONE_27_EXISTING_CAPABILITY_MAP.md        |  25 ++
 docs/intelligence/MILESTONE_27_GAP_MATRIX.md       |  19 +
 docs/product/AI_ROUTING.md                         |  21 ++
 docs/product/MACHINE_ORACLE.md                     |  26 ++
 docs/product/PROOF_CAPSULE_SPECIFICATION.md        |   9 +
 docs/product/REPOSITORY_COVERAGE.md                |   7 +
 tests/unit/test_approval_centre.py                 |   2 +-
 tests/unit/test_approval_conditions.py             | 228 ++++++++++++
 tests/unit/test_authorization_store.py             |  47 ++-
 tests/unit/test_machine_oracle.py                  | 387 +++++++++++++++++++++
 tests/unit/test_milestone27_contracts.py           | 207 +++++++++++
 tests/unit/test_web_app.py                         |   4 +-
 vulnhunter/ai_routing/__init__.py                  |  13 +
 vulnhunter/ai_routing/models.py                    |  73 ++++
 vulnhunter/ai_routing/service.py                   |  55 +++
 vulnhunter/analyst_feedback/__init__.py            |   6 +
 vulnhunter/analyst_feedback/models.py              |  63 ++++
 vulnhunter/analyst_feedback/service.py             |  20 ++
 vulnhunter/approvals/__init__.py                   |   8 +
 vulnhunter/approvals/conditions.py                 |  87 +++++
 vulnhunter/approvals/service.py                    |   3 +
 vulnhunter/approvals/store.py                      |  31 +-
 vulnhunter/attack_paths/__init__.py                |  10 +
 vulnhunter/attack_paths/models.py                  |  95 +++++
 vulnhunter/authorization/store.py                  |  21 +-
 vulnhunter/governance/store.py                     |  18 +-
 vulnhunter/improvements/__init__.py                |   5 +
 vulnhunter/improvements/models.py                  |  68 ++++
 vulnhunter/oracle/__init__.py                      |  41 +++
 vulnhunter/oracle/connectors.py                    |  99 ++++++
 vulnhunter/oracle/models.py                        | 332 ++++++++++++++++++
 vulnhunter/oracle/service.py                       | 100 ++++++
 vulnhunter/oracle/store.py                         | 268 ++++++++++++++
 vulnhunter/reports/__init__.py                     |   6 +
 vulnhunter/reports/models.py                       |  54 +++
 vulnhunter/reports/service.py                      |  73 ++++
 vulnhunter/repository_coverage/__init__.py         |   6 +
 vulnhunter/repository_coverage/models.py           |  59 ++++
 vulnhunter/repository_coverage/service.py          |  68 ++++
 44 files changed, 2747 insertions(+), 20 deletions(-)
```

## 4. Changed and created files

Total: **246**

- `AGENTS.md`
- `.codex/skills/graphify/.graphify_version`
- `.codex/skills/graphify/references/add-watch.md`
- `.codex/skills/graphify/references/exports.md`
- `.codex/skills/graphify/references/extraction-spec.md`
- `.codex/skills/graphify/references/github-and-merge.md`
- `.codex/skills/graphify/references/hooks.md`
- `.codex/skills/graphify/references/query.md`
- `.codex/skills/graphify/references/transcribe.md`
- `.codex/skills/graphify/references/update.md`
- `.codex/skills/graphify/SKILL.md`
- `config/advanced/profiles.json`
- `config/deployment/gunicorn.conf.py`
- `docs/adr/0020-machine-oracle-and-integrated-intelligence-foundations.md`
- `docs/adr/README.md`
- `docs/intelligence/CONTROLLED_RUNTIME_BASELINE_20260715.md`
- `docs/intelligence/MANUAL_COMPLETION_HANDOFF_20260715.md`
- `docs/intelligence/MANUAL_COMPLETION_RELEASE.md`
- `docs/intelligence/MILESTONE_27_EXECUTION_TRACKER.md`
- `docs/intelligence/MILESTONE_27_EXISTING_CAPABILITY_MAP.md`
- `docs/intelligence/MILESTONE_27_GAP_MATRIX.md`
- `docs/intelligence/SECURITY_TOOL_INTEGRATION_AUDIT_20260715.md`
- `docs/intelligence/TEST_RUNTIME_LEDGER.md`
- `docs/intelligence/TOTAL_PROGRAMME_CANONICAL_COVERAGE_MATRIX.md`
- `docs/intelligence/TOTAL_PROGRAMME_EXECUTION_TRACKER.md`
- `docs/intelligence/TOTAL_PROGRAMME_GAP_MATRIX.md`
- `docs/intelligence/TOTAL_PROGRAMME_HANDOFF.md`
- `docs/intelligence/TOTAL_PROGRAMME_REPOSITORY_EVIDENCE_CATALOGUE.md`
- `docs/intelligence/total_programme_state.json`
- `docs/intelligence/VULNHUNTER_FUTURE_MASTER_PLAN.md`
- `docs/intelligence/WAVE_01_CAPABILITY_SUBTRACTION.md`
- `docs/product/AI_ROUTING.md`
- `docs/product/MACHINE_ORACLE.md`
- `docs/product/PROOF_CAPSULE_SPECIFICATION.md`
- `docs/product/REPOSITORY_COVERAGE.md`
- `docs/product/WEB_APPLICATION.md`
- `docs/setup/DEPENDENCY_AND_DOWNLOAD_MATRIX.md`
- `docs/setup/DEPLOYMENT_READINESS.md`
- `docs/setup/MANUAL_INSTALL_RUNBOOK.md`
- `docs/setup/POST_INSTALL_ACTIVATION_PLAN.md`
- `docs/setup/SECURITY_TOOL_INTEGRATION.md`
- `docs/setup/systemd/vulnhunter.service.example`
- `.env.example`
- `.gitignore`
- `.graphifyignore`
- `.local.unexpected-backup-20260715T103931Z`
- `.playwright-cli-config.json`
- `.playwright-validate.cjs`
- `pyproject.toml`
- `README.md`
- `scripts/create_safe_demo_workspace.py`
- `scripts/dependency_readiness.py`
- `scripts/generate_total_programme_coverage.py`
- `scripts/run_local_preview.py`
- `scripts/security_tool_status.py`
- `scripts/validate_manual_completion.py`
- `scripts/validate_security_tool_integration.py`
- `tests/unit/test_agent_controller.py`
- `tests/unit/test_agent_models.py`
- `tests/unit/test_agent_policy.py`
- `tests/unit/test_agent_store.py`
- `tests/unit/test_approval_centre.py`
- `tests/unit/test_approval_conditions.py`
- `tests/unit/test_authorization_store.py`
- `tests/unit/test_binary_analysis.py`
- `tests/unit/test_context_broker.py`
- `tests/unit/test_findings_lifecycle.py`
- `tests/unit/test_machine_oracle.py`
- `tests/unit/test_milestone27_contracts.py`
- `tests/unit/test_mobile_artifacts.py`
- `tests/unit/test_privileged_broker.py`
- `tests/unit/test_provider_runtime.py`
- `tests/unit/test_report_exports.py`
- `tests/unit/test_repository_coverage.py`
- `tests/unit/test_repository_graph.py`
- `tests/unit/test_security_tool_governance.py`
- `tests/unit/test_security_tool_integration.py`
- `tests/unit/test_skill_import.py`
- `tests/unit/test_taskgraph.py`
- `tests/unit/test_threat_detection.py`
- `tests/unit/test_total_programme_coverage.py`
- `tests/unit/test_web_app.py`
- `tests/unit/test_web_settings.py`
- `var/install/vulnhunter-manual-completion-20260715.json`
- `var/install/vulnhunter-security-tool-integration-20260715.json`
- `var/readiness/security-tool-integration.json`
- `vulnhunter/advanced/service.py`
- `vulnhunter/agent/cli.py`
- `vulnhunter/agent/controller.py`
- `vulnhunter/agent/__init__.py`
- `vulnhunter/agent/models.py`
- `vulnhunter/agent/policy.py`
- `vulnhunter/agent/store.py`
- `vulnhunter/ai_routing/__init__.py`
- `vulnhunter/ai_routing/models.py`
- `vulnhunter/ai_routing/service.py`
- `vulnhunter/analyst_feedback/__init__.py`
- `vulnhunter/analyst_feedback/models.py`
- `vulnhunter/analyst_feedback/service.py`
- `vulnhunter/approvals/conditions.py`
- `vulnhunter/approvals/__init__.py`
- `vulnhunter/approvals/service.py`
- `vulnhunter/approvals/store.py`
- `vulnhunter/attack_paths/__init__.py`
- `vulnhunter/attack_paths/models.py`
- `vulnhunter/authorization/store.py`
- `vulnhunter/binary_analysis/__init__.py`
- `vulnhunter/binary_analysis/models.py`
- `vulnhunter/binary_analysis/service.py`
- `vulnhunter/context_broker/__init__.py`
- `vulnhunter/context_broker/models.py`
- `vulnhunter/context_broker/service.py`
- `vulnhunter/findings/__init__.py`
- `vulnhunter/findings/models.py`
- `vulnhunter/findings/service.py`
- `vulnhunter/findings/store.py`
- `vulnhunter/governance/store.py`
- `vulnhunter/improvements/__init__.py`
- `vulnhunter/improvements/models.py`
- `.vulnhunter-install-backups/vulnhunter-manual-completion-20260715-20260715T102143Z/backup_manifest.json`
- `.vulnhunter-install-backups/vulnhunter-manual-completion-20260715-20260715T102143Z/files/docs/intelligence/TOTAL_PROGRAMME_CANONICAL_COVERAGE_MATRIX.md`
- `.vulnhunter-install-backups/vulnhunter-manual-completion-20260715-20260715T102143Z/files/docs/intelligence/TOTAL_PROGRAMME_EXECUTION_TRACKER.md`
- `.vulnhunter-install-backups/vulnhunter-manual-completion-20260715-20260715T102143Z/files/docs/intelligence/TOTAL_PROGRAMME_GAP_MATRIX.md`
- `.vulnhunter-install-backups/vulnhunter-manual-completion-20260715-20260715T102143Z/files/docs/intelligence/TOTAL_PROGRAMME_HANDOFF.md`
- `.vulnhunter-install-backups/vulnhunter-manual-completion-20260715-20260715T102143Z/files/docs/intelligence/total_programme_state.json`
- `.vulnhunter-install-backups/vulnhunter-manual-completion-20260715-20260715T102143Z/files/README.md`
- `.vulnhunter-install-backups/vulnhunter-manual-completion-20260715-20260715T102143Z/files/tests/unit/test_taskgraph.py`
- `.vulnhunter-install-backups/vulnhunter-manual-completion-20260715-20260715T102143Z/files/vulnhunter/providers/__init__.py`
- `.vulnhunter-install-backups/vulnhunter-manual-completion-20260715-20260715T102143Z/files/vulnhunter/providers/models.py`
- `.vulnhunter-install-backups/vulnhunter-manual-completion-20260715-20260715T102143Z/files/vulnhunter/reports/__init__.py`
- `.vulnhunter-install-backups/vulnhunter-manual-completion-20260715-20260715T102143Z/files/vulnhunter/reports/models.py`
- `.vulnhunter-install-backups/vulnhunter-manual-completion-20260715-20260715T102143Z/files/vulnhunter/taskgraph/__init__.py`
- `.vulnhunter-install-backups/vulnhunter-manual-completion-20260715-20260715T102143Z/files/vulnhunter/taskgraph/models.py`
- `.vulnhunter-install-backups/vulnhunter-manual-completion-20260715-20260715T102143Z/files/vulnhunter/taskgraph/store.py`
- `.vulnhunter-install-backups/vulnhunter-manual-completion-20260715-20260715T102143Z/files/vulnhunter/web/services.py`
- `.vulnhunter-install-backups/vulnhunter-manual-completion-20260715-20260715T102143Z/files/vulnhunter/web/static/web/app.css`
- `.vulnhunter-install-backups/vulnhunter-manual-completion-20260715-20260715T102143Z/files/vulnhunter/web/templates/web/agent_run_detail.html`
- `.vulnhunter-install-backups/vulnhunter-manual-completion-20260715-20260715T102143Z/files/vulnhunter/web/templates/web/agent_runs.html`
- `.vulnhunter-install-backups/vulnhunter-manual-completion-20260715-20260715T102143Z/files/vulnhunter/web/templates/web/base.html`
- `.vulnhunter-install-backups/vulnhunter-manual-completion-20260715-20260715T102143Z/files/vulnhunter/web/templates/web/dashboard.html`
- `.vulnhunter-install-backups/vulnhunter-manual-completion-20260715-20260715T102143Z/files/vulnhunter/web/urls.py`
- `.vulnhunter-install-backups/vulnhunter-manual-completion-20260715-20260715T102143Z/files/vulnhunter/web/views.py`
- `.vulnhunter-install-backups/vulnhunter-security-tool-integration-20260715-20260715T153504Z/backup_manifest.json`
- `.vulnhunter-install-backups/vulnhunter-security-tool-integration-20260715-20260715T153504Z/files/config/advanced/profiles.json`
- `.vulnhunter-install-backups/vulnhunter-security-tool-integration-20260715-20260715T153504Z/files/scripts/dependency_readiness.py`
- `.vulnhunter-install-backups/vulnhunter-security-tool-integration-20260715-20260715T153504Z/files/tests/unit/test_security_tool_governance.py`
- `.vulnhunter-install-backups/vulnhunter-security-tool-integration-20260715-20260715T153504Z/files/vulnhunter/advanced/service.py`
- `.vulnhunter-install-backups/vulnhunter-security-tool-integration-20260715-20260715T153504Z/files/vulnhunter/security_tools/adapters.py`
- `.vulnhunter-install-backups/vulnhunter-security-tool-integration-20260715-20260715T153504Z/files/vulnhunter/security_tools/catalog.py`
- `.vulnhunter-install-backups/vulnhunter-security-tool-integration-20260715-20260715T153504Z/files/vulnhunter/security_tools/executor.py`
- `.vulnhunter-install-backups/vulnhunter-security-tool-integration-20260715-20260715T153504Z/files/vulnhunter/security_tools/__init__.py`
- `.vulnhunter-install-backups/vulnhunter-security-tool-integration-20260715-20260715T153504Z/files/vulnhunter/security_tools/models.py`
- `.vulnhunter-install-backups/vulnhunter-security-tool-integration-20260715-20260715T153504Z/files/vulnhunter/security_tools/parsers.py`
- `.vulnhunter-install-backups/vulnhunter-security-tool-integration-20260715-20260715T153504Z/files/vulnhunter/security_tools/targets.py`
- `.vulnhunter-install-backups/vulnhunter-security-tool-integration-20260715-20260715T153504Z/files/vulnhunter/web/templates/web/security_tools.html`
- `.vulnhunter-install-backups/vulnhunter-security-tool-integration-20260715-20260715T154404Z/backup_manifest.json`
- `.vulnhunter-install-backups/vulnhunter-security-tool-integration-20260715-20260715T154404Z/files/config/advanced/profiles.json`
- `.vulnhunter-install-backups/vulnhunter-security-tool-integration-20260715-20260715T154404Z/files/scripts/dependency_readiness.py`
- `.vulnhunter-install-backups/vulnhunter-security-tool-integration-20260715-20260715T154404Z/files/tests/unit/test_security_tool_governance.py`
- `.vulnhunter-install-backups/vulnhunter-security-tool-integration-20260715-20260715T154404Z/files/vulnhunter/advanced/service.py`
- `.vulnhunter-install-backups/vulnhunter-security-tool-integration-20260715-20260715T154404Z/files/vulnhunter/security_tools/adapters.py`
- `.vulnhunter-install-backups/vulnhunter-security-tool-integration-20260715-20260715T154404Z/files/vulnhunter/security_tools/catalog.py`
- `.vulnhunter-install-backups/vulnhunter-security-tool-integration-20260715-20260715T154404Z/files/vulnhunter/security_tools/executor.py`
- `.vulnhunter-install-backups/vulnhunter-security-tool-integration-20260715-20260715T154404Z/files/vulnhunter/security_tools/__init__.py`
- `.vulnhunter-install-backups/vulnhunter-security-tool-integration-20260715-20260715T154404Z/files/vulnhunter/security_tools/models.py`
- `.vulnhunter-install-backups/vulnhunter-security-tool-integration-20260715-20260715T154404Z/files/vulnhunter/security_tools/parsers.py`
- `.vulnhunter-install-backups/vulnhunter-security-tool-integration-20260715-20260715T154404Z/files/vulnhunter/security_tools/targets.py`
- `.vulnhunter-install-backups/vulnhunter-security-tool-integration-20260715-20260715T154404Z/files/vulnhunter/web/templates/web/security_tools.html`
- `.vulnhunter-install-backups/vulnhunter-security-tool-integration-20260715-20260715T161928Z/backup_manifest.json`
- `.vulnhunter-install-backups/vulnhunter-security-tool-integration-20260715-20260715T161928Z/files/config/advanced/profiles.json`
- `.vulnhunter-install-backups/vulnhunter-security-tool-integration-20260715-20260715T161928Z/files/scripts/dependency_readiness.py`
- `.vulnhunter-install-backups/vulnhunter-security-tool-integration-20260715-20260715T161928Z/files/tests/unit/test_security_tool_governance.py`
- `.vulnhunter-install-backups/vulnhunter-security-tool-integration-20260715-20260715T161928Z/files/vulnhunter/advanced/service.py`
- `.vulnhunter-install-backups/vulnhunter-security-tool-integration-20260715-20260715T161928Z/files/vulnhunter/security_tools/adapters.py`
- `.vulnhunter-install-backups/vulnhunter-security-tool-integration-20260715-20260715T161928Z/files/vulnhunter/security_tools/catalog.py`
- `.vulnhunter-install-backups/vulnhunter-security-tool-integration-20260715-20260715T161928Z/files/vulnhunter/security_tools/executor.py`
- `.vulnhunter-install-backups/vulnhunter-security-tool-integration-20260715-20260715T161928Z/files/vulnhunter/security_tools/__init__.py`
- `.vulnhunter-install-backups/vulnhunter-security-tool-integration-20260715-20260715T161928Z/files/vulnhunter/security_tools/models.py`
- `.vulnhunter-install-backups/vulnhunter-security-tool-integration-20260715-20260715T161928Z/files/vulnhunter/security_tools/parsers.py`
- `.vulnhunter-install-backups/vulnhunter-security-tool-integration-20260715-20260715T161928Z/files/vulnhunter/security_tools/targets.py`
- `.vulnhunter-install-backups/vulnhunter-security-tool-integration-20260715-20260715T161928Z/files/vulnhunter/web/templates/web/security_tools.html`
- `vulnhunter/mobile/artifacts.py`
- `vulnhunter/oracle/connectors.py`
- `vulnhunter/oracle/__init__.py`
- `vulnhunter/oracle/models.py`
- `vulnhunter/oracle/service.py`
- `vulnhunter/oracle/store.py`
- `vulnhunter/privileged_broker/__init__.py`
- `vulnhunter/privileged_broker/models.py`
- `vulnhunter/privileged_broker/service.py`
- `vulnhunter/product/service.py`
- `vulnhunter/providers/__init__.py`
- `vulnhunter/providers/models.py`
- `vulnhunter/providers/ollama.py`
- `vulnhunter/providers/runtime.py`
- `vulnhunter/reports/export.py`
- `vulnhunter/reports/__init__.py`
- `vulnhunter/reports/models.py`
- `vulnhunter/reports/service.py`
- `vulnhunter/repository_coverage/__init__.py`
- `vulnhunter/repository_coverage/models.py`
- `vulnhunter/repository_coverage/service.py`
- `vulnhunter/repository_graph/graphify.py`
- `vulnhunter/repository_graph/__init__.py`
- `vulnhunter/repository_graph/models.py`
- `vulnhunter/repository_graph/service.py`
- `vulnhunter/security_tools/adapters.py`
- `vulnhunter/security_tools/catalog.py`
- `vulnhunter/security_tools/executor.py`
- `vulnhunter/security_tools/__init__.py`
- `vulnhunter/security_tools/integration.py`
- `vulnhunter/security_tools/models.py`
- `vulnhunter/security_tools/parsers.py`
- `vulnhunter/security_tools/targets.py`
- `vulnhunter/skill_import/__init__.py`
- `vulnhunter/skill_import/models.py`
- `vulnhunter/skill_import/service.py`
- `vulnhunter/taskgraph/__init__.py`
- `vulnhunter/taskgraph/models.py`
- `vulnhunter/taskgraph/store.py`
- `vulnhunter/threat_detection/__init__.py`
- `vulnhunter/threat_detection/models.py`
- `vulnhunter/threat_detection/service.py`
- `vulnhunter/threat_detection/store.py`
- `vulnhunter/web/management/commands/vh_init_agent_store.py`
- `vulnhunter/web/operations_views.py`
- `vulnhunter/web/services.py`
- `vulnhunter/web/settings.py`
- `vulnhunter/web/static/web/activity.css`
- `vulnhunter/web/static/web/app.css`
- `vulnhunter/web/static/web/app.css.backup-20260715T144236Z`
- `vulnhunter/web/static/web/app.js`
- `vulnhunter/web/templates/web/agent_run_detail.html`
- `vulnhunter/web/templates/web/agent_run_detail.html.backup-20260715T144236Z`
- `vulnhunter/web/templates/web/agent_runs.html`
- `vulnhunter/web/templates/web/base.html`
- `vulnhunter/web/templates/web/base.html.backup-20260715T144236Z`
- `vulnhunter/web/templates/web/dashboard.html`
- `vulnhunter/web/templates/web/findings_overview.html`
- `vulnhunter/web/templates/web/governance_overview.html`
- `vulnhunter/web/templates/web/oracle_overview.html`
- `vulnhunter/web/templates/web/reports_overview.html`
- `vulnhunter/web/templates/web/security_tools.html`
- `vulnhunter/web/templates/web/settings_overview.html`
- `vulnhunter/web/urls.py`
- `vulnhunter/web/views.py`

## 5. Fresh checks

### Git diff check

- Exit code: `0`

```text

```

### Django check

- Exit code: `0`

```text
System check identified no issues (0 silenced).
```

### Migration drift check

- Exit code: `0`

```text
No changes detected
```

### Authentication model and user count

- Exit code: `0`

```text
6 objects imported automatically (use -v 2 for details).

USERNAME_FIELD=username
USER_COUNT=1
```

### Security-tool readiness

> Correction (2026-07-22): this dated output captured a Nuclei version string
> that does not correspond to an official ProjectDiscovery release. It is
> preserved as historical evidence only. Current operational policy pins
> official Nuclei `v3.8.0`.

- Exit code: `0`

```text
      "version_summary": "bandit 1.9.4"
    },
    "bearer": {
      "available": true,
      "checked_at": "2026-07-15T18:55:57.251445Z",
      "error_summary": null,
      "executable_path": "/mnt/vulnhunter-data/tools/vulnhunter-external/bin/bearer",
      "return_code": 0,
      "status": "ready",
      "tool_id": "bearer",
      "usable": true,
      "version_summary": "bearer version 2.0.2, build 255b3d72c911000bfea9aaea5413d354c7220b10"
    },
    "capa": {
      "available": true,
      "checked_at": "2026-07-15T18:56:25.517434Z",
      "error_summary": null,
      "executable_path": "/mnt/vulnhunter-data/tools/vulnhunter-external/bin/capa",
      "return_code": 0,
      "status": "ready",
      "tool_id": "capa",
      "usable": true,
      "version_summary": "capa 9.4.0"
    },
    "detect-secrets": {
      "available": true,
      "checked_at": "2026-07-15T18:56:05.780216Z",
      "error_summary": null,
      "executable_path": "/mnt/vulnhunter-data/tools/vulnhunter-external/bin/detect-secrets",
      "return_code": 0,
      "status": "ready",
      "tool_id": "detect-secrets",
      "usable": true,
      "version_summary": "1.5.0"
    },
    "ffuf": {
      "available": true,
      "checked_at": "2026-07-15T18:55:42.864718Z",
      "error_summary": null,
      "executable_path": "/mnt/vulnhunter-data/tools/vulnhunter-external/bin/ffuf",
      "return_code": 0,
      "status": "ready",
      "tool_id": "ffuf",
      "usable": true,
      "version_summary": "ffuf version: 2.1.0-dev"
    },
    "gitleaks": {
      "available": true,
      "checked_at": "2026-07-15T18:56:08.789904Z",
      "error_summary": null,
      "executable_path": "/mnt/vulnhunter-data/tools/vulnhunter-external/bin/gitleaks",
      "return_code": 0,
      "status": "ready",
      "tool_id": "gitleaks",
      "usable": true,
      "version_summary": "8.30.1"
    },
    "grype": {
      "available": true,
      "checked_at": "2026-07-15T18:56:11.544805Z",
      "error_summary": null,
      "executable_path": "/mnt/vulnhunter-data/tools/vulnhunter-external/bin/grype",
      "return_code": 0,
      "status": "ready",
      "tool_id": "grype",
      "usable": true,
      "version_summary": "Application:         grype"
    },
    "httpx": {
      "available": true,
      "checked_at": "2026-07-15T18:55:42.551943Z",
      "error_summary": null,
      "executable_path": "/mnt/vulnhunter-data/tools/vulnhunter-external/bin/httpx",
      "return_code": 0,
      "status": "ready",
      "tool_id": "httpx",
      "usable": true,
      "version_summary": "__    __  __       _  __"
    },
    "nmap": {
      "available": true,
      "checked_at": "2026-07-15T18:55:39.952469Z",
      "error_summary": null,
      "executable_path": "/usr/bin/nmap",
      "return_code": 0,
      "status": "ready",
      "tool_id": "nmap",
      "usable": true,
      "version_summary": "Nmap version 7.98 ( https://nmap.org )"
    },
    "nuclei": {
      "available": true,
      "checked_at": "2026-07-15T18:55:44.229938Z",
      "error_summary": null,
      "executable_path": "/mnt/vulnhunter-data/tools/vulnhunter-external/bin/nuclei",
      "return_code": 0,
      "status": "ready",
      "tool_id": "nuclei",
      "usable": true,
      "version_summary": "[\u001b[34mINF\u001b[0m] Nuclei Engine Version: v3.11.0"
    },
    "osv-scanner": {
      "available": true,
      "checked_at": "2026-07-15T18:56:13.926380Z",
      "error_summary": null,
      "executable_path": "/mnt/vulnhunter-data/tools/vulnhunter-external/bin/osv-scanner",
      "return_code": 0,
      "status": "ready",
      "tool_id": "osv-scanner",
      "usable": true,
      "version_summary": "osv-scanner version: 2.4.0"
    },
    "syft": {
      "available": true,
      "checked_at": "2026-07-15T18:56:11.525236Z",
      "error_summary": null,
      "executable_path": "/mnt/vulnhunter-data/tools/vulnhunter-external/bin/syft",
      "return_code": 0,
      "status": "ready",
      "tool_id": "syft",
      "usable": true,
      "version_summary": "Application:   syft"
    },
    "testssl": {
      "available": true,
      "checked_at": "2026-07-15T18:56:09.248756Z",
      "error_summary": null,
      "executable_path": "/mnt/vulnhunter-data/tools/vulnhunter-external/bin/testssl.sh",
      "return_code": 0,
      "status": "ready",
      "tool_id": "testssl",
      "usable": true,
      "version_summary": "\u001b[1m"
    },
    "trivy": {
      "available": true,
      "checked_at": "2026-07-15T18:55:47.607483Z",
      "error_summary": null,
      "executable_path": "/mnt/vulnhunter-data/tools/vulnhunter-external/bin/trivy",
      "return_code": 0,
      "status": "ready",
      "tool_id": "trivy",
      "usable": true,
      "version_summary": "Version: 0.72.0"
    }
  },
  "tools_root": "/mnt/vulnhunter-data/tools/vulnhunter-external"
}

Saved readiness report to var/readiness/security-tool-integration.json
```

## 6. Graphify

- State: **GRAPH_AVAILABLE_REQUIRES_VALIDATION**
- graph.json exists: `true`
- GRAPH_REPORT.md exists: `true`
- Project skill exists: `true`
- Automatic hook exists: `false`

### Version

```text
graphify 0.9.16
```

### Failure evidence

```text
FILE: /home/okunlola_labs/graphify-vulnhunter-build-20260715.log
error: no LLM API key found (141 doc/paper/image file(s) need semantic extraction). Set GEMINI_API_KEY or GOOGLE_API_KEY (gemini), MOONSHOT_API_KEY (kimi), ANTHROPIC_API_KEY (claude), OPENAI_API_KEY (openai), DEEPSEEK_API_KEY (deepseek), or pass --backend. A code-only corpus needs no key. Or pass --code-only to index just the code (local AST, no key) and skip the non-code files.

FILE: /home/okunlola_labs/graphify-vulnhunter-code-only-20260715.log
[graphify extract] --code-only: skipping 141 non-code file(s) (141 docs, 0 papers, 0 images) — no LLM extraction
[graphify extract] AST extraction on 415 code files...
  AST extraction: 100/415 uncached files (24%) [4 workers]
  AST extraction: 200/415 uncached files (48%) [4 workers]
  AST extraction: 300/415 uncached files (72%) [4 workers]
  AST extraction: 400/415 uncached files (96%) [4 workers]
  AST extraction: 415/415 uncached files (100%) [4 workers]
```

## 7. Ollama and local provider

- Service:

```text
active
```

- Qwen 2B installed: `false`
- Qwen 9B installed: `true`

### Model storage configuration

```text
Environment=PATH=/home/okunlola_labs/.local/bin:/home/okunlola_labs/android-lab/jadx/bin:/home/okunlola_labs/.local/bin:/home/okunlola_labs/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin OLLAMA_MODELS=/mnt/vulnhunter-data/models/ollama
```

### Installed models

```text
NAME          ID              SIZE      MODIFIED
qwen3.5:9b    6488c96fa5fa    6.6 GB    4 days ago
```

### Loaded models

```text
NAME    ID    SIZE    PROCESSOR    CONTEXT    UNTIL
```

### Repository references

```text
docs/product/AI_ROUTING.md:11:- a loopback-only Ollama connector with an explicit `qwen3.5:9b` allowlist,
docs/product/AI_ROUTING.md:20:- Ollama `0.31.2` health and approved-model inventory pass on loopback;
tests/unit/test_provider_privacy_gate.py:22:    assert route.provider.value == "local_ollama"
vulnhunter/providers/__init__.py:14:from vulnhunter.providers.ollama import OllamaProvider, OllamaProviderError
vulnhunter/providers/__init__.py:21:    "OllamaProvider",
vulnhunter/providers/__init__.py:22:    "OllamaProviderError",
vulnhunter/providers/models.py:15:    LOCAL_OLLAMA = "local_ollama"
vulnhunter/providers/registry.py:27:                reason="Local Ollama is the primary provider.",
vulnhunter/web/services.py:27:from vulnhunter.providers import OllamaProvider, OllamaProviderError
vulnhunter/web/services.py:384:        ollama = OllamaProvider(
vulnhunter/web/services.py:386:            approved_models=(settings.VULNHUNTER_OLLAMA_MODEL,),
vulnhunter/web/services.py:390:        health = ollama.health()
vulnhunter/web/services.py:391:    except OllamaProviderError as exc:
vulnhunter/web/services.py:392:        ollama_row = {
vulnhunter/web/services.py:393:            "name": "Local Ollama/Qwen",
vulnhunter/web/services.py:399:        ollama_row = {
vulnhunter/web/services.py:400:            "name": "Local Ollama/Qwen",
vulnhunter/web/services.py:417:        ollama_row,
vulnhunter/web/settings.py:307:VULNHUNTER_OLLAMA_MODEL = os.environ.get("VULNHUNTER_OLLAMA_MODEL", "qwen3.5:9b")
```

## 8. Groq

- State: **CREDENTIAL_PRESENT_BUT_NOT_ACCESSED**
- Credential mode: `600`
- Credential contents were not read.
- Network execution remains disabled.

```text
docs/product/AI_ROUTING.md:30:- Groq credentials;
tests/unit/test_web_app.py:354:    assert b".groq-api-key" not in settings_page.content
vulnhunter/ai_routing/models.py:26:    GROQ_QWEN = "groq_qwen"
vulnhunter/ai_routing/models.py:27:    GROQ_COMPOUND_MINI = "groq_compound_mini"
vulnhunter/ai_routing/service.py:23:            request, AiRoute.GROQ_COMPOUND_MINI, "approved public-current-information route"
vulnhunter/ai_routing/service.py:30:        return _decision(request, AiRoute.GROQ_QWEN, "approved difficult non-sensitive reasoning")
vulnhunter/ai_routing/service.py:42:    elif route in {AiRoute.GROQ_QWEN, AiRoute.GROQ_COMPOUND_MINI}:
vulnhunter/ai_routing/service.py:43:        provider = "groq-disabled-contract"
vulnhunter/providers/models.py:16:    GROQ_QWEN = "groq_qwen"
vulnhunter/providers/models.py:17:    GROQ_COMPOUND_MINI = "groq_compound_mini"
vulnhunter/providers/registry.py:14:        groq_qwen_enabled: bool = False,
vulnhunter/providers/registry.py:18:        self.groq_qwen_enabled = groq_qwen_enabled
vulnhunter/providers/registry.py:36:        if self.groq_qwen_enabled and gate.allowed_for_remote:
vulnhunter/providers/registry.py:38:                provider=ProviderKind.GROQ_QWEN,
vulnhunter/providers/registry.py:49:                provider=ProviderKind.GROQ_COMPOUND_MINI,
vulnhunter/web/services.py:419:            "name": "Groq fallback",
```

## 9. Context, provider and graph files

```text
./tests/unit/__pycache__/test_context_broker.cpython-314-pytest-9.1.1.pyc
./tests/unit/__pycache__/test_provider_privacy_gate.cpython-314-pytest-9.1.1.pyc
./tests/unit/__pycache__/test_provider_runtime.cpython-314-pytest-9.1.1.pyc
./tests/unit/__pycache__/test_repository_graph.cpython-314-pytest-9.1.1.pyc
./tests/unit/test_context_broker.py
./tests/unit/test_provider_privacy_gate.py
./tests/unit/test_provider_runtime.py
./tests/unit/test_repository_graph.py
./vulnhunter/providers/ollama.py
./vulnhunter/providers/__pycache__/ollama.cpython-314.pyc
```

## 10. Runtime store and agent.db

### Actual files

```text
./.local/runtime/agent/agent.db
```

### Source references

```text
docs/product/WEB_APPLICATION.md:102:  Defaults to `.local/runtime/agent/agent.db`; initialize it explicitly with
docs/product/WEB_APPLICATION.md:240:  - `.local/runtime/agent/agent.db`
tests/unit/test_agent_controller.py:85:            store=AgentStore(tmp_path / "agent.db"),
tests/unit/test_agent_controller_activity.py:40:            store=AgentStore(tmp_path / "agent.db"),
tests/unit/test_agent_controller_activity.py:82:            store=AgentStore(tmp_path / "agent.db"),
tests/unit/test_agent_controller_activity.py:155:            store=AgentStore(tmp_path / "agent.db"),
tests/unit/test_agent_controller_activity.py:212:            store=AgentStore(tmp_path / "agent.db"),
tests/unit/test_agent_controller_activity.py:277:            store=AgentStore(tmp_path / "agent.db"),
tests/unit/test_agent_store.py:31:    database = tmp_path / "runtime" / "agent.db"
tests/unit/test_agent_store.py:38:    database = tmp_path / "runtime" / "agent" / "agent.db"
tests/unit/test_agent_store.py:48:    database = tmp_path / "agent.db"
tests/unit/test_agent_store.py:57:    database = tmp_path / "agent.db"
tests/unit/test_agent_store.py:66:    database = tmp_path / "agent.db"
tests/unit/test_agent_store.py:95:    store = AgentStore(tmp_path / "agent.db")
tests/unit/test_agent_store.py:102:    store = AgentStore(tmp_path / "agent.db")
tests/unit/test_agent_store.py:109:    store = AgentStore(tmp_path / "agent.db")
tests/unit/test_agent_store.py:115:    store = AgentStore(tmp_path / "agent.db")
tests/unit/test_agent_store.py:125:    store = AgentStore(tmp_path / "agent.db")
tests/unit/test_agent_store.py:136:    store = AgentStore(tmp_path / "agent.db")
tests/unit/test_agent_store.py:150:    store = AgentStore(tmp_path / "agent.db")
tests/unit/test_agent_store.py:159:    store = AgentStore(tmp_path / "agent.db")
tests/unit/test_agent_store.py:167:    store = AgentStore(tmp_path / "agent.db")
tests/unit/test_agent_store.py:175:    database = tmp_path / "agent.db"
tests/unit/test_product_cli.py:21:                str(tmp_path / "agent.db"),
tests/unit/test_product_service.py:20:        "agent_database": tmp_path / "agent.db",
tests/unit/test_product_service.py:136:    create_task(tmp_path / "agent.db")
tests/unit/test_product_service.py:174:        tmp_path / "agent.db",
tests/unit/test_product_service.py:191:        tmp_path / "agent.db",
tests/unit/test_web_app.py:41:    settings.VULNHUNTER_AGENT_DATABASE = str(tmp_path / "agent.db")
tests/unit/test_web_app.py:164:            store=AgentStore(tmp_path / "agent.db"),
tests/unit/test_web_app.py:193:    AgentStore.initialize_database(web_paths / "agent.db")
tests/unit/test_web_app.py:213:    AgentStore.initialize_database(web_paths / "agent.db")
tests/unit/test_web_app.py:302:    AgentStore.initialize_database(Path(web_paths / "agent.db"))
tests/unit/test_web_app.py:563:    store = AgentStore(Path(web_paths / "agent.db"))
vulnhunter/product/cli.py:20:    parser.add_argument("--agent-database", type=Path, default=Path("agent.db"))
vulnhunter/product/service.py:57:    agent_database: Path = Path(".local/runtime/agent/agent.db")
vulnhunter/web/settings.py:243:    str(BASE_DIR / ".local" / "runtime" / "agent" / "agent.db"),
```

## 11. Hosting preparation

```text
./config/deployment/gunicorn.conf.py
./docs/setup/DEPLOYMENT_READINESS.md
```

## 12. Changed migrations

```text

```

## 13. Work still requiring proof

1. Review every uncommitted source change.
2. Download and verify qwen3.5:2b-q4_K_M if absent.
3. Complete and test the governed local Ollama provider.
4. Diagnose Graphify SIGILL or retain a fail-closed disabled state.
5. Validate context-broker fallback without Graphify.
6. Correctly initialize the runtime store instead of creating a fake database.
7. Test login and all core authorized web routes.
8. Verify the first administrator and role initialization.
9. Validate approvals, evidence immutability and publication gates.
10. Prepare local Gunicorn operation.
11. Activate PostgreSQL/systemd only after local acceptance.
12. Keep Groq disabled until sanitisation and routing are independently verified.
13. Perform the frontend-only redesign after backend acceptance.
14. Review and back up all changes before any commit or push.

## 14. Capability states

| Capability | State |
|---|---|
| Graphify | `GRAPH_AVAILABLE_REQUIRES_VALIDATION` |
| Graphify hook | `DISABLED` |
| Graphify MCP | `INTENTIONALLY_DISABLED` |
| Qwen 2B | `NOT_INSTALLED` |
| Qwen 9B | `STORED_INACTIVE` |
| Groq | `CREDENTIAL_PRESENT_BUT_NOT_ACCESSED / INTENTIONALLY_DISABLED` |
| Live scans | `INTENTIONALLY_DISABLED` |
| Machine Oracle execution | `INTENTIONALLY_DISABLED` |
| Automatic publication | `INTENTIONALLY_DISABLED` |
| Production hosting | `NOT_ACTIVATED` |

## 15. Rollback warning

> The working tree contains substantial uncommitted work. Do not run
> git reset --hard, git clean, checkout over modified files, rebase, merge or
> remove generated/runtime directories before creating a separate backup and
> reviewing the changes.
