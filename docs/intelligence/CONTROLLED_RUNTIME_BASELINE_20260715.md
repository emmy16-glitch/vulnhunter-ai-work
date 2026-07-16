# Controlled Runtime Integration Baseline — 2026-07-15

- Worktree: `/mnt/vulnhunter-data/Projects/vulnhunter-ai-integrated-future`
- Branch: `milestone-27-integrated-intelligence-machine-oracle`
- Recorded HEAD: `c0f853275bf0b9598f962e0dd81cc997aa13fc01`
- Initial state: substantial staged, unstaged, and untracked Milestone 27 work was
  present. It is user-owned and must not be reset, cleaned, overwritten, committed,
  or moved to the completed Milestone 26 repository.
- Existing source foundations: `vulnhunter/repository_graph/`,
  `vulnhunter/context_broker/`, `vulnhunter/providers/`, `vulnhunter/agent/`, the
  Approval Centre, evidence and review stores, task graph, and authenticated Django
  surfaces. These are the extension points; no parallel `*_v2` packages are needed.
- Initial Graphify state: official `graphifyy==0.9.16` was installed in the isolated
  uv tool environment. The repository had only generated
  `graphify-out/cache/stat-index.json`; no valid `graph.json` or `GRAPH_REPORT.md`
  existed. Existing failure logs under `/home/okunlola_labs/` are preserved.
- Graphify activation boundary: `.codex/hooks.json` was absent, Git hooks reported
  not installed, and no Graphify MCP process was active.
- Initial provider state: generic injected provider runtime existed; there was no
  bounded Ollama HTTP connector, strict structured model-response contract, or live
  local health/inference evidence.
- Initial agent-store defect: web settings defaulted to repository-root `agent.db`,
  while product reads correctly refused to fabricate a missing file. `AgentStore`
  had no explicit schema-version or initialization command.
- Initial web state: Django authentication, role mapping, governance pages, status
  pages, and readiness endpoint existed. A local Django database and governance
  database existed; the required agent runtime store did not.
- Generated runtime artifacts: `graphify-out/`, `.local/`, `var/`, tool readiness
  reports, SQLite databases, caches, logs, and installation backups. Generated graph
  content is runtime intelligence and must remain ignored by Git.
- Tracked/source material: Python packages, tests, templates, static assets,
  configuration JSON, ADRs, product documentation, trackers, `.graphifyignore`, and
  deployment templates.

Safety invariant: intelligence providers may propose or abstain only. Authorization,
scope, approval, execution, evidence integrity, independent verification, human
confirmation, and publication remain VulnHunter-owned deterministic gates.
