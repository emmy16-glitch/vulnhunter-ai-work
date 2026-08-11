# Changelog

All notable project changes are documented here. The project has not yet made a production release.

## Unreleased

### Documentation / product-governance reconciliation — 2026-08-11

- established explicitly authorised **public Internet targets** as a supported product class while preserving the rule that a public URL is never permission;
- added `docs/product/PUBLIC_TARGET_ASSESSMENT.md` with exact authorization, target-class, DNS/address containment, Host/TLS identity, redirect, worker-capability and acceptance requirements;
- added `docs/product/LIVE_EXECUTION_ACTIVITY.md` so queued/running website, Source Hunt and APK work must expose persisted operational activity in the originating workspace;
- made current implementation status explicit: the existing passive Nuclei worker remains private-target-only until a separate public-capable transport/worker path is implemented and accepted;
- reconciled `AGENTS.md`, web-agent rules, README, product definition, security/system architecture, authorization, Nuclei, Source Hunt, web-application and chat-first documents;
- reconciled `CURRENT_STATE.md`, `ROADMAP.md` and `KNOWN_FAILURES.md` so contract approval, runtime implementation and manual/automated acceptance are not confused;
- added ADR 0022 for authorised public targets and marked ADR 0001's product-level public-target prohibition superseded while retaining its containment rationale;
- retired stale future-master/total-programme/milestone documents as current authority while preserving them as historical provenance;
- added/updated agent entry points for Codex/AGENTS, Cline, GitHub Copilot, Claude Code, Gemini and Cursor so they all route to the same current authority chain;
- preserved the locked conversation/task-first UI Contract V2 and strengthened live-running/public-target browser acceptance requirements;
- did **not** claim or enable public scanner runtime by documentation alone.

### Historical Nuclei foundation

Earlier milestones introduced the governed scanner protocol, manager/worker separation, version/template pinning, bounded process/evidence contracts and fail-closed activation. Historical milestone documents are retained for provenance but no longer own current runtime status or delivery order.
