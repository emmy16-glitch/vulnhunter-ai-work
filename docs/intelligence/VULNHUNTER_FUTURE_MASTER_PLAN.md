# VulnHunter AI — Historical Future Master Plan

**Owner:** Emmanuel Okunlola  
**Original creation:** 2026-07-12  
**Status:** RETIRED AS AN AUTHORITY SOURCE — HISTORICAL POINTER ONLY

This file previously described itself as the single source of truth for future VulnHunter architecture. That is no longer correct and must not be used by Codex, Cline, Claude Code, Copilot, Cursor, ChatGPT or humans as a competing roadmap.

## Current authorities

Use instead:

1. repository-root `AGENTS.md` — security/engineering authority;
2. `docs/intelligence/VULNHUNTER_MASTER_ARCHITECTURE.md` — current cross-system blueprint;
3. `docs/intelligence/CURRENT_STATE.md` — actual implementation status;
4. `docs/intelligence/ROADMAP.md` — dependency-ordered remaining work;
5. current focused product/security contracts, including:
   - `docs/product/PUBLIC_TARGET_ASSESSMENT.md`;
   - `docs/product/LIVE_EXECUTION_ACTIVITY.md`;
   - `docs/product/CHAT_FIRST_WORKSPACE.md`;
   - `docs/product/SOURCE_HUNT.md`;
   - `docs/product/NUCLEI_INTEGRATION.md`;
   - `docs/product/AI_ROUTING.md`;
6. locked browser design contracts under `docs/design/`.

## Why this document was retired

The historical plan accumulated assumptions that are no longer safe as current authority, including older product sequencing, earlier provider/UI assumptions and private-laboratory-only wording.

The product direction now explicitly supports **authorised public targets** while retaining exact authorization and network containment. The browser is governed by the locked chat/task-first UI contract. Long-running work is governed by the persisted live execution activity contract. Current ML/programme status is maintained separately.

Keeping the old plan as a competing “single source of truth” would cause future agents to undo newer decisions.

## Historical-use rule

This file may be cited only as historical provenance for why a capability was considered or how an older milestone was sequenced.

It must not be used to:

- prohibit authorised public targets;
- weaken public-target authorization/transport requirements;
- reintroduce dashboard-first UI;
- reintroduce stale provider assumptions;
- override `CURRENT_STATE.md`;
- override `ROADMAP.md`;
- claim old incomplete work is current;
- revive retired implementation patterns.

## Permanent agent instruction

Do **not** begin a new agent session by treating this file as canonical.

Begin with `AGENTS.md` and the current authority chain.
