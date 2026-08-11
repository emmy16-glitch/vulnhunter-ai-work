# Total Programme Gap Matrix — Historical Record

**Status:** HISTORICAL / NON-AUTHORITATIVE

This file previously summarized a 608-row coverage matrix derived from the retired `VULNHUNTER_FUTURE_MASTER_PLAN.md`.

That model is no longer the current product/status/roadmap authority.

## Current sources

Use:

- `docs/intelligence/CURRENT_STATE.md` for implemented/partial/unavailable status;
- `docs/intelligence/KNOWN_FAILURES.md` for current unresolved gaps;
- `docs/intelligence/ROADMAP.md` for dependency order;
- `docs/product/PUBLIC_TARGET_ASSESSMENT.md` for authorised public-target requirements;
- `docs/product/LIVE_EXECUTION_ACTIVITY.md` for running-task requirements;
- the focused product/security/ML contracts relevant to the task.

## Historical value

The old matrix remains available in Git history when provenance for a prior “total programme” requirement is needed.

Do not use historical counts, waves or classifications from this file to decide current implementation work.

## Current transition rule

Current high-priority gaps are maintained explicitly in `ROADMAP.md` rather than inferred from old 608-row classifications.

The present order begins with:

1. authorised public-target passive execution;
2. persisted live execution activity;
3. UI Contract V2 runtime migration;
4. Source Hunt preflight/path semantics;
5. cross-workflow acceptance;
6. remaining ML/Hugging Face and production-readiness work.

## Permanent agent rule

If any old total-programme requirement conflicts with current authorization, public-target, live-execution, UI, Source Hunt, ML or runtime status contracts, current authority wins.
