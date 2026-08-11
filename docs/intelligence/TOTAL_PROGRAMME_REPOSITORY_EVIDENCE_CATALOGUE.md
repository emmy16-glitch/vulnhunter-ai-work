# Total Programme Repository Evidence Catalogue — Historical Record

**Status:** HISTORICAL / NON-AUTHORITATIVE

This file originally catalogued older “total programme” capabilities and phases against a previous repository baseline.

It is retained only as historical provenance. It is **not** a current capability matrix, implementation status source or roadmap.

## Current sources

Use instead:

- `AGENTS.md` — security/engineering rules;
- `docs/intelligence/CURRENT_STATE.md` — current runtime capability classification;
- `docs/intelligence/ROADMAP.md` — current delivery order;
- `docs/intelligence/VULNHUNTER_MASTER_ARCHITECTURE.md` — current cross-system architecture;
- `docs/intelligence/KNOWN_FAILURES.md` — current unresolved limitations;
- focused product/security contracts;
- current code/tests/CI as implementation evidence.

## Why this catalogue is retired

The old table mixed:

- historical milestone states;
- planned future work;
- partial implementation classifications;
- old UI/provider/target assumptions;
- evidence paths tied to earlier baselines.

Those rows can become misleading after later PRs merge.

The product now explicitly defines authorised public-target assessment, persisted live execution activity and a locked UI Contract V2. Current ML programme state has also advanced beyond the older catalogue.

## Historical use

Use Git history/old PRs when investigating a prior milestone or architectural decision.

Do not use this file to:

- decide what is currently implemented;
- decide the next roadmap item;
- prohibit authorised public targets;
- claim public execution is already implemented;
- reintroduce old dashboard UI;
- reintroduce stale provider assumptions;
- override current Source Hunt/public/live-execution contracts.

## Permanent agent instruction

If an agent discovers a conflict between this historical file and a current authority, ignore this file and follow the current authority chain.
