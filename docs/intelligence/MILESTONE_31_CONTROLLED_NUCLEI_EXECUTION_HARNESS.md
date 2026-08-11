# Milestone 31 — Controlled Nuclei Execution Harness — Historical Record

**Status:** HISTORICAL / NON-AUTHORITATIVE

This milestone documents an earlier stage when the scanner manager/worker architecture and Nuclei execution harness were being introduced and production execution was intentionally disabled.

It is preserved for provenance but is no longer a current scanner status document.

## Current authorities

Use instead:

- `AGENTS.md`;
- `docs/product/NUCLEI_INTEGRATION.md`;
- `docs/product/PUBLIC_TARGET_ASSESSMENT.md`;
- `docs/product/LIVE_EXECUTION_ACTIVITY.md`;
- `docs/intelligence/SYSTEM_ARCHITECTURE.md`;
- `docs/intelligence/CURRENT_STATE.md`;
- `docs/intelligence/ROADMAP.md`;
- current scanner manager/worker code/config/tests.

## Historical value

This milestone remains useful for understanding the origin of:

- manager/worker separation;
- versioned scanner protocol;
- immutable execution request design;
- compatibility/version pinning;
- bounded rate/concurrency/output/timeouts;
- no raw shell/argv/secret fields;
- fail-closed activation.

## Current correction

The repository has evolved beyond the milestone's `future isolated worker` / `execution disabled` state. The current passive private-target worker path exists, while the authorised public-target worker/transport path is the next required implementation programme.

Do not use this historical file to determine current activation status or target policy.

## Permanent agent rule

If any historical engine version, adapter status, lifecycle statement or remaining-work item here conflicts with the current contracts/status documents, current authority wins.
