# Milestone 28 — Governed Nuclei Integration — Historical Record

**Status:** HISTORICAL / NON-AUTHORITATIVE

This milestone records an earlier Nuclei-integration stage and is retained for provenance only.

Do **not** use this file as the current scanner architecture, current roadmap, public-target policy or activation status.

## Current authorities

Use instead:

- `AGENTS.md`;
- `docs/product/NUCLEI_INTEGRATION.md`;
- `docs/product/PUBLIC_TARGET_ASSESSMENT.md`;
- `docs/product/LIVE_EXECUTION_ACTIVITY.md`;
- `docs/intelligence/CURRENT_STATE.md`;
- `docs/intelligence/ROADMAP.md`;
- current scanner/worker code, configuration and tests.

## Historical value

This milestone is useful for understanding why VulnHunter adopted controls such as:

- fixed/bounded Nuclei policy;
- reviewed templates;
- restricted command construction;
- candidate-only scanner output;
- no cloud/public-OAST/update behavior by default;
- manager/worker separation and activation gates.

Those ideas remain subject to current contracts and code.

## Current target-policy correction

The finished product is no longer private/laboratory-only. Explicitly authorised public targets are a supported product class under `PUBLIC_TARGET_ASSESSMENT.md`.

The current passive worker is still private-target-only until the public-capable transport/worker path is implemented and accepted.

Do not use this historical milestone either to prohibit authorised public-target work or to bypass the current worker boundary.

## Permanent agent rule

If any statement from this historical milestone conflicts with current state, roadmap, Nuclei integration, public-target, live-execution or UI contracts, the current authority wins.
