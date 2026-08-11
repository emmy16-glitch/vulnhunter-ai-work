# Gemini — VulnHunter Repository Instructions

Read **`AGENTS.md` in full before making changes**. `AGENTS.md` is the binding repository operating manual; this file is only a tool-specific pointer.

For browser/UI work, also read the exact chain in `vulnhunter/web/AGENTS.md`.

Do not improvise around these permanent rules:

- authorised private and public website targets are supported product classes, but a URL is never authorization;
- public execution must follow `docs/product/PUBLIC_TARGET_ASSESSMENT.md` and preserve explicit worker capability plus DNS/address/Host/TLS containment;
- the existing private-only worker must not be weakened merely to make a public target execute;
- queued/running work must follow `docs/product/LIVE_EXECUTION_ACTIVITY.md` and show persisted task/activity truth;
- Source Hunt must follow `docs/product/SOURCE_HUNT.md`, including preflight and exact snapshot/path semantics;
- browser work follows the locked `docs/design/` contract and remains conversation/task-first;
- never fabricate progress, tool activity, evidence or findings;
- never expose hidden chain-of-thought/private reasoning;
- models never grant authorization, execution, verification, review, merge, release or publication authority;
- use `docs/intelligence/CURRENT_STATE.md` for implementation truth and `docs/intelligence/ROADMAP.md` for remaining delivery order;
- historical milestone/total-programme/future-plan documents are provenance only unless a current authority explicitly says otherwise.

When a requested change cannot preserve those boundaries, stop and report the blocker rather than weakening the contract.
