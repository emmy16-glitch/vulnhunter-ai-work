# Claude Code — VulnHunter Repository Instructions

Before doing any work in this repository, read **`AGENTS.md` in full**. It is the binding repository operating manual.

Do not treat this file as a second source of truth.

For browser/UI work, follow the exact additional read order defined by `AGENTS.md` and `vulnhunter/web/AGENTS.md`.

Permanent high-level rules:

- authorised private and public targets are supported product classes;
- a public URL never grants permission;
- public execution must follow `docs/product/PUBLIC_TARGET_ASSESSMENT.md` and must not be enabled by weakening private-worker/scope protections;
- long-running queued/running work must follow `docs/product/LIVE_EXECUTION_ACTIVITY.md` and expose persisted operational activity rather than fake progress;
- Source Hunt must follow `docs/product/SOURCE_HUNT.md`, including deterministic preflight and truthful permitted-path semantics;
- UI must follow the locked `docs/design/` authority chain and remain conversation/task-first;
- never expose hidden chain-of-thought/private model reasoning;
- models never grant authorization, execution, verification, review, merge, release or publication authority;
- `docs/intelligence/CURRENT_STATE.md` owns current implementation status;
- `docs/intelligence/ROADMAP.md` owns the current dependency order;
- historical milestone/total-programme/future-plan documents do not override current authorities.

If a requested implementation conflicts with these rules, stop and report the conflict instead of silently weakening a boundary.
