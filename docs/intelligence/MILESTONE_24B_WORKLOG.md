# Milestone 24B Worklog — Agent Activity Foundation

## Baseline

- Required baseline: `fa330e4`
- Required branch: `milestone-24b-agent-activity-foundation`
- Milestone 24 UI work remains active in another worktree.
- Milestone 25A is checkpointed independently at `8ec0efc`.

## Scope

This milestone supplies the additive, framework-neutral foundation for the live
bounded-agent activity timeline. It does not modify the in-progress Milestone 24
interface or runtime files.

## Implementation

1. Strict event and polling-snapshot models.
2. Append-only per-run event store with sequence and SHA-256 chain validation.
3. Safe redaction and hidden-reasoning rejection.
4. Framework-neutral service and public read models.
5. Escaped HTML fragment, responsive CSS, and same-origin polling JavaScript.
6. Read-only integrity and inspection CLI.
7. Focused tests and integration documentation.

## Non-goals

- no route or template guessing while Milestone 24 is changing;
- no public or external scan;
- no connector activation;
- no arbitrary shell execution;
- no Git write automation;
- no deployment;
- no autonomous approval, adjudication, release, or model training;
- no hidden chain-of-thought exposure.

## Promotion plan

After Milestone 24 is committed, create a combined integration branch, integrate
Milestone 24, Milestone 25A commit `8ec0efc`, and this milestone. Then add the thin
Milestone 24 adapter, run focused tests, one complete suite, the project audit, and
only then merge and push `main`.
