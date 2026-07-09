# Bounded Orchestration Loop and Evaluation Harness

## Purpose

The orchestration subsystem turns a proposed engineering change into a bounded, auditable workflow rather than an open-ended autonomous agent session.

The mandatory lifecycle is:

```text
task specification
    -> project context
    -> restricted builder action
    -> deterministic verification
    -> independent security-policy verification
    -> independent implementation review
    -> explicit human approval
    -> documentation and learning record
```

The harness does not autonomously edit source code. A builder—human or agent—works inside declared file boundaries. The harness then measures the actual repository state and refuses unsupported completion claims.

## Six mandatory loop definitions

Every `LoopSpec` must define:

1. a precise objective;
2. required project context;
3. allowed actions and repository paths;
4. deterministic verifiers and required evidence;
5. stop controls and recovery instructions;
6. an append-only audit trail, created automatically by the store.

A specification that omits any of these elements is invalid.

## Role separation

The recorded roles are:

- **Builder** — implements the bounded change.
- **Test runner** — executes the fixed deterministic verifier suite.
- **Security verifier** — runs an independent policy check over the diff.
- **Reviewer** — evaluates the implementation, evidence, limitations, and regressions.
- **Human approver** — approves or rejects the reviewed change.

The system rejects reuse of the same pseudonymous actor across roles that must be independent.

## Proof-based completion

Completion is based on stored evidence, not a builder statement. Evidence includes:

- changed-file list;
- out-of-scope path detection;
- diff byte count;
- diff SHA-256;
- repository change fingerprint;
- exit code, duration, output hash, and redacted excerpt for each verifier;
- security-policy findings;
- independent review decision and limitations;
- human approval record;
- changed documentation paths and final learning record.

The fixed verifier registry currently supports:

- Ruff lint;
- Python bytecode compilation;
- pytest;
- Ruff format check;
- `git diff --check`.

Commands are executed as argument arrays with `shell=False`. Arbitrary commands from the specification are never executed.

## Hard controls

Each loop enforces:

- maximum iterations;
- maximum elapsed time;
- per-verifier timeout;
- maximum consecutive failures;
- repeated-error detection;
- no-progress detection;
- changed-file ceiling;
- diff-size ceiling;
- optional token budget;
- optional cost budget;
- explicit human escalation;
- guarded rollback that refuses to rewrite committed history.

## Audit integrity

Each event records:

- sequence number;
- loop ID;
- event type;
- actor ID;
- UTC timestamp;
- redacted payload;
- previous-event hash;
- event hash.

The full chain is revalidated before a loop can be considered complete.

## Security-policy verification

The deterministic security gate rejects or flags:

- files outside the declared boundary;
- generated databases or model artifacts;
- sensitive-looking filenames;
- automatic HTTP redirects;
- environment proxy inheritance;
- disabled TLS verification;
- shell execution;
- possible hard-coded secrets;
- security-critical source changes without documentation.

This gate is a sentinel, not a complete security proof. The independent reviewer and human approver remain necessary.

## Recovery and rollback

`recovery-plan` is non-destructive and should be used first.

The guarded rollback requires:

- a state where rollback is permitted;
- exact loop-ID confirmation;
- `--apply`;
- unchanged Git HEAD since the loop baseline;
- no changed path outside the declared boundary.

It restores only the bounded working-tree changes. It never rewrites commits.

## CLI workflow

```bash
vulnhunter loop template loop-spec.json
vulnhunter loop create loop-spec.json --creator human-owner --builder builder-agent
vulnhunter loop verify LOOP_ID --runner test-runner
vulnhunter loop security-check LOOP_ID --verifier security-verifier
vulnhunter loop review LOOP_ID --reviewer reviewer-agent --decision approve --summary "..."
vulnhunter loop approve LOOP_ID --human human-owner --decision approve --note "..."
vulnhunter loop learn LOOP_ID --actor human-owner --summary "..." \
  --limitation "..." --documentation docs/intelligence/ORCHESTRATION_LOOP.md
```

The `artifacts/loops/` directory contains local operational evidence and remains outside the tracked source of truth.
