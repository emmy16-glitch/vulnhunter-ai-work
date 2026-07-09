# Transactional Autoresearch Engine

## Purpose

The research engine turns one bounded hypothesis into a reproducible keep-or-revert experiment. It is deliberately stricter than the general orchestration loop because it must prevent a candidate from improving a score by weakening the evaluator.

## Trusted flow

```text
clean primary repository
    -> immutable evaluator policy
    -> protected-file snapshot
    -> isolated Git branch/worktree
    -> exactly one candidate commit
    -> trusted baseline metric report
    -> trusted candidate metric report
    -> fixed shell-free verifiers
    -> protected-resource and path checks
    -> objective, regression, and safety gates
    -> deterministic accept/reject/inconclusive decision
    -> rejected worktree removed, evidence retained
    -> accepted candidate requires independent human promotion
```

## Resource classes

Every candidate-visible repository path is classified as:

- `editable`: may change only when the experiment specification also lists the path;
- `read_only`: visible for context or evaluation but any change causes rejection;
- `inaccessible`: secrets, local artifacts, production/customer data, private targets, authorization evidence, and similar resources that are not legitimate candidate inputs.

The most restrictive matching rule wins. An experiment specification cannot downgrade a read-only or inaccessible rule. Inaccessible paths are required to be absent from the tracked baseline; experiment creation stops if one is tracked. Untracked files are not copied into the Git worktree. This prevents accidental inclusion, but it is not a substitute for an operating-system sandbox or removal of previously committed secrets from Git history.

## Immutable evaluator boundary

The built-in policy protects at least:

- all tests;
- `AGENTS.md` and accepted ADRs;
- repository audit and CI workflows;
- scope, redaction, authorization, orchestration, and research-engine code;
- benchmark scenario and manifest logic;
- local artifact directories;
- environment files, keys, credentials, production data, customer data, and private-target inventories.

At experiment creation, the trusted primary repository is inventoried and protected resources are hashed. Candidate evaluation fails when a protected file is missing or different.

## Transactional Git model

Each experiment receives a dedicated branch and worktree outside the primary worktree. The candidate must be exactly one clean commit directly above the recorded baseline.

A rejected or inconclusive experiment:

1. retains its manifest, metric reports, patch, verifier outputs, decision, and event chain;
2. removes its isolated worktree and experiment branch by default;
3. never resets, rewrites, or dirties the primary branch.

An accepted experiment is not automatically merged. A distinct human promoter must provide the exact experiment ID, and the primary repository must still be clean and at the original baseline. Promotion uses one guarded cherry-pick and aborts on conflict.

## Objective gate

The experiment defines:

- one objective metric;
- maximize or minimize direction;
- minimum meaningful improvement;
- non-objective regression metrics and allowed degradation;
- required boolean safety checks;
- fixed deterministic verifiers;
- file, diff, time, token, and cost ceilings.

Acceptance requires every gate to pass. A high objective score cannot compensate for a safety, integrity, scope, redaction, authorization, review, or leakage failure.

## Metric reports

Metric input is strict non-executable JSON. Values must be finite numbers and safety checks must be booleans. Reports are bound to an independent evaluator identity and SHA-256 source hash.

The current engine records evaluator identity but does not cryptographically authenticate it. Signed actor attestations remain technical debt.

## Outer-loop analysis

`vulnhunter research meta-analyze` examines experiment history for:

- repeated hypothesis fingerprints;
- overused strategy families;
- underused strategy families;
- rejection concentration;
- windows with no accepted experiment.

It can propose new strategy weights, but it cannot:

- modify evaluator rules;
- alter safety gates;
- generate or inject executable Python;
- start an experiment;
- approve its own policy.

Every proposed search-policy generation requires explicit human approval.

## Commands

```bash
vulnhunter research template experiment.json
vulnhunter research create experiment.json --creator ... --builder ...
vulnhunter research prepare EXPERIMENT_ID --actor ...
vulnhunter research record-baseline EXPERIMENT_ID --evaluator ... --report baseline.json
vulnhunter research candidate EXPERIMENT_ID --builder ...
vulnhunter research evaluate EXPERIMENT_ID --evaluator ... --report candidate.json
vulnhunter research decide EXPERIMENT_ID --decider ...
vulnhunter research promote EXPERIMENT_ID --human ... --confirm EXPERIMENT_ID
vulnhunter research integrity EXPERIMENT_ID
vulnhunter research meta-analyze --output proposed-policy.json
vulnhunter research approve-policy proposed-policy.json --human ...
```

## Honest limitations

The engine provides strong application-level controls, integrity checks, role separation, and transactional Git isolation. It is not a kernel sandbox. A local account that owns every file can still attempt to bypass filesystem permissions; acceptance therefore relies on trusted baseline hashes and deterministic rejection rather than claiming impossible local isolation.

The engine also does not authenticate actor identities, sign artifacts, pin DNS connections, or create real-world performance evidence. Those remain separate security and validation workstreams.
