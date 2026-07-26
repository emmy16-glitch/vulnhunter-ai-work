# Groq Source Hunt

## Purpose

Source Hunt is VulnHunter's attacker-first source-code analysis path. Groq is the only model provider. Deterministic repository controls establish what source exists, which paths are eligible, which entry points reach which sinks, and whether every model-supplied file, hash and line reference is genuine.

Groq may propose hypotheses, challenge them, assess attacker capability and draft remediation. It cannot authorize source processing, expand repository scope, execute tools, verify a finding, set final severity, apply a patch, merge code or publish a finding.

## Canonical flow

```text
operator-approved repository root
→ exact revision and content snapshot
→ repository, revision, snapshot-hash and path-bound Groq approval
→ non-secret file-backed job queue
→ separate Source Hunt worker
→ deterministic Python inventory and AST graph
→ attacker-accessible entry-point discovery
→ bounded source-to-sink paths
→ Groq reconnaissance
→ Groq attack-path hypothesis
→ separate Groq falsification
→ Groq capability filter
→ evidence-bound remediation and RED test proposal
→ isolated developer-led fix
→ read-only deterministic fix verification
→ independent human review
```

A candidate is not retained as an actionable issue unless it survives falsification and the capability filter identifies a meaningful security boundary break.

## Browser and worker separation

The browser never performs the multi-stage Groq hunt inside an HTTP request. A submission performs only bounded local work:

1. validate the operator and password step-up;
2. build and hash the exact repository snapshot;
3. create the time-limited source-processing approval;
4. persist a non-secret queued job;
5. return the queued identifier to the browser.

A separate worker atomically claims the job, changes it to `running`, performs the Groq stages, persists the report, and records `completed` or `failed`. Browser navigation, session loss, reverse-proxy timeouts and Gunicorn request limits therefore do not interrupt an active hunt.

The queue has four directories beneath `VULNHUNTER_SOURCE_HUNT_JOB_ROOT`:

```text
queued/
running/
completed/
failed/
```

Job files contain repository and approval metadata but never the Groq key, user password or governance secret.

## Exact remote source-processing approval

Before any source excerpt is transmitted, VulnHunter binds approval to:

- repository identifier;
- revision;
- complete eligible-file snapshot SHA-256;
- repository visibility;
- permitted repository-relative paths;
- provider identity `groq`;
- approving identity;
- approval and expiry times;
- approval-record SHA-256.

The browser additionally requires password re-authentication. The direct CLI requires an active governance administrator and an owner-only secret file. A changed file, changed path set, expired approval or different revision fails closed.

Customer data, credentials, cookies, authorization records, private keys and detected secrets remain prohibited even when source processing is approved.

## Current deterministic mapper

The first production slice supports Python. It:

- inventories regular `.py` files without following symlinks;
- excludes generated, virtual-environment, cache and local-runtime directories;
- enforces per-file, repository-byte and file-count limits;
- hashes every eligible file;
- discovers decorated web routes and externally invoked handlers;
- records request-like attacker inputs;
- builds bounded unambiguous inter-function call paths;
- identifies authorization, validation and sanitization guards;
- identifies bounded sink families including subprocess execution, dynamic code execution, unsafe deserialization, database operations, outbound requests, filesystem access and writes, template rendering and unsafe HTML marking.

Unsupported languages and ambiguous call targets are not silently treated as covered.

## Groq stages

### Reconnaissance

Receives repository metadata and deterministic attack surfaces. It may prioritize supplied surfaces but cannot create new source facts.

### Attack-path hunt

Produces a structured hypothesis containing the entry point, sink, exact path, assumptions, confidence and evidence references.

### Falsification

A separate request attempts to reject the hypothesis by finding unreachable code, missing attacker control, security guards, framework protections, contradictory source or unrealistic preconditions. Uncertainty should produce `rejected` or `abstained`.

### Capability filter

Determines the actual capability gained by the attacker. Suspicious syntax without a meaningful security boundary break is discarded.

### Remediation planning

Produces a minimal reviewable change, a failing security regression test, compatibility risks and an independent verification recipe. This stage does not edit the repository.

## Evidence integrity

Every source reference must match a file and SHA-256 from the exact snapshot, and every line range must exist in that file. References invented by Groq are rejected. Remediation target files must also exist in the snapshot.

Each source file is re-read and re-hashed immediately before its excerpt is prepared for Groq. Snapshot-to-transmission drift therefore fails closed.

The service has hard limits for files, bytes, attack surfaces, candidates, path depth, prompt size, output size, timeout and model calls. There is no open-ended agent loop.

## Fix and verify

VulnHunter's existing bounded orchestration and isolated-worktree controls remain responsible for implementing a proposed fix. The expected workflow is:

```text
safe exploit or reproduction fixture
→ failing security test (RED)
→ minimal bounded patch
→ security test passes (GREEN)
→ broader deterministic verifiers pass
→ original attack recipe independently shown blocked
→ read-only fix verifier verdict
→ human-controlled promotion or merge
```

The read-only verifier can emit:

- `fixed`;
- `partially_fixed`;
- `not_fixed`;
- `regression_detected`;
- `cannot_verify`;
- `out_of_scope_change`.

It accepts immutable snapshot data and verifier receipts only. It has no repository write, network, shell, approval or merge capability.

## Browser operation

Assessment operators can open **Analysis → Source Hunt** or use the Source Hunt action in the assessment workspace. The page uses the shared product shell and persisted job/report state; it does not display fabricated progress, findings or readiness.

Completed jobs link to their persisted report. Failed jobs retain a bounded safe error. Refreshing the page does not restart work.

## Worker operation

Run continuously:

```bash
python manage.py vh_run_source_hunt_worker --poll-seconds 0.5
```

Process one queued job and exit:

```bash
python manage.py vh_run_source_hunt_worker --once
```

Codespaces starts this worker automatically when Groq is enabled and the owner-private key file exists.

## Direct CLI operation

The direct CLI remains available for a supervised terminal workflow:

```bash
python manage.py vh_source_hunt \
  --repo /absolute/path/to/authorised-repository \
  --revision <commit-sha> \
  --visibility private \
  --permitted-path . \
  --actor <governance-admin-id> \
  --secret-file /owner-only/path/to/governance-secret \
  --approve-groq-source-processing
```

Configure approved roots and persistent stores with the platform path separator:

```bash
VULNHUNTER_SOURCE_HUNT_ROOTS=/workspaces/repo-a:/workspaces/repo-b
VULNHUNTER_SOURCE_HUNT_JOB_ROOT=/var/lib/vulnhunter/source-hunt-jobs
VULNHUNTER_SOURCE_HUNT_REPORT_ROOT=/var/lib/vulnhunter/source-hunts
```

## Limitations

Source Hunt does not claim complete semantic taint analysis, full language coverage, automatic exploitability in production, business impact, severity or publication readiness. The current source mapper is Python-first and deliberately abstains on ambiguity. Real private-source use also depends on the operator's review of Groq terms, retention and data controls.
