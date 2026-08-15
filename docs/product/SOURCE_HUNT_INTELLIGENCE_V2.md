# Source Hunt Intelligence V2

## Status

Source Hunt Intelligence V2 is an opt-in, fail-closed extension of the existing Python Source Hunt production slice. It reuses the existing repository snapshot, exact Groq source-processing approval, deterministic Python attack-surface mapper, privacy gate, evidence-reference validation, falsification, capability filter, remediation proposal, job queue, human review and release controls.

V2 does **not** authorize a repository, execute an exploit, clone an arbitrary repository, expand permitted paths, apply a fix, merge code, confirm a finding, set final severity, or publish a result.

The V2 worker is deliberately separate from the legacy worker during acceptance:

```bash
python manage.py vh_run_source_hunt_v2_worker --once
```

Both workers use the same queue lock, so they cannot consume the same queue concurrently.

## V2 flow

```text
exact approved local repository
→ exact Python snapshot + source-processing approval
→ deterministic Python entry point / sink surfaces
→ independent bounded specialist passes per surface
→ best evidence-bound hypothesis only
→ existing independent falsification
→ existing capability filter
→ existing remediation proposal
→ deterministic related-occurrence root-cause sweep
→ non-executing RED/GREEN proof plan
→ cryptographically bound V2 intelligence sidecar
→ human review
→ isolated developer-led remediation
→ deterministic reproduction receipt
→ strict read-only fix verification
```

## Specialist passes

V2 assigns each existing deterministic attack surface to a primary specialist and one independent second pass. Current roles are:

- injection;
- access control;
- navigation/filesystem boundary;
- network boundary;
- unsafe deserialization;
- business logic;
- cryptography;
- sink-driven backstop.

The mapper remains authoritative for source facts. A specialist cannot introduce a file, source hash, entry point, sink or line range outside the supplied deterministic attack surface. Each specialist call is bounded by the existing model-call, prompt, output and timeout limits. A specialist failure or invented reference is discarded; if every specialist fails or abstains the surface abstains.

The current implementation executes the independent passes sequentially inside the worker rather than introducing concurrent provider calls. They are logically independent but share the same immutable source facts. This preserves existing provider budgets and avoids race conditions in model-call accounting.

## Root-cause sweep

After a candidate survives falsification and the capability filter, V2 builds a deterministic root-cause fingerprint from:

- normalized vulnerability class;
- deterministic sink family;
- deterministic entry-point kind;
- guard-count shape.

It then searches the already-discovered deterministic surfaces for related occurrences. A sweep occurrence is **not** a confirmed vulnerability. It is a review lead that still requires its own evidence, falsification, capability assessment and human review before promotion.

The sweep is bounded and never scans outside the exact repository snapshot.

## RED/GREEN proof plan

A surviving candidate with a remediation proposal receives an immutable non-executing `SecurityProofPlan`. The plan binds:

- candidate ID;
- original snapshot SHA-256;
- approved target files;
- proposed RED security regression test;
- proposed GREEN verification recipe;
- original evidence-bound condition;
- required verifier classes;
- plan SHA-256.

The proof plan is data only. VulnHunter does not execute submitted test strings or model-generated commands.

A separate isolated deterministic runner may later produce a `ReproductionReceipt` showing that:

1. the vulnerable state was reproduced in the approved isolated fixture;
2. the security test passes after the fix;
3. the original evidence-bound condition is independently blocked;
4. the receipt is bound to the exact proof-plan digest and original/fixed revisions.

`StrictReadOnlyFixVerifier` validates this proof chain before delegating to the existing read-only fix verifier. It retains no shell, network, repository-write, merge or publication authority.

## Repository graph summary

V2 builds a bounded Python symbol/call summary from the exact snapshot. It records counts for:

- Python files;
- classes;
- functions;
- deterministically resolved call edges;
- resolved `self.method()` edges;
- ambiguous calls;
- unresolved calls.

This summary is advisory context and does not widen the deterministic attack surface. The existing mapper continues to abstain when a call target is ambiguous rather than pretending complete taint coverage.

## Language inventory

V2 inventories common source-language suffixes and explicitly records coverage state.

Current state:

- Python: `production` for the existing declared deterministic Source Hunt slice;
- JavaScript/TypeScript, Java, Kotlin, Go, PHP, C#, C and C++: `inventory_only`;
- unrecognized languages: not claimed as analyzed.

Inventory-only means files can be counted for truthful coverage reporting, but no vulnerability-analysis claim is made for those languages. A future language indexer must emit the same normalized attack-surface contracts and pass independent acceptance before its status can become `production`.

## Ground-truth benchmark

`benchmark_v2.py` provides deterministic evaluation against immutable synthetic or controlled-laboratory ground truth. It records:

- true positives;
- false positives;
- false negatives;
- true negatives;
- precision;
- recall;
- F1;
- unmatched candidate IDs;
- source-report and snapshot provenance.

The benchmark schema intentionally accepts only `synthetic` and `controlled_lab` corpus kinds. Every benchmark report sets `production_accuracy_claim_permitted=false`. Controlled benchmark results must never be represented as production or real-world accuracy.

## Headless / CI admission

The headless service never accepts a repository URL and never clones source. CI must already have an operator-approved local checkout under `VULNHUNTER_SOURCE_HUNT_ROOTS`.

Before a job can be enqueued, a distinct human approver must create an immutable `HeadlessPermissionManifest` bound to:

- repository ID;
- exact revision;
- exact snapshot SHA-256;
- permitted repository-relative paths;
- requester identity;
- distinct approver identity;
- explicit remote-source-processing permission;
- one-run maximum;
- creation and expiry time;
- manifest SHA-256.

The manifest is consumed through an atomic one-use ledger before the existing Source Hunt job is queued. Replay fails closed.

The enqueue command is:

```bash
python manage.py vh_enqueue_source_hunt_headless \
  --repo /approved/local/repository \
  --revision <exact-revision> \
  --manifest-file /protected/path/headless-manifest.json \
  --approval-file /protected/path/source-processing-approval.json
```

The command only validates and queues. The separate V2 worker performs model-assisted source analysis under the existing Groq controls.

## Intelligence sidecar

The existing `SourceHuntReport` remains the authoritative finding-analysis record. V2 stores additional intelligence in a sidecar keyed by the same report ID and exact snapshot SHA-256. The sidecar contains:

- specialist assignments;
- related-occurrence sweeps;
- proof plans;
- graph summary;
- language inventory;
- V2 engine version;
- creation time.

A V2 worker refuses to claim V2 completion for an existing legacy report that lacks its V2 sidecar.

## Acceptance and rollout

V2 remains opt-in until the exact candidate commit passes the repository's mandatory gates, including Python 3.11/3.12 tests, Ruff, compileall, repository audit and Source Hunt worker tests. It must then be evaluated against controlled ground truth before replacing the legacy Source Hunt worker as the default.

The rollout must not weaken:

- exact source-processing approval;
- customer-data prohibition;
- source-reference hash/line validation;
- model-call budgets;
- human review authority;
- read-only verification;
- public-target restrictions;
- release and publication gates.
