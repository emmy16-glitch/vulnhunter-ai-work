# Source Hunt Controlled Corpus and Campaign

## Status

This is the governed ground-truth layer for Source Hunt Intelligence V2 benchmark acceptance.
It is intentionally limited to **controlled local Python fixtures**. It does not authorize a
repository, scan a target, execute fixture code, call Groq, apply a fix, merge a branch, or
publish a finding.

The seed fixture under `tests/fixtures/source_hunt_controlled/python_core/` is a **candidate
corpus specification**, not automatically accepted ground truth. Repository CI may exercise the
governance mechanics with test identities, but those synthetic test approvals are not a human
corpus release and must not be used to promote V2.

## Why this layer exists

The benchmark evaluator added in the previous batch can calculate precision, recall, F1, false
positives and false negatives, but those numbers are only meaningful when the expected answers
were independently reviewed. The engine under evaluation must not be allowed to silently invent,
edit or cherry-pick its own labels.

This layer therefore separates:

1. fixture source preparation;
2. exact source/line binding;
3. two independent reviewer decisions;
4. separate administrator release;
5. reviewed-suite assembly;
6. baseline-versus-candidate evaluation.

## Seed controlled fixture

`python_core/app.py` is source-only benchmark material and carries an explicit never-execute
warning. The initial case specification contains eight cases across four families:

- path traversal: one direct vulnerable case and one guarded case;
- command injection: one direct vulnerable case and one guarded case;
- SQL injection: one direct vulnerable case and one guarded case;
- template injection: one direct vulnerable case and one guarded case.

The guarded examples deliberately use guard names already recognized by the current deterministic
Python mapper (`resolve`, `sanitize`, `validate`, and `escape`). The corpus is still review data,
not proof that the mapper or model will classify every case correctly.

## Exact source binding

Case specifications do not hard-code fragile line numbers. Each case names:

- a stable case ID;
- vulnerability class;
- repository-relative path;
- an exact unique source-line anchor;
- whether the case is expected to be vulnerable.

`ControlledCorpusDraftBuilder` resolves each anchor against an exact `RepositorySnapshot`. A draft
records the source file SHA-256, resolved line range, repository ID, source revision and snapshot
SHA-256. Preparation fails if the file changed after snapshot creation, the anchor is missing or
ambiguous, the path is outside the fixture repository, or the corpus does not contain both
positive and negative cases.

## Human authority and review separation

A draft binds exactly two assigned governance identities. Both must currently be active and hold
the `reviewer` role. The preparer cannot be either reviewer.

Each reviewer authenticates through the existing `GovernanceStore` and creates a
`CorpusReviewAttestation` bound to:

- exact draft ID and SHA-256;
- reviewer ID;
- reviewer identity-record SHA-256;
- approved/rejected verdict;
- human reason;
- review timestamp;
- attestation SHA-256.

Reviews are written to `CorpusReviewLedger`, an append-only per-draft ledger. The first decision
from an assigned reviewer is immutable. A rejection cannot later be hidden by supplying a
different approval file. If a rejected label is corrected, a new source/case draft with a new
digest must be prepared and reviewed.

Corpus release requires both exact assigned reviews to be approvals. The releasing identity must
be an active `campaign_admin` and must be different from the preparer and both reviewers. Current
reviewer identity records must still match their assignment and attestation bindings.

## Reviewed suite release

A `ReviewedSourceBenchmarkSuite` embeds the complete released corpus artifacts rather than merely
accepting unverified corpus IDs. Its validator reconstructs the benchmark suite from those corpus
releases and fails if the suite entries do not match the reviewed provenance.

Only `controlled_lab` corpora are permitted in this reviewed-suite path. Synthetic corpora can
still be evaluated by the lower-level benchmark tooling, but they cannot enter this controlled
promotion evidence path.

## Management command

The lifecycle is exposed through one command so each action uses the same authority rules:

```bash
python manage.py vh_source_hunt_corpus <action> ...
```

Secrets are never accepted as normal command-line values. Use an owner-only `--secret-file`, or an
interactive hidden prompt.

### 1. Prepare a draft

```bash
python manage.py vh_source_hunt_corpus \
  --prepare \
  --actor corpus-preparer \
  --secret-file /protected/preparer.secret \
  --fixture-root tests/fixtures/source_hunt_controlled/python_core \
  --revision <exact-fixture-revision> \
  --corpus-id python-core-v1 \
  --spec-file tests/fixtures/source_hunt_controlled/python_core/cases.json \
  --reviewer reviewer-a \
  --reviewer reviewer-b \
  --output /protected/corpus/python-core-v1.draft.json
```

The fixture root must be inside `VULNHUNTER_SOURCE_HUNT_CORPUS_ROOTS`. If the environment variable
is not set, the command defaults to the repository's controlled fixture root.

### 2. Review independently

Reviewer A and reviewer B each authenticate and run their own command:

```bash
python manage.py vh_source_hunt_corpus \
  --review /protected/corpus/python-core-v1.draft.json \
  --actor reviewer-a \
  --secret-file /protected/reviewer-a.secret \
  --decision approved \
  --reason "Reviewed exact source anchors and vulnerable/guarded labels." \
  --output /protected/corpus/python-core-v1.reviewer-a.json
```

The authoritative decision is also recorded in the append-only ledger configured by
`VULNHUNTER_SOURCE_HUNT_CORPUS_LEDGER_ROOT`.

### 3. Release the corpus

```bash
python manage.py vh_source_hunt_corpus \
  --release-corpus /protected/corpus/python-core-v1.draft.json \
  --actor corpus-release-admin \
  --secret-file /protected/release-admin.secret \
  --output /protected/corpus/python-core-v1.release.json
```

The command loads the two authoritative ledger decisions. Arbitrary review files cannot be
substituted at release time.

### 4. Release the reviewed suite

```bash
python manage.py vh_source_hunt_corpus \
  --release-suite \
  --actor corpus-release-admin \
  --secret-file /protected/release-admin.secret \
  --suite-id python-controlled-v1 \
  --corpus-release-file /protected/corpus/python-core-v1.release.json \
  --output /protected/corpus/python-controlled-v1.suite.json
```

Additional independently released controlled corpora can be added with repeated
`--corpus-release-file` arguments.

### 5. Produce baseline and candidate Source Hunt reports

The corpus command does **not** create these reports. Baseline and candidate reports must be
produced separately using the existing authorized Source Hunt flow for the exact reviewed fixture
snapshot. Existing source-processing approval, Groq privacy controls, model-call budgets and V2
worker boundaries remain in force.

Each report directory uses the existing convention:

```text
<report-dir>/<corpus-id>.json
```

### 6. Run the controlled campaign

```bash
python manage.py vh_source_hunt_corpus \
  --run-campaign /protected/corpus/python-controlled-v1.suite.json \
  --actor benchmark-admin \
  --secret-file /protected/benchmark-admin.secret \
  --policy-file /protected/corpus/source-hunt-policy.json \
  --baseline-report-dir /protected/corpus/reports/baseline \
  --candidate-report-dir /protected/corpus/reports/v2 \
  --baseline-engine-revision <baseline-commit> \
  --candidate-engine-revision <candidate-commit> \
  --output /protected/corpus/python-controlled-v1.evidence.json
```

The command consumes reports only. It performs no scan, provider call, repository clone, shell
execution or network request. Rejected candidate evidence is still written atomically before the
command exits with failure.

## Promotion rule

A green repository CI run is necessary but not enough to make V2 the default Source Hunt engine.
Promotion requires all of the following:

- an independently human-reviewed controlled corpus release;
- a reviewed benchmark suite release;
- baseline reports from the legacy engine over that exact suite;
- candidate reports from V2 over that exact suite;
- the immutable acceptance policy;
- an accepted `ControlledBenchmarkCampaignEvidence` bundle;
- normal human code review and merge authority.

No model, benchmark result, command, worker or CI job receives merge or publication authority.

## Known limitation

The campaign evidence binds the exact report bytes and records the baseline/candidate engine
revision labels through the underlying acceptance bundle. The current `SourceHuntReport` schema
does not itself contain a code-build commit attestation, so report-to-engine-revision provenance
still depends on the controlled report-generation procedure. A future isolated multi-revision
harness can strengthen this by producing signed or independently attested engine-run manifests.
This limitation must remain visible and must not be described as cryptographic build provenance.

## Accuracy language

Every draft, release, suite and campaign evidence object carries
`production_accuracy_claim_permitted=false`. Controlled-lab results may be used for regression and
promotion decisions, but they must never be described as production or real-world accuracy.
