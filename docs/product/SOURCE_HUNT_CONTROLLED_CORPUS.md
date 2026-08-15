# Source Hunt Controlled Corpus and Promotion Campaign

## Status

This capability is the governed acceptance layer for Source Hunt Intelligence V2. It turns proposed controlled-laboratory labels into promotion-eligible benchmark evidence only after independent human review.

It does **not** claim that V2 has passed a production benchmark. It does not scan public targets, run exploits, execute submitted proof text, call Groq, clone repositories, create source-processing permission, merge code, publish findings, or describe controlled-lab metrics as production accuracy.

The parse-only fixture seed in this batch is:

`benchmarks/source_hunt/controlled_python_v1/`

It contains ten paired cases spanning path traversal, command injection, SQL injection, SSRF, and unsafe deserialization. Each class has one deliberately vulnerable case and one safe/guarded control, so the campaign measures false positives as well as detection. The fixture is source input only; the controlled-corpus workflow reads it but never imports or executes it.

No reviewed ground-truth release is committed with the fixture. Labels become promotion-eligible only through the authenticated review lifecycle below.

## Marker-defined corpus

`controlled_python_v1/definition.json` describes each proposed truth case using a unique `VH-GT:*` marker instead of a hand-maintained line number. The definition is intentionally identity-neutral: source files cannot declare who has review authority. The authenticated governance identity supplied when the draft is created is authoritative.

`ControlledFixtureCompiler`:

- builds two exact local snapshots and fails if the source changes between them;
- resolves every marker exactly once;
- verifies each referenced file against its snapshot SHA-256;
- converts the marker line into an immutable `SourceGroundTruthCase`;
- requires at least one vulnerable case and one safe control;
- emits only `controlled_lab` ground truth;
- never imports or executes fixture source.

The compiled snapshot revision is set to its exact snapshot SHA-256. Moving, removing, duplicating, or renaming a marker therefore requires a new reviewed draft rather than silently shifting an existing truth label.

## Authority model

A controlled corpus requires three separated human actions:

1. one authenticated governance reviewer proposes the exact label set;
2. a second authenticated reviewer independently approves or rejects that exact draft digest;
3. a third authenticated reviewer independently approves or rejects that same exact draft digest.

The draft creator cannot approve their own labels. The two approving reviewers must be distinct. A rejection blocks release. A reviewer who is no longer active or no longer holds the `reviewer` role cannot be counted when release is created.

Reviewer passwords are never stored in corpus records and are never accepted as command-line arguments. Interactive draft/review commands prompt through `getpass` and persist only the stable reviewer ID plus tamper-evident review evidence.

## Exact source binding

A `ControlledCorpusDraft` stores a sanitized fixture binding rather than the local repository root. It contains:

- repository ID;
- exact revision;
- exact repository snapshot SHA-256;
- repository-relative source paths;
- exact source-file SHA-256 values;
- source line counts;
- immutable `SourceBenchmarkCorpus` labels;
- authenticated label creator identity and time;
- draft SHA-256 and content-derived draft ID.

Every ground-truth case must reference a source file in the exact fixture snapshot and a line range inside that file. Synthetic corpora are rejected from this lifecycle.

## Review and release

Each `ControlledCorpusReviewAttestation` is bound to the exact draft ID, draft SHA-256, corpus SHA-256, authenticated reviewer ID, approve/reject decision, review time, and a content-derived attestation ID and SHA-256.

A `ControlledCorpusRelease` is created only when at least two distinct non-creator reviewers approved the exact same draft. Review attestations use canonical reviewer order before release hashing. Release re-checks current governance identities and stores the canonical reviewer set and release digest.

The release remains controlled-lab evidence. `production_accuracy_claim_permitted` is always `false`.

## Operator workflow

### 1. Create the marker-defined draft

For the committed ten-case fixture:

```bash
python manage.py vh_create_source_hunt_corpus_draft \
  --repo benchmarks/source_hunt/controlled_python_v1 \
  --definition-file benchmarks/source_hunt/controlled_python_v1/definition.json \
  --creator-id <reviewer-id> \
  --governance-db /protected/governance.sqlite3 \
  --output /protected/corpus-draft.json
```

`VULNHUNTER_SOURCE_HUNT_ROOTS` must already contain the fixture location. The command prompts for the creator's governance credential, compiles marker lines, binds the exact snapshot, and creates the authenticated draft in one operation.

For another already-labelled controlled fixture, the same command can instead accept `--corpus-file /protected/proposed-corpus.json` plus `--revision <exact-revision>`. A manually proposed corpus is not trusted merely because its schema is accepted; it still requires the reviews below.

### 2. Obtain two independent reviews

Run once for each independent reviewer:

```bash
python manage.py vh_review_source_hunt_corpus \
  --draft-file /protected/corpus-draft.json \
  --reviewer-id <independent-reviewer-id> \
  --decision approve \
  --governance-db /protected/governance.sqlite3 \
  --output /protected/review-a.json
```

A reviewer can use `--decision reject`; any included rejection prevents release.

### 3. Release the reviewed corpus

```bash
python manage.py vh_release_source_hunt_corpus \
  --draft-file /protected/corpus-draft.json \
  --review-file /protected/review-a.json \
  --review-file /protected/review-b.json \
  --governance-db /protected/governance.sqlite3 \
  --output /protected/controlled-release.json
```

This operation does not generate or change labels. It verifies the review chain and emits immutable release evidence.

### 4. Produce baseline and candidate reports

Existing authorized Source Hunt workers produce reports separately. This subsystem cannot run them and cannot grant their required source-processing permission.

For every released corpus, place the already-produced report at:

```text
<baseline-report-dir>/<corpus-id>.json
<candidate-report-dir>/<corpus-id>.json
```

Each report must be terminal (`COMPLETE` or `ABSTAINED`) and match the exact repository ID, source revision, and snapshot SHA-256 bound by the release. A terminal `ABSTAINED` report is deliberately scored as zero detections: vulnerable ground-truth cases therefore become false negatives, while safe cases become true negatives. Nonterminal stages are rejected instead of being scored.

### 5. Run the controlled promotion campaign

```bash
python manage.py vh_check_source_hunt_controlled_campaign \
  --release-file /protected/controlled-release.json \
  --policy-file /protected/source-hunt-acceptance-policy.json \
  --baseline-report-dir /protected/baseline-reports \
  --candidate-report-dir /protected/v2-reports \
  --baseline-engine-revision <exact-baseline-commit> \
  --candidate-engine-revision <exact-v2-commit> \
  --output /protected/controlled-campaign-evidence.json
```

Multiple `--release-file` arguments may be supplied. Releases are canonicalized by corpus ID so input ordering cannot change evidence identity.

The command evaluates only pre-produced reports. It makes no model call and no network request. If the candidate fails an absolute or baseline-relative policy gate, rejection evidence is written first and the command exits non-zero.

## Promotion evidence

`ControlledBenchmarkCampaignEvidence` binds the controlled campaign and manifest digests, every reviewed release SHA-256, the declared baseline/candidate engine revision values, exact source report hashes, aggregate TP/FP/FN/TN, precision/recall/F1, regression deltas and reasons, the acceptance verdict, and a final evidence SHA-256.

The current `SourceHuntReport` schema does **not** itself contain the Git commit that generated the report. Therefore the engine revision values supplied to the campaign are integrity-bound operator declarations, not cryptographic proof that each report was generated by that commit. A production-promotion decision must preserve independent CI/worker provenance showing which exact checkout generated each report; this controlled campaign must not overstate that provenance.

The benchmark acceptance policy still controls minimum case count, controlled-lab minimum, precision/recall/F1 floors, maximum false positives/negatives, and baseline regression ceilings.

## Failure behavior

The lifecycle fails closed when the corpus is synthetic; markers are missing, duplicated, or changed; fixture source changes while compilation is running; a definition lacks vulnerable or safe controls; a case references a missing file or invalid line range; the creator self-reviews; credentials or reviewer role are invalid; the same reviewer is counted twice; any review rejects; a reviewer becomes ineligible before release; any protected digest changes; report sets or snapshot provenance differ; a report is nonterminal; engine revisions are identical; or the candidate fails acceptance policy.

No failure path silently downgrades controlled evidence into synthetic evidence and no failed campaign can promote V2.

## Rollout boundary

The presence of this code and ten-case fixture does **not** mean Source Hunt V2 is the default engine and does not mean the proposed labels have been independently approved. Promotion remains blocked until humans create reviewed releases, authorized baseline and V2 reports are produced for those exact fixture snapshots, independent worker/CI provenance confirms the declared engine revisions, and the campaign returns accepted evidence.

Only after that evidence exists should the separate production-promotion batch consider changing the default worker. JavaScript/TypeScript remains `inventory_only` until its own deterministic analyzer and independent acceptance exist.
