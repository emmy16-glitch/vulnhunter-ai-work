# Source Hunt benchmark acceptance

## Purpose

Source Hunt Intelligence V2 must not become the default engine because a model response looks convincing or because one synthetic example scores well. Promotion requires deterministic evidence from the same immutable benchmark suite for both the current baseline engine and the candidate engine revision.

This acceptance layer is deliberately report-only. It does not scan repositories, invoke Groq, clone remote source, create authorization, execute proof plans, or confirm vulnerabilities. It evaluates already-produced `SourceHuntReport` records from synthetic or controlled-laboratory fixtures.

Controlled benchmark metrics remain laboratory evidence only. Every run, result and evidence bundle sets `production_accuracy_claim_permitted=false`.

## Trust boundary

The acceptance flow is:

```text
human-reviewed fixture repositories
    -> exact repository snapshots
    -> immutable benchmark corpora
    -> SourceBenchmarkSuite
    -> baseline SourceHunt reports
    -> candidate SourceHunt reports
    -> deterministic per-corpus evaluator
    -> aggregate campaign runs
    -> immutable acceptance policy
    -> baseline-vs-candidate comparison
    -> tamper-evident acceptance bundle
    -> human promotion decision
```

The benchmark evaluator is not a source-processing authorization mechanism. Producing the reports is still governed by the normal Source Hunt approval and worker path. The acceptance command only reads report JSON that already exists.

## Immutable benchmark suite

`SourceBenchmarkSuite` binds each corpus to:

- corpus ID and corpus SHA-256;
- corpus kind (`synthetic` or `controlled_lab`);
- exact fixture repository ID;
- exact fixture source revision;
- exact repository snapshot SHA-256.

The complete suite has its own SHA-256. A run must supply exactly one report for every corpus in the suite. Missing corpora, extra report-map keys, incomplete reports, or a snapshot mismatch fail closed before metrics are accepted.

This prevents a candidate from being evaluated on a smaller or easier set than the baseline.

## Campaign runs

`SourceBenchmarkCampaignRunner` evaluates one exact engine revision over the complete suite. It records:

- engine revision;
- suite ID and digest;
- every corpus ID, kind and digest;
- fixture repository and snapshot provenance;
- source report ID and SHA-256;
- per-corpus TP/FP/FN/TN and precision/recall/F1;
- unmatched candidate IDs;
- aggregate metrics;
- controlled-lab and synthetic case counts;
- deterministic run ID and run SHA-256.

The runner performs no network or model work.

## Acceptance policy

`SourceBenchmarkAcceptancePolicy` combines absolute quality floors with no-regression controls.

Supported gates include:

- minimum total cases;
- minimum controlled-lab cases;
- minimum precision;
- minimum recall;
- minimum F1;
- maximum false positives;
- maximum false negatives;
- maximum new false positives versus baseline;
- maximum new false negatives versus baseline;
- maximum precision regression;
- maximum recall regression;
- maximum F1 regression.

The policy itself is tamper-evident. Editing a threshold without recomputing the policy through the typed constructor causes validation failure.

A strict V2 promotion policy should normally set all regression allowances to zero and require a meaningful controlled-lab population. Thresholds must be chosen before inspecting the candidate result; they must not be loosened after a failed run merely to promote the candidate.

## Acceptance result

`SourceBenchmarkAcceptanceEvaluator` requires baseline and candidate runs to use the exact same suite digest and distinct engine revisions.

A candidate is accepted only when every configured absolute and baseline-relative gate passes. Rejections contain deterministic reasons such as:

- recall below the required minimum;
- too many false positives;
- new false negatives compared with the baseline;
- F1 regression beyond policy.

The result is cryptographically bound to the policy, suite, baseline run and candidate run.

`SourceBenchmarkAcceptanceBundle` then binds the two complete runs and the acceptance result into one final SHA-256 evidence object.

## CI-safe command

The command is:

```bash
python manage.py vh_check_source_hunt_benchmark_acceptance \
  --suite-file /protected/benchmarks/source-hunt-suite.json \
  --policy-file /protected/benchmarks/source-hunt-policy.json \
  --baseline-report-dir /protected/benchmarks/baseline-reports \
  --candidate-report-dir /protected/benchmarks/candidate-reports \
  --baseline-engine-revision <exact-baseline-commit> \
  --candidate-engine-revision <exact-candidate-commit> \
  --output /protected/benchmarks/source-hunt-acceptance.json
```

Each report directory contains one file per corpus named:

```text
<corpus_id>.json
```

The command:

1. validates the suite and policy digests;
2. loads the exact report set for both engines;
3. validates report stage and fixture snapshot bindings;
4. builds baseline and candidate campaign runs;
5. evaluates the immutable acceptance policy;
6. atomically writes the full acceptance bundle;
7. exits unsuccessfully when the candidate is rejected.

The evidence file is intentionally written even for a policy rejection so the failure remains reviewable.

## Creating suite and policy files

Suite and policy JSON should be generated through the typed constructors rather than hand-editing stored digests.

Example policy construction:

```python
from vulnhunter.source_hunt.benchmark_acceptance import SourceBenchmarkAcceptancePolicy

policy = SourceBenchmarkAcceptancePolicy.create(
    policy_id="source-hunt-v2-promotion",
    minimum_cases=30,
    minimum_controlled_lab_cases=20,
    minimum_precision=0.90,
    minimum_recall=0.90,
    minimum_f1=0.90,
    maximum_false_positives=3,
    maximum_false_negatives=3,
    maximum_new_false_positives=0,
    maximum_new_false_negatives=0,
    maximum_precision_regression=0.0,
    maximum_recall_regression=0.0,
    maximum_f1_regression=0.0,
)
```

Those values are an example of the schema, not a claim that they are the final approved promotion thresholds.

## Failure behavior

The acceptance layer fails closed when:

- the suite or policy digest is tampered;
- a corpus ID is duplicated;
- a required report is missing;
- a report does not belong to the bound fixture snapshot;
- a report is not complete;
- baseline and candidate use different suites;
- baseline and candidate use the same engine revision;
- any absolute threshold fails;
- any allowed-regression threshold fails;
- a stored run, result or bundle is altered after creation.

No failure grants permission to drop a corpus, weaken a threshold, reinterpret a false negative as acceptable, or describe the result as production accuracy.

## Rollout rule

The V2 worker may replace the legacy Source Hunt worker only after:

1. the exact V2 implementation commit is fully green under repository CI;
2. an approved benchmark suite contains enough controlled-laboratory diversity to support the decision;
3. baseline and candidate reports are generated for the exact same suite;
4. the candidate receives an `accepted` result under a pre-approved acceptance policy;
5. the acceptance bundle digest is recorded in the promotion review;
6. a distinct human approver decides whether to promote the candidate.

The benchmark result is evidence for promotion, not automatic merge authority.

## Current limitation

This layer provides the acceptance mechanism. It does not itself create the controlled-laboratory corpus or claim that the current repository already contains enough fixture diversity for a production-default decision. Adding or changing corpus cases is a separate governed benchmark-data change and must preserve ground-truth review independence.
