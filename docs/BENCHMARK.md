# Controlled Local Benchmark

VulnHunter's controlled benchmark validates the complete passive mapping,
human review, dataset quality, model training, and artifact-provenance pipeline.
It is not a claim of real-world vulnerability-detection performance.

## Safety boundary

- The server binds only to `127.0.0.1` on an ephemeral port.
- Every scenario is scanned through the normal scope guard and safe HTTP client.
- Only passive GET requests are generated.
- Each scenario uses a separate scan ID and URL path boundary.
- Benchmark data must use a dedicated empty SQLite database.
- No benchmark suggestion becomes a label without an explicit human decision.

## Workflow

```text
vulnhunter benchmark run
vulnhunter benchmark status
vulnhunter benchmark review
vulnhunter ml readiness --database artifacts/benchmark.db
vulnhunter benchmark train
vulnhunter ml info --model artifacts/vulnhunter-benchmark-baseline.json
```

The review command presents one scenario at a time. `accept` applies the catalog
suggestion after the operator inspects the rationale and listed findings.
`confirmed` and `false_positive` let the operator override the suggestion.
`skip` and `quit` leave labels unchanged.

## Interpretation

A benchmark model is stored as artifact version 3 with:

- `training_context=controlled_benchmark`;
- benchmark run ID;
- catalog version;
- SHA-256 of the integrity-checked manifest;
- disjoint training and holdout scan IDs.

Metrics from this synthetic dataset validate plumbing and reproducibility only.
They must not be presented as production accuracy or evidence that VulnHunter can
replace qualified human security review.
