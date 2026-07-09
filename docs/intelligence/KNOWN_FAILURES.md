# Known Failures and Limitations

## 1. Initial baseline model under-detected confirmed findings

The first controlled benchmark baseline produced high precision but very low recall. This showed that the model predicted the confirmed class too rarely.

Interpretation: the pipeline worked, but the model was not practically useful.

Response:

- preserve the weak artifact as a baseline;
- add richer privacy-safe features;
- compare estimators and thresholds;
- select using training scans only;
- inspect locked-holdout errors.

## 2. Synthetic benchmark performance is not real-world performance

The controlled benchmark has known scenarios and deliberately structured signals. Strong performance can validate the experiment pipeline but cannot establish generalisation to real applications.

## 3. DNS connection pinning is incomplete

Scope validation rechecks resolution, but the eventual network connection may still resolve separately. Full socket-level pinning remains unresolved.

## 4. Passive observations do not prove exploitability

Missing headers, debug indicators, directory-style pages, and technology disclosures require context. The project intentionally requires human review.

## 5. Limited application diversity

Current benchmark data does not represent the diversity of frameworks, deployment stacks, authentication states, custom errors, proxies, and content found in real applications.

## 6. Historical single-review labels

The project now supports two-reviewer consensus and third-person adjudication for new manual observations. Historical and controlled-benchmark labels remain single-review records for reproducibility and must not be mistaken for independently reviewed real-world ground truth.

## 7. Local artifact lifecycle

Databases and model artifacts are local operational files. Backup, retention, signing, and release procedures are not yet formalised.

## 8. CLI-first operation

The project currently prioritises a CLI workflow. A graphical review interface is out of scope until the data contracts and review process are stable.

## 9. Orchestration is not an operating-system sandbox

The evaluation harness executes only fixed verifier command templates with `shell=False`, bounded output, timeouts, and an offline-oriented environment. The repository tests and build tools themselves are still local code and are not isolated by a kernel sandbox or container. A verifier pass therefore proves the configured checks ran successfully; it does not prove hostile repository code could not affect the host.

Loop roles are pseudonymous local identifiers. Their separation is mechanically recorded but not backed by authenticated accounts or digital signatures.

## 10. Local experiment isolation is not a kernel sandbox

Git worktrees, protected hashes, fixed verifiers, role separation, and deterministic rejection make evaluator gaming visible and prevent promotion. Experiment creation also refuses tracked paths classified as inaccessible. These controls do not provide operating-system isolation from a fully privileged local account, and they cannot erase secrets already reachable through Git history. Stronger isolation would require a separate low-privilege user, container, VM, or sandbox profile plus repository-history hygiene.

## 11. Outer-loop guidance is intentionally non-executable

The meta-search layer proposes strategy changes rather than injecting Python. This limits autonomy but prevents the outer loop from mutating its own evaluator or security boundaries.

## 9. Prompt-only unattended restrictions are insufficient

Natural-language instructions cannot prove that tools, paths, network, connectors, secrets, deletion, deployment, or retries were bounded. The unattended control plane therefore enforces an approved manifest in code and records every decision. OS-level isolation remains future work.
