# Known Failures and Limitations

## 1. Initial baseline model under-detected confirmed findings

The first controlled benchmark baseline produced high precision but very low recall. The pipeline worked, but the model predicted the confirmed class too rarely to be practically useful.

Response:

- preserve the weak artifact as an honest baseline;
- add privacy-safe features;
- compare estimators and thresholds using training scans only;
- inspect locked-holdout errors without tuning against them.

## 2. Synthetic benchmark performance is not real-world performance

The controlled benchmark uses known scenarios and deliberately structured signals. Strong scores validate experiment plumbing and reproducibility, not generalisation to real applications.

## 3. Historical DNS time-of-check/time-of-use gap — resolved

Earlier releases revalidated DNS before a request but allowed the HTTP stack to resolve the hostname again while opening the socket. The transport now resolves at connection time, connects directly to an approved IP, verifies the peer, preserves the original hostname for HTTP/TLS, and disables keep-alive reuse between independently pinned requests.

## 4. Passive observations do not prove exploitability

Missing headers, debug indicators, directory-style pages, and technology disclosures require context. VulnHunter intentionally keeps human review authoritative.

## 5. Real application diversity remains limited

The control plane can govern diverse campaigns, but the project has not yet produced a sufficiently broad real dataset spanning frameworks, deployment stacks, authentication states, proxies, custom errors, and application families.

## 6. Historical and benchmark single-review labels remain

New governed real observations require two authenticated assigned reviewers and, when needed, an independent adjudicator. Historical and controlled-benchmark labels remain single-review records for reproducibility and cannot qualify for a governed campaign release without matching attestations.

## 7. Local artifact lifecycle is not fully operationalised

Databases, campaign releases, model artifacts, and experiment evidence are local operational files. Formal backup, retention, migration, signing, restore, and release procedures remain future work.

## 8. CLI-first operation

The project prioritises a CLI workflow. A graphical interface is deferred until the campaign and review process is validated through real use.

## 9. Orchestration and research isolation are not kernel sandboxes

Fixed shell-free verifiers, worktrees, protected hashes, role separation, and deterministic rejection make evaluator gaming visible, but repository code still runs under the local account. Stronger isolation requires a dedicated low-privilege user, container, VM, or operating-system sandbox.

## 10. Outer-loop guidance is intentionally non-executable

The meta-search layer proposes strategy changes rather than injecting Python. This limits autonomy but prevents the outer loop from mutating its evaluator or security boundaries.

## 11. Runtime permissions do not replace operating-system controls

The unattended control plane enforces tools, paths, commands, network, connectors, secrets, and destructive permissions in application code. It cannot protect the host from code that already executes with equivalent operating-system privilege.

## 12. Local authentication is not external identity proof

Reviewer secrets use scrypt and actions are identity-bound, but the local registry does not provide SSO, MFA, hardware-backed keys, independent proof that separate accounts belong to separate people, or protection from a compromised administrator account.

## 13. Campaign integrity is hash-based, not digitally signed

Campaign records, attestations, releases, and events detect local database tampering through deterministic hashes and a hash chain. They are not yet signed by a protected external key, so portable authenticity and non-repudiation are not established.

## 14. Historical scan-completion correlation gap — resolved

Earlier governed scan linking matched scan completion primarily by scan ID and
event order after a matching start event. The authorization completion event now
binds the authorization ID, normalized scan database, scan ID, normalized target
URL, and persisted scan snapshot hash, and campaign linking fails closed when
that tuple is missing, malformed, mismatched, or ordered before the matching
start event.

## 15. Real-world model evidence is still absent

The governed collection workflow is implemented, but meaningful performance claims require actual collection across diverse authorised applications, independent review, application-group-isolated development and holdout sets, and an untouched external evaluation.
