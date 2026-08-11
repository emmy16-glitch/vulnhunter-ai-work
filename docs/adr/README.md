# Architecture Decision Records

ADRs preserve architectural decisions that future contributors and coding agents must not casually reverse.

## Current ADR index

- [ADR-0001: Initial laboratory-only target scope — superseded for product target classes by ADR 0022](0001-laboratory-only-target-scope.md)
- [ADR-0002: Human review remains authoritative](0002-human-review-authoritative.md)
- [ADR-0003: Split datasets by scan group](0003-scan-group-isolation.md)
- [ADR-0004: Synthetic benchmarks are pipeline evidence only](0004-synthetic-benchmark-limits.md)
- [ADR-0005: Controlled source ingestion](0005-controlled-source-ingestion.md)
- [ADR-0006: Explicit target authorization](0006-explicit-target-authorization.md)
- [ADR-0007: Independent review and adjudication](0007-independent-review-and-adjudication.md)
- [ADR-0008: Bounded orchestration and proof-based completion](0008-bounded-orchestration-and-proof-based-completion.md)
- [ADR-0009: Immutable evaluator and transactional experiments](0009-immutable-evaluator-and-transactional-experiments.md)
- [ADR-0010: Bounded meta-search without code injection](0010-bounded-meta-search-without-code-injection.md)
- [ADR-0011: Runtime-enforced unattended permissions](0011-runtime-enforced-unattended-permissions.md)
- [ADR-0012: Connection-bound DNS scope enforcement](0012-connection-bound-dns-scope-enforcement.md)
- [ADR-0013: Governed collection campaigns and authenticated review identities](0013-governed-collection-and-authenticated-review.md)
- [ADR-0018: Governed security-tool orchestration before activation](0018-governed-security-tool-orchestration.md)
- [ADR-0019: Governed Android APK analysis before execution](0019-governed-android-apk-analysis.md)
- [ADR-0020: Machine Oracle and integrated intelligence foundations](0020-machine-oracle-and-integrated-intelligence-foundations.md)
- [ADR-0021: Scanner manager and worker separation](0021-scanner-manager-worker-separation.md)
- [ADR-0022: Authorised public targets and transport containment](0022-authorised-public-targets-and-transport-containment.md)

## ADR states

- Proposed
- Accepted
- Superseded
- Rejected

## Supersession rule

When a product decision changes materially:

1. create a new ADR;
2. mark the older ADR as superseded or partially superseded;
3. link both directions;
4. preserve the older rationale/history;
5. update current product/status documents so agents cannot follow stale policy accidentally.

Do not rewrite architectural history merely to make old documents look current.

## Current target-policy note

ADR 0001 established the conservative private/laboratory-only starting boundary. ADR 0022 supersedes the **product-level prohibition on public targets** while preserving the strict authorization, DNS/address containment and anti-pivot reasoning.

Therefore:

```text
authorised private target  → supported product class
authorised public target   → supported product class
arbitrary public target    → prohibited
```

The current runtime may still be narrower than the accepted architecture. `docs/intelligence/CURRENT_STATE.md` owns implementation truth; a product ADR does not by itself prove that a worker capability has shipped.
