# Total Programme Gap Matrix

## Authority and scope

The atomic source is
`TOTAL_PROGRAMME_CANONICAL_COVERAGE_MATRIX.md`. Its `608` rows preserve every
canonical section, subsection, requirement, and deferred phase with repository
evidence, tests, wave, task, dependency, restrictions, gate, and one allowed
classification. This summary does not replace those rows.

## Reconciliation gate

| Measure | Count |
| --- | ---: |
| Canonical requirements | 608 |
| COMPLETE | 86 |
| PARTIAL | 272 |
| MISSING | 0 |
| CONTRACT_ONLY | 43 |
| ACTIVATION_REQUIRED | 19 |
| EXTERNAL_PREREQUISITE | 59 |
| MANUAL_INSTALL_REQUIRED | 11 |
| CREDENTIAL_REQUIRED | 23 |
| RESOURCE_DEFERRED | 42 |
| LATE_STAGE_GATED | 40 |
| INTENTIONALLY_EXCLUDED | 13 |
| PROHIBITED | 0 |
| UNMAPPED | 0 |

Transition status: `PASS`.

## Dependency-ordered gaps

| Programme area | Current state | Next bounded implementation | Gate |
| --- | --- | --- | --- |
| Wave 1 agent runtime | PARTIAL | Lifecycle, pause/cancel, and authoritative approval binding complete; next harden task-graph CAS and worker leases. | Focused deterministic lifecycle, actor separation, recovery, evidence, and budget tests pass. |
| Wave 1B agentic threats | COMPLETE | Typed sequence signals, containment decisions, human notification and immutable assessment evidence implemented. | Focused sequence, containment, audit and recovery tests pass. |
| Wave 2 repository intelligence | PARTIAL | Add incremental deterministic symbols, relationships, impact, staleness, and context interfaces. | Changed-region, source-verification, secret-safe, and stale-index tests pass. |
| Graphify CLI | MANUAL_INSTALL_REQUIRED | Keep adapter contract preparatory until a reviewed manual install is approved. | Exact executable identity and disabled-by-default readiness pass. |
| Graphify learning | EXTERNAL_PREREQUISITE | Record non-authoritative usage only after CLI readiness. | Reviewed metrics justify the native schema. |
| Native graph | PARTIAL | Deterministic incremental AST graph implemented; Graphify learning/comparison remains an external prerequisite. | Native graph tests pass; provider comparison remains gated. |
| Context broker | COMPLETE | Typed deterministic routing, budgets, provenance, freshness, confidence, rules, contradictions and optional approved retrieval implemented. | Focused routing, protected-data and budget tests pass. |
| AI providers/models | CONTRACT_ONLY / CREDENTIAL_REQUIRED / RESOURCE_DEFERRED | Implement disabled adapters, schemas, health, budgets, and truthful degraded mode without activating providers. | Real readiness remains separately manual and credential gated. |
| Security tools | PARTIAL / MANUAL_INSTALL_REQUIRED | Extend the existing catalog/executor with restricted adapters only for reviewed installed tools. | Authorization, target, argv, identity, timeout, output, parser, cancellation, and evidence tests pass. |
| Product workspace | PARTIAL | Audit existing Django surfaces before choosing progressive enhancement. | Functional, accessibility, responsive, and visual regression gates pass. |
| Findings, mobile, binary, reporting | PARTIAL | Extend existing typed foundations in their ordered waves; static-first only. | Focused provenance, protected-data, access, lifecycle, and export tests pass. |
| Oracle operational readiness | PARTIAL / ACTIVATION_REQUIRED | Extend authenticated key/replay/conflict contracts; keep live verifier disabled. | Independent real connector readiness is separately approved and passes. |
| Connectors and privileged broker | CONTRACT_ONLY / MANUAL_INSTALL_REQUIRED | Keep read-only connector contracts and a design-only broker until manual activation. | Minimum permissions, revocation, audit, replay, and process-boundary tests pass. |
| Production hardening | PARTIAL | Add secure configuration and abstractions without deployment. | System, migration, health, backup/restore, concurrency, and error-redaction gates pass. |
| Analyst learning | PARTIAL / LATE_STAGE_GATED | Complete governed feedback datasets and evaluation records; do not train. | Provenance, leakage, disagreement, frozen holdout, and release tests pass. |
| Pilot/demo | MISSING | Build truthful seeded local demonstrations after product workflows stabilize. | No live integration or fabricated result is represented as operational. |

## Graphify order

The mandatory order remains:

1. restricted Graphify CLI adapter;
2. repository-graph learning period;
3. reviewed VulnHunter-native schema;
4. native security-critical relationship migration;
5. Graphify retained as an optional accelerator;
6. optional restricted local MCP service only at the late gate.

Graphify is not installed and cannot authorize, scope, execute, modify code or
policy, receive unrestricted shell access, or become a source of truth.

## Non-implementation classifications

- Activation, credential, external, manual-install, and resource gates remain
  truthful operational limitations, not code completion claims.
- All 13 canonical exclusions remain `INTENTIONALLY_EXCLUDED`.
- No excluded or unsafe capability is silently absorbed into another wave.
