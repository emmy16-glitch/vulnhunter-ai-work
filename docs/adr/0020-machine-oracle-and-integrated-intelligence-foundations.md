# ADR 0020: Machine Oracle and Integrated Intelligence Foundations

## Status

Accepted for Milestone 27 implementation.

## Context

VulnHunter needs an independent verification layer for candidate findings, but it must not become the controller, authorization authority, Approval Centre, execution engine, scope manager, or final reviewer.

## Decision

Add additive, disabled-by-default foundations:

1. immutable Machine Oracle proof capsules;
2. deterministic Oracle verification contracts;
3. disabled-by-default `pentest-ai` connector response validation requiring an injected authenticator and durable replay ledger;
4. repository coverage inventory contracts;
5. deterministic-first AI routing records;
6. attack-path graph contracts that prevent unverified confirmed paths;
7. analyst feedback and improvement proposal records.

No live external verifier, AI provider, security tool, APK runtime, connector, or broker is activated by this milestone.

External Oracle responses must authenticate through an injected contract before acceptance. This milestone implements the interface and fail-closed checks, not production key management or signature deployment.

## Consequences

The platform gains auditable contracts for independent verification and future intelligence routing. Operational activation remains environment-specific and requires separate approval, isolation, credentials, and review.
