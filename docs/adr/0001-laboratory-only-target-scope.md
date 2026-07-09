# ADR-0001: Laboratory-only target scope

- Status: Accepted
- Decision date: 2026-07-09

## Context

The platform performs security-related network collection. A permissive target model would create legal, ethical, and technical risk.

## Decision

Restrict initial targets to approved loopback/private laboratory address space. Revalidate every derived URL and redirect against immutable scheme, hostname, port, path, and address boundaries.

## Consequences

Benefits:

- safer default behaviour;
- testable deterministic scope rules;
- reduced SSRF-style destination drift.

Costs:

- public bug-bounty targets are not supported by the current product boundary;
- hostname transport still needs stronger connection-level pinning.
