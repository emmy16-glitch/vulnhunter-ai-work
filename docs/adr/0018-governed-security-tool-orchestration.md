# ADR 0018: Governed security-tool orchestration before activation

## Status

Accepted as a disabled-by-default foundation.

## Context

VulnHunter needs to coordinate free security assessment tools without giving an
AI planner unrestricted shell, sudo, target, connector, credential, or
deployment authority. The existing bounded runtime, authorization records,
scope checks, role registry, activity timeline, and secure web application are
necessary but do not provide a durable approval centre, exact action manifests,
tool-specific fixed command adapters, evidence integrity records, or a durable
multi-agent task graph.

## Decision

Introduce the following independently testable contracts:

1. immutable SHA-256 action manifests carrying campaign, target,
   authorization, role, skill, tool, operation, expiry, and hard limits;
2. a fail-closed deterministic action policy;
3. a transactional SQLite approval centre with the six human decisions,
   persistent expiration, requester separation, one-time action-hash
   consumption, per-request hash-chained ledgers, and fail-closed conditional
   approvals until a condition validator exists;
4. a registry for Nmap, httpx, Nuclei, OWASP ZAP, testssl.sh, Trivy, Semgrep,
   Greenbone, Amass, ffuf, sqlmap, and Metasploit;
5. fixed shell-free direct adapters only where a bounded command contract is
   implemented;
6. connector-only status for tools that need a dedicated long-running service
   or higher-risk integration;
7. a disabled-by-default subprocess executor with bounded output, timeout,
   minimal environment, no sudo, and no arbitrary planner arguments;
8. append-only evidence records with artifact hashes;
9. a durable acyclic task graph for role- and skill-specific handoffs;
10. local-first provider routing and a privacy gate for any future cloud
    fallback;
11. owner privilege-grant and broker-request data contracts that never store a
    sudo password;
12. authenticated Approval Centre, Security Tool Registry, and Advanced Mode
    web surfaces.

## Activation boundary

This milestone does not install external tools, run scans, enable connectors,
create credentials, contact model providers, start privileged services, or
change the existing laboratory-only product boundary. External tool execution,
active assessment, validation, and privileged brokerage remain disabled in
`config/security_tools/runtime.json`.

A later reviewed milestone must connect current authorization and scope records
to action manifests, independently verify tool versions and command contracts,
add service-specific connectors, and explicitly activate selected profiles.

## Consequences

The platform can now represent and review deep multi-tool assessment plans,
show local tool availability, preserve human approval authority, and test
security boundaries without performing a scan during installation. Every
future activation has a concrete enforcement and audit surface rather than an
unrestricted command channel.
