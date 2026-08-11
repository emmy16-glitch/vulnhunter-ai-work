# ADR-0001: Initial Laboratory-only Target Scope

- **Status:** Superseded for product target classes by ADR 0022; retained as historical safety rationale
- **Decision date:** 2026-07-09
- **Superseded:** 2026-08-11

## Context

VulnHunter began with security-related network collection while the scope and transport architecture was still immature. A permissive target model would have created legal, ethical and technical risk.

## Original decision

Restrict initial website targets to approved loopback/private laboratory address space and revalidate every derived URL/redirect against immutable scheme, hostname, port, path and address boundaries.

This was intentionally conservative and enabled deterministic scope/transport work before public-host execution.

## What remains valid

The safety reasoning remains binding:

- a URL is not permission;
- exact scheme/hostname/port/path boundaries matter;
- redirects must not escape scope;
- DNS/address changes must not escape the authorization decision;
- special-use/metadata/link-local/loopback behavior must fail closed according to worker context;
- browser/model input must not grant network authority;
- connection-level containment is required.

## What is superseded

The statement that VulnHunter's finished product must reject all public Internet targets is superseded by **ADR 0022 — Authorised Public Targets and Transport Containment**.

The current product supports the concept of explicitly authorised `public` targets in addition to `private` targets.

Public does **not** mean unrestricted. Public execution requires the exact authorization and transport boundary defined in:

- `docs/adr/0022-authorised-public-targets-and-transport-containment.md`;
- `docs/product/PUBLIC_TARGET_ASSESSMENT.md`;
- `docs/product/NUCLEI_INTEGRATION.md`.

## Current runtime note

The current passive Nuclei worker remains private-target-only until a reviewed public-capable transport path is implemented and accepted.

Do not use this historical ADR to prohibit authorised public-target product work, and do not use ADR 0022 to justify weakening the current private worker before the public transport boundary exists.
