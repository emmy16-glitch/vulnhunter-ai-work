# ADR 0018: Governed Security-Tool Orchestration Before Activation

## Status

Accepted as the governance/orchestration foundation.

**Target-policy clarification:** this ADR was written while VulnHunter was still private/laboratory-only. ADR 0022 later superseded that product-level target restriction. The orchestration controls in this ADR remain valid for both authorised private and authorised public targets.

## Context

VulnHunter needs to coordinate security-assessment tools without giving an AI planner unrestricted shell, sudo, target, connector, credential or deployment authority.

Authorization records, scope checks, role registry, activity state and web controls must remain separate from tool execution.

## Decision

Maintain independently enforceable contracts for:

1. immutable action/plan identities carrying target, authorization, role, tool, operation, expiry and hard limits;
2. fail-closed deterministic action policy;
3. governed human approval/decision state where required;
4. a restricted tool registry;
5. fixed shell-free adapters only where a bounded command contract exists;
6. connector/service boundaries for tools that cannot safely execute as direct subprocess adapters;
7. bounded execution with timeout/output/environment controls and no arbitrary planner arguments;
8. append-only evidence/artifact hashes;
9. durable task/worker handoffs;
10. provider privacy/routing rules;
11. privilege-grant/broker contracts that do not store privileged passwords;
12. authenticated browser surfaces that project backend state but do not create authority.

## Activation boundary

The original milestone intentionally did not install/activate external scanners or change the **then-current** private/laboratory-only target policy.

That historical limitation must not be read as a permanent ban on authorised public targets.

Current target architecture is:

```text
authorised private target → permitted product class
authorised public target  → permitted product class
arbitrary public target   → prohibited
```

Public execution additionally requires the transport/worker containment in ADR 0022 and `docs/product/PUBLIC_TARGET_ASSESSMENT.md`.

The current passive Nuclei worker remains private-target-only until that separate public-capable path is implemented and accepted.

## Authority boundary

No orchestration action, AI plan, tool registry entry or approval-centre record may by itself:

- create target authorization;
- expand target class/scope;
- switch a private-only worker to public mode;
- bypass DNS/address containment;
- confirm a vulnerability;
- change human review authority;
- publish/release a finding.

## Consequences

The platform can represent/review bounded multi-tool plans and keep execution behind explicit policy/worker gates.

Future tool activation must still prove exact command/tool identity, target authorization, worker capability, bounded evidence and safe failure rather than exposing an unrestricted command channel.

## Related decisions

- ADR 0006 — explicit target authorization;
- ADR 0012 — connection-bound DNS scope enforcement;
- ADR 0021 — scanner manager/worker separation;
- ADR 0022 — authorised public targets and transport containment.
