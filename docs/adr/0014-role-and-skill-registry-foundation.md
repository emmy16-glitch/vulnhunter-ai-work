# ADR-0014: Version-Controlled Role and Skill Registry Foundation

## Status

Accepted for Milestone 19.5A foundation. Runtime activation is deferred.

## Context

VulnHunter now contains authorization, bounded scanning, independent review,
governed collection, orchestration, autoresearch, and unattended-operation
controls. Future specialist agents need narrow, reviewable boundaries before
any runtime system may route work to them.

Prompt instructions alone are not permission enforcement. A specialist is not
trustworthy merely because it has a domain-specific name or detailed prompt.
Connectors and third-party skills add external trust and prompt-injection risks.

## Decision

Maintain a version-controlled registry with separate role and skill
definitions. Validate it with immutable Pydantic models and cross-reference
checks. Compute a deterministic SHA-256 over the validated snapshot.

The registry shall:

- default every role and skill to `planned` and `untrusted`;
- default connectors to disabled;
- declare global denied actions;
- require exact semantic versions for registry-owned definitions;
- require immutable pins and integrity digests for external dependencies;
- record human approvals, tests, verification, review dates, and rollback;
- fail closed on unknown roles, skills, actions, tools, operations, connectors,
  undeclared files, or path traversal;
- remain declarative until a later runtime-enforcement milestone.

Milestone 19.5A does not modify root CLI routing, orchestration execution,
unattended permissions, governance identities, or connector configuration. This
keeps the parallel branch independent from Milestone 18.1 provenance changes.

## Security properties

- Role files cannot allow registry-wide denied actions.
- Allowed and denied action sets cannot overlap.
- Human approval points must reference an explicitly allowed action.
- Tool operations are least-privilege declarations.
- Connector-capable tools require matching reviewed connector grants.
- Dependency pins reject mutable branch or wildcard references.
- Registry file paths cannot escape the configured root.
- Undeclared role and skill files fail validation.
- `allowed` means only that the declaration permits an action; runtime controls
  remain mandatory.

## Alternatives rejected

### Trust role prompts without a registry

Rejected because prompts are mutable, hard to diff, and do not enforce
permissions.

### Activate all specialist roles immediately

Rejected because the governed pilot has not yet produced operational evidence
for permissions, handoffs, or failure recovery.

### Enable connectors as a convenience default

Rejected because connectors introduce external data, authorization, and prompt
injection risks.

### Use one broad general-purpose agent

Rejected because broad authority weakens least privilege, independent review,
and blame-free auditability.

## Consequences

The project gains a deterministic, testable foundation for role governance. It
also gains deliberate friction: a planned role cannot act until a later
milestone binds an authenticated identity, runtime permission manifest, human
approval, and independent verification.

Milestone 19.5B will revise and activate only the roles justified by the
controlled pilot.
