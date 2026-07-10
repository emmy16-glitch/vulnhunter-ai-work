# Role and Skill Registry Foundation

## Status

Milestone 19.5A introduces a version-controlled declaration layer for narrowly
scoped specialist roles and skills. The registry is **not** a runtime agent
manager and does not grant authority merely because a JSON file exists.

Every initial role and skill is:

- `planned`;
- explicitly `untrusted`;
- connector-disabled by default;
- unable to push Git changes, deploy, delete data, read secrets, override
  authorization, or approve its own review;
- subject to explicit verification, human approval, tests, and rollback.

## Purpose

The registry makes specialist boundaries reviewable before they are connected
to orchestration or unattended execution. It records:

- purpose, owner, version, lifecycle status, and risk level;
- allowed inputs, actions, outputs, tools, and data access;
- explicitly denied actions;
- skill bindings;
- output schema;
- verification requirements and required tests;
- human approval points;
- connector policy;
- reviewed external dependencies;
- last review date and rollback procedure.

A role declaration is evidence of intended boundaries, not proof that a role is
safe, correct, authenticated, independently verified, or ready to execute.

## Files

- `config/roles/registry.json` — complete immutable manifest.
- `config/roles/roles/*.json` — specialist role declarations.
- `config/roles/skills/*.json` — narrowly scoped skill declarations.
- `config/roles/schema/role-definition.schema.json` — editor/tooling schema.
- `vulnhunter/roles/models.py` — executable Pydantic validation.
- `vulnhunter/roles/registry.py` — loading, cross-reference validation,
  fingerprinting, and fail-closed declaration decisions.
- `vulnhunter/roles/cli.py` — read-only registry inspection.

## Initial roles

The registry contains these planned roles:

1. Orchestrator
2. Authorization and Scope Guardian
3. Architecture Specialist
4. Backend Specialist
5. Frontend Specialist
6. Scanner and Evidence Specialist
7. Finding Triage Analyst
8. Dataset Quality Auditor
9. Model Experiment Specialist
10. Independent Security Verifier
11. Test and Verification Specialist
12. Report Writer
13. Knowledge Curator

## Connector policy

The registry-wide default is disabled. A future connector grant must include:

- a specific connector identifier and purpose;
- least-privilege scope;
- completed prompt-injection review;
- audit logging;
- Emmanuel's named approval;
- expiry;
- revocation procedure.

No connector grants are included in Milestone 19.5A.

## Third-party dependency policy

Plugins, skills, packages, or other third-party capabilities are external
dependencies. They require:

- an immutable pinned reference;
- an integrity SHA-256;
- risk classification;
- named reviewer and review date;
- explicit allowed and denied capabilities;
- verification tests;
- rollback procedure.

References such as `latest`, `main`, `master`, `HEAD`, or wildcards fail
validation.

## Policy decisions

`RoleRegistry.evaluate_action()` is fail-closed and can return:

- `denied`;
- `requires_approval`;
- `allowed`.

An `allowed` declaration still says that runtime enforcement is required. This
foundation does not execute the action and does not replace the existing
orchestration, authorization, governance, independent-review, or unattended
control planes.

## Validation

From the repository root:

```bash
python -m vulnhunter.roles validate
python -m vulnhunter.roles fingerprint
python -m vulnhunter.roles list-roles
python -m vulnhunter.roles list-skills
python -m vulnhunter.roles show-role orchestrator
```

The fingerprint is computed from canonical validated manifest, role, and skill
content. Any validated registry change produces a different digest.

## Deferred integration

Milestone 19.5B must use pilot evidence before activating roles. It will decide:

- which planned roles are needed in real operations;
- how identities authenticate to roles;
- which runtime permission manifest binds each action;
- how role activation, suspension, revocation, expiry, and recovery work;
- how role decisions integrate with orchestration and unattended controls;
- which role outputs require independent verification;
- whether any connector exception is justified.

No role should become active merely because Milestone 19.5A passes its tests.

## Pilot-informed refinement

The controlled governed pilot readiness workflow adds one declarative
capability to the planned Dataset Quality Auditor role and Dataset Quality
Audit skill: `pilot.readiness.assess`. This capability is limited to read-only
assessment of existing release manifests, authorization evidence, scan links,
review attestations, duplicate/leakage indicators, class balance, and
deterministic report fingerprints.

The refinement does not activate any role, grant connector access, allow model
training, approve campaigns, submit or adjudicate reviews, release datasets, or
read secrets. Runtime authority remains deferred until a separate milestone
binds authenticated identities, permission manifests, human approvals,
verification obligations, and recovery procedures.
