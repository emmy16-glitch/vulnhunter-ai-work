# VulnHunter Role and Skill Registry

This directory is the version-controlled declaration layer for specialist roles
and narrowly scoped skills. It does **not** activate an agent, grant runtime
permissions, enable a connector, approve a task, or make a specialist trusted.

- `registry.json` is the complete manifest.
- `roles/` contains one immutable role declaration per JSON file.
- `skills/` contains one immutable skill declaration per JSON file.
- `schema/` provides an editor/tooling schema; Pydantic models remain the
  executable validation authority.

All initial roles and skills are `planned` and explicitly `untrusted`.
Connector access is disabled by default and there are no connector grants in
this foundation milestone.

Validate from the repository root:

```bash
python -m vulnhunter.roles validate
python -m vulnhunter.roles fingerprint
python -m vulnhunter.roles list-roles
python -m vulnhunter.roles list-skills
```
