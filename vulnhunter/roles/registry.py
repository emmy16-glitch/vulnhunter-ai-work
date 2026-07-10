"""Load, validate, fingerprint, and query the role and skill registry."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from pydantic import ValidationError

from vulnhunter.roles.models import (
    ActionDecision,
    DecisionStatus,
    LifecycleStatus,
    RegistryManifest,
    RegistryValidationReport,
    RoleDefinition,
    SkillDefinition,
)


class RegistryError(ValueError):
    """Base error for registry loading and policy checks."""


class RegistryIntegrityError(RegistryError):
    """Raised when files or cross-references violate registry invariants."""


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _read_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RegistryIntegrityError(f"Registry file is missing: {path}") from exc
    except json.JSONDecodeError as exc:
        raise RegistryIntegrityError(f"Registry file is not valid JSON: {path}") from exc
    except OSError as exc:
        raise RegistryIntegrityError(f"Registry file could not be read: {path}") from exc


class RoleRegistry:
    """Immutable in-memory registry with fail-closed action decisions."""

    def __init__(
        self,
        *,
        root: Path,
        manifest: RegistryManifest,
        roles: tuple[RoleDefinition, ...],
        skills: tuple[SkillDefinition, ...],
    ) -> None:
        self.root = root
        self.manifest = manifest
        self.roles = roles
        self.skills = skills
        self._roles_by_id = {role.role_id: role for role in roles}
        self._skills_by_id = {skill.skill_id: skill for skill in skills}

    @classmethod
    def from_path(cls, root: Path | str = Path("config/roles")) -> RoleRegistry:
        registry_root = Path(root).expanduser().resolve()
        manifest_path = registry_root / "registry.json"

        try:
            manifest = RegistryManifest.model_validate(_read_json(manifest_path))
        except ValidationError as exc:
            raise RegistryIntegrityError(f"Registry manifest is invalid: {exc}") from exc

        roles = tuple(
            cls._load_role(registry_root, relative_path) for relative_path in manifest.role_files
        )
        skills = tuple(
            cls._load_skill(registry_root, relative_path) for relative_path in manifest.skill_files
        )

        registry = cls(
            root=registry_root,
            manifest=manifest,
            roles=roles,
            skills=skills,
        )
        registry._validate_cross_references()
        registry._validate_declared_file_set()
        return registry

    @staticmethod
    def _load_role(root: Path, relative_path: str) -> RoleDefinition:
        path = RoleRegistry._safe_child(root, relative_path)
        try:
            role = RoleDefinition.model_validate(_read_json(path))
        except ValidationError as exc:
            raise RegistryIntegrityError(f"Role definition is invalid: {path}: {exc}") from exc
        expected_name = f"{role.role_id}.json"
        if path.name != expected_name:
            raise RegistryIntegrityError(
                f"Role filename must match role_id: expected {expected_name}, got {path.name}"
            )
        return role

    @staticmethod
    def _load_skill(root: Path, relative_path: str) -> SkillDefinition:
        path = RoleRegistry._safe_child(root, relative_path)
        try:
            skill = SkillDefinition.model_validate(_read_json(path))
        except ValidationError as exc:
            raise RegistryIntegrityError(f"Skill definition is invalid: {path}: {exc}") from exc
        expected_name = f"{skill.skill_id}.json"
        if path.name != expected_name:
            raise RegistryIntegrityError(
                f"Skill filename must match skill_id: expected {expected_name}, got {path.name}"
            )
        return skill

    @staticmethod
    def _safe_child(root: Path, relative_path: str) -> Path:
        candidate = (root / relative_path).resolve()
        try:
            candidate.relative_to(root)
        except ValueError as exc:
            raise RegistryIntegrityError(
                f"Registry path escapes the configured root: {relative_path}"
            ) from exc
        return candidate

    def _validate_cross_references(self) -> None:
        role_ids = [role.role_id for role in self.roles]
        skill_ids = [skill.skill_id for skill in self.skills]
        if len(set(role_ids)) != len(role_ids):
            raise RegistryIntegrityError("Role IDs must be unique")
        if len(set(skill_ids)) != len(skill_ids):
            raise RegistryIntegrityError("Skill IDs must be unique")

        missing_roles = set(self.manifest.required_role_ids) - set(role_ids)
        if missing_roles:
            raise RegistryIntegrityError(
                f"Required role definitions are missing: {sorted(missing_roles)}"
            )
        missing_skills = set(self.manifest.required_skill_ids) - set(skill_ids)
        if missing_skills:
            raise RegistryIntegrityError(
                f"Required skill definitions are missing: {sorted(missing_skills)}"
            )

        for role in self.roles:
            unknown_skills = set(role.skill_ids) - set(skill_ids)
            if unknown_skills:
                raise RegistryIntegrityError(
                    f"Role {role.role_id} references unknown skills: {sorted(unknown_skills)}"
                )
            globally_denied = set(role.allowed_actions) & set(self.manifest.global_denied_actions)
            if globally_denied:
                raise RegistryIntegrityError(
                    f"Role {role.role_id} allows globally denied actions: {sorted(globally_denied)}"
                )
            for tool in role.tools:
                if tool.connector_access:
                    granted_ids = {grant.connector_id for grant in role.connector_policy.grants}
                    if tool.tool_id not in granted_ids:
                        raise RegistryIntegrityError(
                            f"Role {role.role_id} connector tool {tool.tool_id} "
                            "does not have a matching explicit connector grant"
                        )

    def _validate_declared_file_set(self) -> None:
        declared_roles = {
            self._safe_child(self.root, relative).resolve() for relative in self.manifest.role_files
        }
        actual_roles = {path.resolve() for path in (self.root / "roles").glob("*.json")}
        undeclared_roles = actual_roles - declared_roles
        if undeclared_roles:
            raise RegistryIntegrityError(
                "Undeclared role files are present: "
                f"{sorted(path.name for path in undeclared_roles)}"
            )

        declared_skills = {
            self._safe_child(self.root, relative).resolve()
            for relative in self.manifest.skill_files
        }
        actual_skills = {path.resolve() for path in (self.root / "skills").glob("*.json")}
        undeclared_skills = actual_skills - declared_skills
        if undeclared_skills:
            raise RegistryIntegrityError(
                "Undeclared skill files are present: "
                f"{sorted(path.name for path in undeclared_skills)}"
            )

    def get_role(self, role_id: str) -> RoleDefinition:
        try:
            return self._roles_by_id[role_id]
        except KeyError as exc:
            raise RegistryError(f"Unknown role: {role_id}") from exc

    def get_skill(self, skill_id: str) -> SkillDefinition:
        try:
            return self._skills_by_id[skill_id]
        except KeyError as exc:
            raise RegistryError(f"Unknown skill: {skill_id}") from exc

    def fingerprint(self) -> str:
        payload = {
            "manifest": self.manifest.model_dump(mode="json"),
            "roles": [
                role.model_dump(mode="json")
                for role in sorted(self.roles, key=lambda item: item.role_id)
            ],
            "skills": [
                skill.model_dump(mode="json")
                for skill in sorted(self.skills, key=lambda item: item.skill_id)
            ],
        }
        return hashlib.sha256(_canonical_json(payload)).hexdigest()

    def validate(self) -> RegistryValidationReport:
        warnings: list[str] = []
        if all(role.status == LifecycleStatus.PLANNED for role in self.roles):
            warnings.append(
                "All roles are planned and untrusted; the registry does not "
                "activate runtime agents."
            )

        return RegistryValidationReport(
            registry_version=self.manifest.registry_version,
            role_count=len(self.roles),
            skill_count=len(self.skills),
            active_role_count=sum(role.status == LifecycleStatus.ACTIVE for role in self.roles),
            planned_role_count=sum(role.status == LifecycleStatus.PLANNED for role in self.roles),
            connector_grant_count=sum(len(role.connector_policy.grants) for role in self.roles),
            external_dependency_count=(
                sum(len(role.external_dependencies) for role in self.roles)
                + sum(len(skill.external_dependencies) for skill in self.skills)
            ),
            fingerprint_sha256=self.fingerprint(),
            warnings=tuple(warnings),
        )

    def evaluate_action(
        self,
        role_id: str,
        action: str,
        *,
        tool_id: str | None = None,
        operation: str | None = None,
        connector_id: str | None = None,
        approval_reference: str | None = None,
    ) -> ActionDecision:
        try:
            role = self.get_role(role_id)
        except RegistryError as exc:
            return ActionDecision(
                status=DecisionStatus.DENIED,
                role_id=role_id,
                action=action,
                reason=str(exc),
                tool_id=tool_id,
                operation=operation,
                connector_id=connector_id,
                approval_reference=approval_reference,
            )

        if role.status != LifecycleStatus.ACTIVE:
            return self._decision(
                DecisionStatus.DENIED,
                role,
                action,
                f"Role status is {role.status}; only active roles may be evaluated as allowed.",
                tool_id,
                operation,
                connector_id,
                approval_reference,
            )

        if action in self.manifest.global_denied_actions:
            return self._decision(
                DecisionStatus.DENIED,
                role,
                action,
                "Action is denied by the registry-wide safety policy.",
                tool_id,
                operation,
                connector_id,
                approval_reference,
            )
        if action in role.denied_actions:
            return self._decision(
                DecisionStatus.DENIED,
                role,
                action,
                "Action is explicitly denied for this role.",
                tool_id,
                operation,
                connector_id,
                approval_reference,
            )
        if action not in role.allowed_actions:
            return self._decision(
                DecisionStatus.DENIED,
                role,
                action,
                "Action is not explicitly allowed for this role.",
                tool_id,
                operation,
                connector_id,
                approval_reference,
            )

        if tool_id is not None:
            tool = next((item for item in role.tools if item.tool_id == tool_id), None)
            if tool is None:
                return self._decision(
                    DecisionStatus.DENIED,
                    role,
                    action,
                    "Requested tool is not granted to this role.",
                    tool_id,
                    operation,
                    connector_id,
                    approval_reference,
                )
            if operation is None or operation not in tool.allowed_operations:
                return self._decision(
                    DecisionStatus.DENIED,
                    role,
                    action,
                    "Requested tool operation is not explicitly allowed.",
                    tool_id,
                    operation,
                    connector_id,
                    approval_reference,
                )

        if connector_id is not None:
            grant = next(
                (
                    item
                    for item in role.connector_policy.grants
                    if item.connector_id == connector_id
                ),
                None,
            )
            if grant is None:
                return self._decision(
                    DecisionStatus.DENIED,
                    role,
                    action,
                    "Connector access is disabled unless an explicit reviewed grant exists.",
                    tool_id,
                    operation,
                    connector_id,
                    approval_reference,
                )

        if action in role.human_approval_points and not approval_reference:
            return self._decision(
                DecisionStatus.REQUIRES_APPROVAL,
                role,
                action,
                "This action requires a recorded human approval reference.",
                tool_id,
                operation,
                connector_id,
                approval_reference,
            )

        return self._decision(
            DecisionStatus.ALLOWED,
            role,
            action,
            "The declaration allows this action; runtime enforcement is still required.",
            tool_id,
            operation,
            connector_id,
            approval_reference,
        )

    @staticmethod
    def _decision(
        status: DecisionStatus,
        role: RoleDefinition,
        action: str,
        reason: str,
        tool_id: str | None,
        operation: str | None,
        connector_id: str | None,
        approval_reference: str | None,
    ) -> ActionDecision:
        return ActionDecision(
            status=status,
            role_id=role.role_id,
            action=action,
            reason=reason,
            tool_id=tool_id,
            operation=operation,
            connector_id=connector_id,
            approval_reference=approval_reference,
        )
