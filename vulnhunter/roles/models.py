"""Immutable models for the VulnHunter role and skill registry."""

from __future__ import annotations

import json
import re
from datetime import date
from enum import StrEnum
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_IDENTIFIER_PATTERN = re.compile(r"^[a-z0-9][a-z0-9.-]{1,63}$")
_VERSION_PATTERN = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_FORBIDDEN_PIN_REFERENCES = {"latest", "main", "master", "head", "*"}


class RiskLevel(StrEnum):
    """Risk classification for a role, skill, or dependency."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class LifecycleStatus(StrEnum):
    """Registry lifecycle status."""

    PLANNED = "planned"
    ACTIVE = "active"
    DISABLED = "disabled"
    DEPRECATED = "deprecated"


class DecisionStatus(StrEnum):
    """Result of a registry policy decision."""

    ALLOWED = "allowed"
    DENIED = "denied"
    REQUIRES_APPROVAL = "requires_approval"


class ToolGrant(BaseModel):
    """Least-privilege declaration for one tool."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    tool_id: str
    purpose: str = Field(min_length=8)
    allowed_operations: tuple[str, ...] = Field(min_length=1)
    denied_operations: tuple[str, ...] = ()
    write_access: bool = False
    network_access: bool = False
    connector_access: bool = False
    secrets_access: bool = False

    @field_validator("tool_id")
    @classmethod
    def validate_tool_id(cls, value: str) -> str:
        if _IDENTIFIER_PATTERN.fullmatch(value) is None:
            raise ValueError("tool_id must be a stable lowercase identifier")
        return value

    @model_validator(mode="after")
    def validate_operation_boundaries(self) -> Self:
        overlap = set(self.allowed_operations) & set(self.denied_operations)
        if overlap:
            raise ValueError(f"tool operations cannot be both allowed and denied: {overlap}")
        if len(set(self.allowed_operations)) != len(self.allowed_operations):
            raise ValueError("allowed tool operations must be unique")
        if len(set(self.denied_operations)) != len(self.denied_operations):
            raise ValueError("denied tool operations must be unique")
        return self


class DataPermission(BaseModel):
    """Declared data access for a role."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    resource: str
    classification: Literal["public", "internal", "sensitive", "secret"]
    operations: tuple[Literal["read", "append", "write", "delete"], ...]
    purpose: str = Field(min_length=8)
    retention: str = Field(min_length=3)

    @field_validator("resource")
    @classmethod
    def validate_resource(cls, value: str) -> str:
        if not value.strip() or value.startswith("/") or ".." in value.split("/"):
            raise ValueError("resource must be a non-absolute logical path without traversal")
        return value

    @model_validator(mode="after")
    def validate_operations(self) -> Self:
        if len(set(self.operations)) != len(self.operations):
            raise ValueError("data operations must be unique")
        return self


class ConnectorGrant(BaseModel):
    """Explicit connector exception to the disabled-by-default policy."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    connector_id: str
    purpose: str = Field(min_length=12)
    least_privilege_scope: tuple[str, ...] = Field(min_length=1)
    prompt_injection_reviewed: Literal[True]
    audit_logging: Literal[True]
    approved_by: str = Field(min_length=3)
    revocation_procedure: tuple[str, ...] = Field(min_length=1)
    expires_on: date

    @field_validator("connector_id")
    @classmethod
    def validate_connector_id(cls, value: str) -> str:
        if _IDENTIFIER_PATTERN.fullmatch(value) is None:
            raise ValueError("connector_id must be a stable lowercase identifier")
        return value


class ConnectorPolicy(BaseModel):
    """Connector policy for one role."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    default: Literal["disabled"] = "disabled"
    grants: tuple[ConnectorGrant, ...] = ()

    @model_validator(mode="after")
    def validate_unique_connectors(self) -> Self:
        identifiers = [grant.connector_id for grant in self.grants]
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("connector grants must have unique connector_id values")
        return self


class ExternalDependency(BaseModel):
    """Reviewed and pinned third-party plugin, skill, or package."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    dependency_id: str
    source: str = Field(min_length=4)
    pinned_reference: str = Field(min_length=3)
    integrity_sha256: str
    risk_level: RiskLevel
    reviewed_by: str = Field(min_length=3)
    reviewed_on: date
    allowed_capabilities: tuple[str, ...] = Field(min_length=1)
    denied_capabilities: tuple[str, ...] = ()
    verification_tests: tuple[str, ...] = Field(min_length=1)
    rollback_procedure: tuple[str, ...] = Field(min_length=1)

    @field_validator("dependency_id")
    @classmethod
    def validate_dependency_id(cls, value: str) -> str:
        if _IDENTIFIER_PATTERN.fullmatch(value) is None:
            raise ValueError("dependency_id must be a stable lowercase identifier")
        return value

    @field_validator("pinned_reference")
    @classmethod
    def validate_pinned_reference(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized in _FORBIDDEN_PIN_REFERENCES or "*" in normalized:
            raise ValueError("third-party dependencies must use an immutable pin")
        return value

    @field_validator("integrity_sha256")
    @classmethod
    def validate_integrity_sha256(cls, value: str) -> str:
        normalized = value.lower()
        if _SHA256_PATTERN.fullmatch(normalized) is None:
            raise ValueError("integrity_sha256 must be a 64-character hexadecimal digest")
        return normalized

    @model_validator(mode="after")
    def validate_capabilities(self) -> Self:
        overlap = set(self.allowed_capabilities) & set(self.denied_capabilities)
        if overlap:
            raise ValueError(f"dependency capabilities overlap: {overlap}")
        return self


class SkillDefinition(BaseModel):
    """Versioned declaration of one narrowly scoped capability."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    skill_id: str
    display_name: str = Field(min_length=3)
    owner: str = Field(min_length=3)
    version: str
    purpose: str = Field(min_length=20)
    risk_level: RiskLevel
    status: LifecycleStatus = LifecycleStatus.PLANNED
    trust_assumption: Literal["untrusted"] = "untrusted"
    allowed_inputs: tuple[str, ...] = Field(min_length=1)
    allowed_outputs: tuple[str, ...] = Field(min_length=1)
    allowed_actions: tuple[str, ...] = Field(min_length=1)
    denied_actions: tuple[str, ...] = Field(min_length=1)
    required_tools: tuple[str, ...] = ()
    verification_requirements: tuple[str, ...] = Field(min_length=1)
    required_tests: tuple[str, ...] = Field(min_length=1)
    last_reviewed_on: date
    rollback_procedure: tuple[str, ...] = Field(min_length=1)
    external_dependencies: tuple[ExternalDependency, ...] = ()

    @field_validator("skill_id")
    @classmethod
    def validate_skill_id(cls, value: str) -> str:
        if _IDENTIFIER_PATTERN.fullmatch(value) is None:
            raise ValueError("skill_id must be a stable lowercase identifier")
        return value

    @field_validator("version")
    @classmethod
    def validate_version(cls, value: str) -> str:
        if _VERSION_PATTERN.fullmatch(value) is None:
            raise ValueError("version must be an exact semantic version")
        return value

    @model_validator(mode="after")
    def validate_actions_and_dependencies(self) -> Self:
        overlap = set(self.allowed_actions) & set(self.denied_actions)
        if overlap:
            raise ValueError(f"skill actions overlap: {overlap}")
        dependency_ids = [item.dependency_id for item in self.external_dependencies]
        if len(set(dependency_ids)) != len(dependency_ids):
            raise ValueError("external dependency IDs must be unique")
        return self


class RoleDefinition(BaseModel):
    """Versioned declaration of one narrowly scoped specialist role."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    role_id: str
    display_name: str = Field(min_length=3)
    owner: str = Field(min_length=3)
    version: str
    purpose: str = Field(min_length=20)
    risk_level: RiskLevel
    status: LifecycleStatus = LifecycleStatus.PLANNED
    trust_assumption: Literal["untrusted"] = "untrusted"
    allowed_inputs: tuple[str, ...] = Field(min_length=1)
    allowed_actions: tuple[str, ...] = Field(min_length=1)
    denied_actions: tuple[str, ...] = Field(min_length=1)
    skill_ids: tuple[str, ...] = Field(min_length=1)
    tools: tuple[ToolGrant, ...] = ()
    data_permissions: tuple[DataPermission, ...] = ()
    output_schema: dict[str, object]
    verification_requirements: tuple[str, ...] = Field(min_length=1)
    human_approval_points: tuple[str, ...] = ()
    required_tests: tuple[str, ...] = Field(min_length=1)
    last_reviewed_on: date
    rollback_procedure: tuple[str, ...] = Field(min_length=1)
    connector_policy: ConnectorPolicy = Field(default_factory=ConnectorPolicy)
    external_dependencies: tuple[ExternalDependency, ...] = ()

    @field_validator("role_id")
    @classmethod
    def validate_role_id(cls, value: str) -> str:
        if _IDENTIFIER_PATTERN.fullmatch(value) is None:
            raise ValueError("role_id must be a stable lowercase identifier")
        return value

    @field_validator("version")
    @classmethod
    def validate_version(cls, value: str) -> str:
        if _VERSION_PATTERN.fullmatch(value) is None:
            raise ValueError("version must be an exact semantic version")
        return value

    @model_validator(mode="after")
    def validate_role_boundaries(self) -> Self:
        overlap = set(self.allowed_actions) & set(self.denied_actions)
        if overlap:
            raise ValueError(f"role actions overlap: {overlap}")
        if not set(self.human_approval_points).issubset(self.allowed_actions):
            raise ValueError("human approval points must reference allowed actions")

        tool_ids = [tool.tool_id for tool in self.tools]
        if len(set(tool_ids)) != len(tool_ids):
            raise ValueError("role tools must have unique tool_id values")

        resources = [permission.resource for permission in self.data_permissions]
        if len(set(resources)) != len(resources):
            raise ValueError("role data permissions must have unique resources")

        dependency_ids = [item.dependency_id for item in self.external_dependencies]
        if len(set(dependency_ids)) != len(dependency_ids):
            raise ValueError("external dependency IDs must be unique")

        try:
            json.dumps(self.output_schema, sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError) as exc:
            raise ValueError("output_schema must be JSON serializable") from exc
        if self.output_schema.get("type") != "object":
            raise ValueError("output_schema must describe a JSON object")

        if any(tool.connector_access for tool in self.tools) and not self.connector_policy.grants:
            raise ValueError("connector-capable tools require explicit connector grants")
        return self


class RegistryManifest(BaseModel):
    """Top-level manifest for a complete registry snapshot."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    registry_version: str
    owner: str = Field(min_length=3)
    default_trust: Literal["untrusted"] = "untrusted"
    default_connector_policy: Literal["disabled"] = "disabled"
    role_files: tuple[str, ...] = Field(min_length=1)
    skill_files: tuple[str, ...] = Field(min_length=1)
    required_role_ids: tuple[str, ...] = Field(min_length=1)
    required_skill_ids: tuple[str, ...] = Field(min_length=1)
    global_denied_actions: tuple[str, ...] = Field(min_length=1)
    review_cadence_days: int = Field(ge=1, le=365)
    last_reviewed_on: date

    @field_validator("registry_version")
    @classmethod
    def validate_registry_version(cls, value: str) -> str:
        if _VERSION_PATTERN.fullmatch(value) is None:
            raise ValueError("registry_version must be an exact semantic version")
        return value

    @model_validator(mode="after")
    def validate_manifest_uniqueness(self) -> Self:
        fields = (
            self.role_files,
            self.skill_files,
            self.required_role_ids,
            self.required_skill_ids,
            self.global_denied_actions,
        )
        if any(len(set(values)) != len(values) for values in fields):
            raise ValueError("manifest lists must contain unique values")
        return self


class ActionDecision(BaseModel):
    """Fail-closed result from evaluating one proposed role action."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    status: DecisionStatus
    role_id: str
    action: str
    reason: str
    tool_id: str | None = None
    operation: str | None = None
    connector_id: str | None = None
    approval_reference: str | None = None


class RegistryValidationReport(BaseModel):
    """Deterministic validation summary for one registry snapshot."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    registry_version: str
    role_count: int = Field(ge=0)
    skill_count: int = Field(ge=0)
    active_role_count: int = Field(ge=0)
    planned_role_count: int = Field(ge=0)
    connector_grant_count: int = Field(ge=0)
    external_dependency_count: int = Field(ge=0)
    fingerprint_sha256: str
    warnings: tuple[str, ...] = ()

    @field_validator("fingerprint_sha256")
    @classmethod
    def validate_fingerprint(cls, value: str) -> str:
        normalized = value.lower()
        if _SHA256_PATTERN.fullmatch(normalized) is None:
            raise ValueError("fingerprint_sha256 must be a SHA-256 digest")
        return normalized
