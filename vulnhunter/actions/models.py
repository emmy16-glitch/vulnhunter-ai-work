"""Immutable action contracts for governed security operations."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
_ACTION = re.compile(r"^[a-z][a-z0-9_.-]{2,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def utc_now() -> datetime:
    return datetime.now(UTC)


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def sha256_json(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


class ActionClass(StrEnum):
    """Risk and side-effect class for one requested operation."""

    READ_ONLY = "read_only"
    REVERSIBLE_LOCAL = "reversible_local"
    CONSEQUENTIAL = "consequential"
    SENSITIVE = "sensitive"
    FORBIDDEN = "forbidden"


class ActionDecisionStatus(StrEnum):
    """Deterministic policy result."""

    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


class ExecutionLimits(BaseModel):
    """Bounded runtime limits carried inside every action manifest."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    timeout_seconds: int = Field(default=300, ge=1, le=86_400)
    maximum_requests: int = Field(default=100, ge=1, le=1_000_000)
    maximum_output_bytes: int = Field(default=2_000_000, ge=1_024, le=100_000_000)
    maximum_targets: int = Field(default=1, ge=1, le=65_536)
    maximum_attempts: int = Field(default=1, ge=1, le=10)


class ActionManifest(BaseModel):
    """Exact, hash-bound request for a single governed action."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    manifest_id: str
    campaign_id: str
    requested_by: str
    role_id: str
    skill_id: str
    action: str
    action_class: ActionClass
    tool_id: str
    operation: str
    target_references: tuple[str, ...] = Field(min_length=1)
    authorization_references: tuple[str, ...] = Field(min_length=1)
    limits: ExecutionLimits = Field(default_factory=ExecutionLimits)
    approval_required: bool = False
    created_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime
    parent_manifest_sha256: str | None = None
    purpose: str = Field(min_length=8, max_length=500)

    @field_validator(
        "manifest_id",
        "campaign_id",
        "requested_by",
        "role_id",
        "skill_id",
        "tool_id",
        "operation",
    )
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("identifier must be a stable lowercase value")
        return value

    @field_validator("action")
    @classmethod
    def validate_action(cls, value: str) -> str:
        if _ACTION.fullmatch(value) is None:
            raise ValueError("action must be a stable dotted identifier")
        return value

    @field_validator("target_references", "authorization_references")
    @classmethod
    def validate_references(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(item.strip() for item in values)
        if any(not item for item in normalized):
            raise ValueError("references must not be blank")
        if len(set(normalized)) != len(normalized):
            raise ValueError("references must be unique")
        return normalized

    @field_validator("parent_manifest_sha256")
    @classmethod
    def validate_optional_sha256(cls, value: str | None) -> str | None:
        if value is not None and _SHA256.fullmatch(value) is None:
            raise ValueError("parent_manifest_sha256 must be a SHA-256 digest")
        return value

    @model_validator(mode="after")
    def validate_contract(self) -> Self:
        if self.expires_at <= self.created_at:
            raise ValueError("expires_at must be later than created_at")
        if len(self.target_references) > self.limits.maximum_targets:
            raise ValueError("target count exceeds maximum_targets")
        if self.action_class in {ActionClass.CONSEQUENTIAL, ActionClass.SENSITIVE}:
            if not self.approval_required:
                raise ValueError("consequential and sensitive actions require approval")
        if self.action_class == ActionClass.FORBIDDEN:
            raise ValueError("forbidden actions cannot be represented as executable manifests")
        return self

    def fingerprint(self) -> str:
        return sha256_json(self.model_dump(mode="json"))


class ActionDecision(BaseModel):
    """Recorded deterministic result of evaluating an action manifest."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    status: ActionDecisionStatus
    reason: str = Field(min_length=3)
    manifest_sha256: str
    evaluated_at: datetime = Field(default_factory=utc_now)
    approval_request_id: str | None = None

    @field_validator("manifest_sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("manifest_sha256 must be a SHA-256 digest")
        return value
