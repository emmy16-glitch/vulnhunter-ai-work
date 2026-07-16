"""Contracts for a disabled-by-default, allowlisted privileged broker."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def utc_now() -> datetime:
    return datetime.now(UTC)


class GrantStatus(StrEnum):
    ISSUED = "issued"
    CONSUMED = "consumed"
    EXPIRED = "expired"
    REVOKED = "revoked"


class BrokerOperation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    operation_id: str
    executable: str
    fixed_arguments: tuple[str, ...]
    maximum_runtime_seconds: int = Field(default=30, ge=1, le=300)
    allow_variable_arguments: bool = False

    @field_validator("operation_id")
    @classmethod
    def validate_operation_id(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("operation_id must be a stable lowercase identifier")
        return value

    @field_validator("executable")
    @classmethod
    def validate_executable(cls, value: str) -> str:
        if not value.startswith("/") or "\x00" in value:
            raise ValueError("broker executable must be an absolute path")
        return value


class PrivilegedGrant(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    grant_id: str
    operation_id: str
    actor_id: str
    approver_id: str
    action_manifest_sha256: str
    execution_id: str
    target_sha256: str
    issued_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime
    status: GrantStatus = GrantStatus.ISSUED
    consumed_at: datetime | None = None

    @field_validator("grant_id", "operation_id", "actor_id", "approver_id", "execution_id")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("grant identifiers must be stable lowercase values")
        return value

    @field_validator("action_manifest_sha256", "target_sha256")
    @classmethod
    def validate_hash(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("grant bindings must be SHA-256 digests")
        return value

    @model_validator(mode="after")
    def validate_grant(self):
        if self.actor_id == self.approver_id:
            raise ValueError("requester and approver must be different actors")
        if self.expires_at <= self.issued_at:
            raise ValueError("grant expiry must be after issuance")
        if self.status == GrantStatus.CONSUMED and self.consumed_at is None:
            raise ValueError("consumed grant requires consumed_at")
        return self
