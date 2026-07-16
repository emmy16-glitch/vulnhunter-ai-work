"""Short-lived, action-bound privilege contracts."""

from __future__ import annotations

import re
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def utc_now() -> datetime:
    return datetime.now(UTC)


class PrivilegeGrant(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    grant_id: str
    owner_id: str
    campaign_id: str
    action_manifest_sha256: str
    approval_request_id: str
    issued_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime
    maximum_actions: int = Field(default=1, ge=1, le=100)
    consumed_actions: int = Field(default=0, ge=0, le=100)
    revoked: bool = False

    @field_validator("grant_id", "owner_id", "campaign_id", "approval_request_id")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("identifier must be a stable lowercase value")
        return value

    @field_validator("action_manifest_sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("action_manifest_sha256 must be a SHA-256 digest")
        return value

    @model_validator(mode="after")
    def validate_grant(self):
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be later than issued_at")
        if self.consumed_actions > self.maximum_actions:
            raise ValueError("consumed actions exceed grant limit")
        return self

    def is_active(self, now: datetime | None = None) -> bool:
        instant = now or datetime.now(UTC)
        return (
            not self.revoked
            and instant < self.expires_at
            and self.consumed_actions < self.maximum_actions
        )


class PrivilegedBrokerRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    request_id: str
    grant_id: str
    action_manifest_sha256: str
    tool_id: str
    operation: str
    target_reference: str
    fixed_arguments: tuple[str, ...]
    timeout_seconds: int = Field(ge=1, le=3600)

    @field_validator("request_id", "grant_id", "tool_id", "operation")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("identifier must be a stable lowercase value")
        return value

    @field_validator("action_manifest_sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("action_manifest_sha256 must be a SHA-256 digest")
        return value
