"""Immutable models for exact, attributable, one-time human approvals."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from vulnhunter.actions.models import sha256_json

_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def utc_now() -> datetime:
    return datetime.now(UTC)


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    INFORMATION_REQUIRED = "information_required"
    CONDITIONS_PROPOSED = "conditions_proposed"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    CANCELLED = "cancelled"
    CONSUMED = "consumed"


class ApprovalDecision(StrEnum):
    APPROVE_ONCE = "approve_once"
    APPROVE_WITH_CONDITIONS = "approve_with_conditions"
    REQUEST_MORE_INFORMATION = "request_more_information"
    PROPOSE_SAFER_ALTERNATIVE = "propose_safer_alternative"
    DENY_CONTINUE_SAFELY = "deny_continue_safely"
    DENY_STOP_RUN = "deny_stop_run"


class ApprovalRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    request_id: str
    campaign_id: str
    run_id: str
    action_manifest_sha256: str
    requested_by: str
    summary: str = Field(min_length=8, max_length=500)
    risk_summary: str = Field(min_length=8, max_length=500)
    requested_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime
    status: ApprovalStatus = ApprovalStatus.PENDING
    decided_by: str | None = None
    decision: ApprovalDecision | None = None
    decision_reason: str | None = None
    conditions: tuple[str, ...] = ()
    decided_at: datetime | None = None
    consumed_at: datetime | None = None
    consumed_by_execution_id: str | None = None

    @field_validator("request_id", "campaign_id", "run_id", "requested_by")
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

    @field_validator("conditions")
    @classmethod
    def validate_conditions(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(value.strip() for value in values)
        if any(not value for value in normalized):
            raise ValueError("conditions must not be blank")
        return normalized

    @model_validator(mode="after")
    def validate_state(self) -> Self:
        if self.expires_at <= self.requested_at:
            raise ValueError("expires_at must be later than requested_at")
        if self.status in {ApprovalStatus.APPROVED, ApprovalStatus.DENIED}:
            if not self.decided_by or not self.decision or not self.decided_at:
                raise ValueError("decided requests require attributable decision metadata")
        if self.status == ApprovalStatus.CONSUMED:
            if not self.consumed_at or not self.consumed_by_execution_id:
                raise ValueError("consumed approvals require execution metadata")
        if self.decision == ApprovalDecision.APPROVE_WITH_CONDITIONS and not self.conditions:
            raise ValueError("conditional approval requires at least one condition")
        return self

    def fingerprint(self) -> str:
        return sha256_json(self.model_dump(mode="json"))


class ApprovalEvent(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    sequence: int = Field(ge=1)
    request_id: str
    event_type: str
    actor_id: str
    occurred_at: datetime
    detail: dict[str, object]
    previous_sha256: str
    event_sha256: str
