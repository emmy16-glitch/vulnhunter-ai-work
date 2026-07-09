"""Immutable target-authorization records and audit events."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

AuthorizationStatus = Literal["active", "revoked"]
AuthorizationEventType = Literal[
    "created",
    "validated",
    "validation_rejected",
    "scan_started",
    "scan_completed",
    "scan_failed",
    "revoked",
]


class AuthorizationLimits(BaseModel):
    """Maximum passive-scan activity permitted by one authorization."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    maximum_pages: int = Field(ge=1, le=500)
    maximum_depth: int = Field(ge=0, le=10)
    maximum_requests: int = Field(ge=1, le=10_000)
    minimum_request_delay_seconds: float = Field(ge=0, le=10)


class AuthorizationRecord(BaseModel):
    """An immutable permission boundary plus its current revocation state."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    authorization_id: str = Field(min_length=8, max_length=80)
    target_url: str = Field(min_length=1, max_length=2_000)
    scheme: Literal["http", "https"]
    hostname: str = Field(min_length=1, max_length=255)
    port: int = Field(ge=1, le=65_535)
    path_boundary: str = Field(min_length=1, max_length=2_000)
    approved_addresses: tuple[str, ...] = Field(min_length=1)
    owner: str = Field(min_length=1, max_length=300)
    approved_by: str = Field(min_length=1, max_length=300)
    purpose: str = Field(min_length=1, max_length=2_000)
    evidence_reference: str | None = Field(default=None, max_length=2_000)
    issued_at: datetime
    valid_from: datetime
    expires_at: datetime
    limits: AuthorizationLimits
    status: AuthorizationStatus = "active"
    revoked_at: datetime | None = None
    revocation_reason: str | None = Field(default=None, max_length=2_000)
    record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("issued_at", "valid_from", "expires_at", "revoked_at")
    @classmethod
    def require_timezone(cls, value: datetime | None) -> datetime | None:
        """Reject ambiguous local timestamps at the trust boundary."""
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Authorization timestamps must include a timezone.")
        return value.astimezone(UTC)


class AuthorizationEvent(BaseModel):
    """Append-only authorization audit event."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: int
    authorization_id: str
    event_type: AuthorizationEventType
    occurred_at: datetime
    detail: dict[str, object]


class AuthorizationDecision(BaseModel):
    """Successful authorization validation for one requested scan."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    authorization_id: str
    target_url: str
    checked_at: datetime
    limits: AuthorizationLimits


def authorization_record_sha256(record: AuthorizationRecord | dict[str, object]) -> str:
    """Return a deterministic integrity hash excluding the hash field itself."""
    if isinstance(record, AuthorizationRecord):
        validated = record
    else:
        candidate = dict(record)
        candidate["record_sha256"] = "0" * 64
        validated = AuthorizationRecord.model_validate(candidate)

    payload = validated.model_dump(mode="json", exclude={"record_sha256"})
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
