"""Untrusted third-party skill import contracts."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator

_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9.-]{1,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def utc_now() -> datetime:
    return datetime.now(UTC)


class ImportRisk(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ImportDecision(StrEnum):
    REJECTED = "rejected"
    REVIEW_REQUIRED = "review_required"
    SAFE_TO_REWRITE = "safe_to_rewrite"


class ImportedFileRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    relative_path: str
    sha256: str
    size_bytes: int = Field(ge=0)
    executable: bool = False
    findings: tuple[str, ...] = ()

    @field_validator("sha256")
    @classmethod
    def validate_sha(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("sha256 must be a digest")
        return value


class SkillImportReview(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    review_id: str
    source_reference: str = Field(min_length=4, max_length=1_000)
    source_sha256: str
    files: tuple[ImportedFileRecord, ...]
    risk: ImportRisk
    decision: ImportDecision
    reasons: tuple[str, ...]
    activation_allowed: bool = False
    reviewed_at: datetime = Field(default_factory=utc_now)

    @field_validator("review_id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("review_id must be a stable identifier")
        return value
