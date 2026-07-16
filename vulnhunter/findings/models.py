"""Unified finding, remediation, and retest lifecycle contracts."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from vulnhunter.actions.models import sha256_json

_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def utc_now() -> datetime:
    return datetime.now(UTC)


class FindingSeverity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VerificationState(StrEnum):
    OBSERVED = "observed"
    NEEDS_REVIEW = "needs_review"
    VERIFIED = "verified"
    CONFLICTED = "conflicted"
    FALSE_POSITIVE = "false_positive"


class FindingStatus(StrEnum):
    OPEN = "open"
    TRIAGED = "triaged"
    IN_REMEDIATION = "in_remediation"
    READY_FOR_RETEST = "ready_for_retest"
    RETESTING = "retesting"
    REMEDIATED = "remediated"
    ACCEPTED_RISK = "accepted_risk"
    CLOSED = "closed"


class EvidenceReference(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence_id: str
    sha256: str
    provenance: str = Field(min_length=3, max_length=1_000)
    content_type: str = Field(min_length=3, max_length=200)

    @field_validator("evidence_id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("evidence_id must be a stable identifier")
        return value

    @field_validator("sha256")
    @classmethod
    def validate_sha(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("sha256 must be a digest")
        return value


class RemediationRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    summary: str = Field(min_length=10, max_length=5_000)
    owner_id: str | None = None
    due_at: datetime | None = None
    references: tuple[str, ...] = ()


class RetestRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    retest_id: str
    performed_by: str
    performed_at: datetime = Field(default_factory=utc_now)
    outcome: str = Field(pattern=r"^(passed|failed|partial|blocked)$")
    evidence: tuple[EvidenceReference, ...] = ()
    notes: str = Field(min_length=3, max_length=5_000)

    @field_validator("retest_id", "performed_by")
    @classmethod
    def validate_id(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("identifier must be stable and lowercase")
        return value


class Finding(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    finding_id: str
    campaign_id: str
    fingerprint: str
    title: str = Field(min_length=3, max_length=300)
    description: str = Field(min_length=10, max_length=20_000)
    severity: FindingSeverity
    confidence: int = Field(ge=0, le=100)
    verification: VerificationState = VerificationState.OBSERVED
    status: FindingStatus = FindingStatus.OPEN
    affected_asset: str = Field(min_length=1, max_length=1_000)
    affected_component: str | None = Field(default=None, max_length=1_000)
    cwe_ids: tuple[str, ...] = ()
    cve_ids: tuple[str, ...] = ()
    owasp_mappings: tuple[str, ...] = ()
    evidence: tuple[EvidenceReference, ...] = ()
    attack_path_ids: tuple[str, ...] = ()
    remediation: RemediationRecord | None = None
    retests: tuple[RetestRecord, ...] = ()
    analyst_decision: str | None = Field(default=None, max_length=5_000)
    revision: int = Field(default=0, ge=0)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    @field_validator("finding_id", "campaign_id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("identifier must be stable and lowercase")
        return value

    @field_validator("fingerprint")
    @classmethod
    def validate_fingerprint(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("fingerprint must be a SHA-256 digest")
        return value

    @model_validator(mode="after")
    def validate_lifecycle(self) -> Self:
        if self.updated_at < self.created_at:
            raise ValueError("updated_at cannot predate creation")
        if self.verification == VerificationState.VERIFIED and not self.evidence:
            raise ValueError("verified findings require evidence")
        if self.status == FindingStatus.REMEDIATED:
            if not self.retests or self.retests[-1].outcome != "passed":
                raise ValueError("remediated findings require a passed retest")
        return self

    @classmethod
    def create_fingerprint(
        cls,
        *,
        campaign_id: str,
        title: str,
        affected_asset: str,
        affected_component: str | None,
    ) -> str:
        return sha256_json(
            {
                "campaign_id": campaign_id,
                "title": title.strip().casefold(),
                "affected_asset": affected_asset.strip().casefold(),
                "affected_component": (affected_component or "").strip().casefold(),
            }
        )

    def validate_update_from(self, previous: Finding) -> None:
        for name in ("finding_id", "campaign_id", "fingerprint", "created_at"):
            if getattr(self, name) != getattr(previous, name):
                raise ValueError(f"finding field is immutable: {name}")
        if self.revision != previous.revision + 1:
            raise ValueError("finding revision must increase by exactly one")
        if self.updated_at < previous.updated_at:
            raise ValueError("finding updated_at cannot move backwards")
        old_evidence = {item.sha256 for item in previous.evidence}
        new_evidence = {item.sha256 for item in self.evidence}
        if not old_evidence.issubset(new_evidence):
            raise ValueError("finding evidence is append-only")
        if self.retests[: len(previous.retests)] != previous.retests:
            raise ValueError("finding retest history is append-only")
