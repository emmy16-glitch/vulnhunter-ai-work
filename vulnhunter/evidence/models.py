"""Evidence and finding lifecycle models."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator

from vulnhunter.actions.models import sha256_json

_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def utc_now() -> datetime:
    return datetime.now(UTC)


class FindingStatus(StrEnum):
    CANDIDATE = "candidate"
    OBSERVED = "observed"
    VALIDATED = "validated"
    INDEPENDENTLY_VERIFIED = "independently_verified"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"
    REMEDIATED = "remediated"
    RETEST_PASSED = "retest_passed"


class EvidenceRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence_id: str
    campaign_id: str
    run_id: str
    action_manifest_sha256: str
    tool_id: str
    target_reference: str
    finding_status: FindingStatus
    title: str = Field(min_length=3, max_length=500)
    severity: str
    confidence: str
    artifact_path: str | None = None
    artifact_sha256: str | None = None
    metadata: dict[str, object] = Field(default_factory=dict)
    recorded_by: str
    recorded_at: datetime = Field(default_factory=utc_now)
    previous_record_sha256: str = "0" * 64
    record_sha256: str

    @field_validator("evidence_id", "campaign_id", "run_id", "tool_id", "recorded_by")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("identifier must be a stable lowercase value")
        return value

    @field_validator(
        "action_manifest_sha256",
        "previous_record_sha256",
        "record_sha256",
        "artifact_sha256",
    )
    @classmethod
    def validate_sha256(cls, value: str | None) -> str | None:
        if value is not None and _SHA256.fullmatch(value) is None:
            raise ValueError("digest must be a SHA-256 value")
        return value

    def unsigned_payload(self) -> dict[str, object]:
        return self.model_dump(mode="json", exclude={"record_sha256"})

    def expected_sha256(self) -> str:
        return sha256_json(self.unsigned_payload())
