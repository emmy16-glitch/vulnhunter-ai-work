"""Analyst feedback models for governed evaluation."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator

_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")


def utc_now() -> datetime:
    return datetime.now(UTC)


class AnalystOutcome(StrEnum):
    ACCEPT = "accept"
    REJECT = "reject"
    FALSE_POSITIVE = "false_positive"
    SEVERITY_CORRECTION = "severity_correction"
    CONFIDENCE_CORRECTION = "confidence_correction"
    REQUEST_MORE_EVIDENCE = "request_more_evidence"
    VERIFICATION_PASSED = "verification_passed"
    VERIFICATION_FAILED = "verification_failed"
    ORACLE_AGREEMENT = "oracle_agreement"
    ORACLE_DISAGREEMENT = "oracle_disagreement"
    REMEDIATION_ACCEPTED = "remediation_accepted"
    RETEST_FAILED = "retest_failed"
    RETEST_PASSED = "retest_passed"


class AnalystFeedback(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    feedback_id: str
    finding_id: str
    analyst_id: str
    outcome: AnalystOutcome
    evidence_references: tuple[str, ...] = ()
    notes: str = Field(min_length=3, max_length=1_000)
    recorded_at: datetime = Field(default_factory=utc_now)

    @field_validator("feedback_id", "finding_id", "analyst_id")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("identifier must be a stable lowercase value")
        return value


class FeedbackMetrics(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    records: int
    accepted: int
    rejected: int
    false_positives: int
    oracle_agreements: int
    oracle_disagreements: int
    retest_passed: int
    retest_failed: int
