"""Typed, evidence-bound contracts for bounded advisory reasoning."""

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


class AnalysisStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    ABSTAINED = "abstained"
    FAILED = "failed"


class ReasoningStage(StrEnum):
    ANALYST = "analyst"
    CRITIC = "critic"
    SYNTHESIZER = "synthesizer"


class AdvisoryHypothesis(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    vulnerability_type: str = Field(min_length=3, max_length=200)
    cwe_ids: tuple[str, ...] = ()
    disposition: Literal["supported", "likely", "uncertain", "unlikely", "abstain"]
    confidence: int = Field(ge=0, le=100)
    evidence_refs: tuple[str, ...] = ()
    contradicting_evidence_refs: tuple[str, ...] = ()
    assumptions: tuple[str, ...] = ()
    explanation: str = Field(min_length=3, max_length=4_000)

    @field_validator("evidence_refs", "contradicting_evidence_refs")
    @classmethod
    def validate_evidence_refs(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)):
            raise ValueError("evidence references must be unique")
        if any(_SHA256.fullmatch(value) is None for value in values):
            raise ValueError("evidence references must be SHA-256 digests")
        return values


class AdvisoryStagePayload(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    summary: str = Field(min_length=3, max_length=5_000)
    conclusion: Literal["supported", "likely", "uncertain", "unlikely", "abstain"]
    hypotheses: tuple[AdvisoryHypothesis, ...] = Field(default=(), max_length=10)
    missing_information: tuple[str, ...] = Field(default=(), max_length=20)
    safe_verification_suggestions: tuple[str, ...] = Field(default=(), max_length=20)
    remediation_options: tuple[str, ...] = Field(default=(), max_length=20)


class FindingAnalysisRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    analysis_id: str
    finding_id: str
    run_id: str
    campaign_id: str
    title: str = Field(min_length=3, max_length=500)
    scanner_severity: str = Field(min_length=1, max_length=100)
    scanner_confidence: str = Field(min_length=1, max_length=100)
    verification_verdict: str = Field(min_length=1, max_length=100)
    verification_strategy: str = Field(min_length=1, max_length=200)
    scanner_template_id: str = Field(min_length=1, max_length=300)
    target_identity: str = Field(min_length=8, max_length=200)
    evidence_sha256: tuple[str, ...] = Field(min_length=1, max_length=64)
    safe_observations: tuple[str, ...] = Field(default=(), max_length=32)
    context_sha256: str
    created_at: datetime = Field(default_factory=utc_now)

    @field_validator("analysis_id", "finding_id", "run_id", "campaign_id")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("analysis identifiers must be stable lowercase values")
        return value

    @field_validator("context_sha256")
    @classmethod
    def validate_context_sha256(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("context_sha256 must be a SHA-256 digest")
        return value

    @field_validator("evidence_sha256")
    @classmethod
    def validate_evidence_sha256(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)):
            raise ValueError("evidence_sha256 must be unique")
        if any(_SHA256.fullmatch(value) is None for value in values):
            raise ValueError("evidence_sha256 values must be SHA-256 digests")
        return values

    def unsigned_payload(self) -> dict[str, object]:
        return self.model_dump(mode="json", exclude={"context_sha256"})

    @classmethod
    def create(cls, **values) -> Self:
        draft = dict(values)
        draft.setdefault("created_at", utc_now())
        temporary = cls.model_construct(context_sha256="0" * 64, **draft)
        draft["context_sha256"] = sha256_json(temporary.unsigned_payload())
        return cls.model_validate(draft)

    @model_validator(mode="after")
    def validate_context_binding(self) -> Self:
        if self.context_sha256 != sha256_json(self.unsigned_payload()):
            raise ValueError("analysis request context digest does not match")
        return self


class AdvisoryStageResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    stage: ReasoningStage
    model: str = Field(min_length=3, max_length=200)
    reasoning_effort: Literal["low", "medium", "high"]
    payload: AdvisoryStagePayload
    output_sha256: str
    created_at: datetime = Field(default_factory=utc_now)

    @field_validator("output_sha256")
    @classmethod
    def validate_output_sha256(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("output_sha256 must be a SHA-256 digest")
        return value


class FindingIntelligenceReport(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    analysis_id: str
    finding_id: str
    run_id: str
    status: AnalysisStatus
    stages: tuple[AdvisoryStageResult, ...] = Field(default=(), max_length=3)
    final: AdvisoryStagePayload | None = None
    models: tuple[str, ...] = ()
    advisory_only: bool = True
    trusted: bool = False
    safe_error: str | None = Field(default=None, max_length=1_000)
    created_at: datetime
    completed_at: datetime = Field(default_factory=utc_now)

    @field_validator("analysis_id", "finding_id", "run_id")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("report identifiers must be stable lowercase values")
        return value

    @model_validator(mode="after")
    def validate_report(self) -> Self:
        if self.trusted or not self.advisory_only:
            raise ValueError("intelligence reports are always untrusted advisory output")
        expected = (
            ReasoningStage.ANALYST,
            ReasoningStage.CRITIC,
            ReasoningStage.SYNTHESIZER,
        )
        actual = tuple(stage.stage for stage in self.stages)
        if actual != expected[: len(actual)]:
            raise ValueError("reasoning stages must follow analyst, critic, synthesizer order")
        if self.status == AnalysisStatus.COMPLETED:
            if len(self.stages) != 3 or self.final is None:
                raise ValueError("completed reports require all three stages and a final payload")
        if self.status in {AnalysisStatus.ABSTAINED, AnalysisStatus.FAILED} and not self.safe_error:
            raise ValueError("non-completed reports require a safe error")
        return self
