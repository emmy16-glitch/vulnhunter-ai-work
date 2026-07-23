"""Typed contracts for reviewed memory, evaluation, and capability proposals."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal, Self
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def utc_now() -> datetime:
    return datetime.now(UTC)


def _digest(payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(encoded).hexdigest()


class MemoryKind(StrEnum):
    EPISODIC = "episodic"
    SEMANTIC = "semantic"
    PROCEDURAL = "procedural"


class CandidateStatus(StrEnum):
    PENDING_REVIEW = "pending_review"
    APPROVED_FOR_EVALUATION = "approved_for_evaluation"
    REJECTED = "rejected"
    PROMOTED = "promoted"
    RETIRED = "retired"


class ReviewDecision(StrEnum):
    APPROVE = "approve"
    REJECT = "reject"


class CapabilityAction(StrEnum):
    NETWORK_REQUEST = "network_request"
    GRANT_AUTHORIZATION = "grant_authorization"
    CHANGE_SEVERITY = "change_severity"
    PUBLISH_RESULT = "publish_result"
    EXPLOIT_ACTION = "exploit_action"


class MemoryCandidate(BaseModel):
    """Untrusted learning proposal that cannot affect runtime until promoted."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    candidate_id: str
    kind: MemoryKind
    content: str = Field(min_length=10, max_length=8_000)
    source_analysis_id: str
    source_finding_id: str
    source_run_id: str
    evidence_sha256: tuple[str, ...] = Field(min_length=1, max_length=64)
    created_by: Literal["ai", "human", "system"]
    status: CandidateStatus = CandidateStatus.PENDING_REVIEW
    advisory_only: bool = True
    authority_effect: Literal["none"] = "none"
    candidate_sha256: str
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    @field_validator("candidate_id", "source_analysis_id", "source_finding_id", "source_run_id")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("learning identifiers must be stable lowercase values")
        return value

    @field_validator("evidence_sha256")
    @classmethod
    def validate_evidence(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)):
            raise ValueError("evidence references must be unique")
        if any(_SHA256.fullmatch(value) is None for value in values):
            raise ValueError("evidence references must be SHA-256 digests")
        return values

    def unsigned_payload(self) -> dict[str, object]:
        return self.model_dump(
            mode="json",
            exclude={"candidate_sha256", "updated_at", "status"},
        )

    @classmethod
    def create(cls, **values: object) -> Self:
        draft = dict(values)
        draft.setdefault("candidate_id", f"memory-{uuid4().hex[:24]}")
        draft.setdefault("created_at", utc_now())
        draft.setdefault("updated_at", draft["created_at"])
        temporary = cls.model_construct(candidate_sha256="0" * 64, **draft)
        draft["candidate_sha256"] = _digest(temporary.unsigned_payload())
        return cls.model_validate(draft)

    @model_validator(mode="after")
    def validate_binding(self) -> Self:
        if not self.advisory_only or self.authority_effect != "none":
            raise ValueError("learning candidates cannot carry runtime authority")
        if self.candidate_sha256 != _digest(self.unsigned_payload()):
            raise ValueError("candidate digest does not match its immutable content")
        return self


class MemoryReview(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    review_id: str = Field(default_factory=lambda: f"review-{uuid4().hex[:24]}")
    candidate_id: str
    decision: ReviewDecision
    reviewer_id: str = Field(min_length=2, max_length=128)
    reason: str = Field(min_length=8, max_length=2_000)
    reviewed_at: datetime = Field(default_factory=utc_now)


class EvaluationResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    evaluation_id: str = Field(default_factory=lambda: f"evaluation-{uuid4().hex[:24]}")
    candidate_id: str
    suite_version: str = Field(min_length=3, max_length=100)
    evaluator_id: str = Field(min_length=2, max_length=128)
    grounding_score: float = Field(ge=0, le=1)
    safety_score: float = Field(ge=0, le=1)
    usefulness_score: float = Field(ge=0, le=1)
    regression_count: int = Field(ge=0, le=10_000)
    passed: bool
    notes: str = Field(default="", max_length=4_000)
    evaluated_at: datetime = Field(default_factory=utc_now)


class PromotionRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    promotion_id: str = Field(default_factory=lambda: f"promotion-{uuid4().hex[:24]}")
    candidate_id: str
    promoted_by: str = Field(min_length=2, max_length=128)
    policy_version: str = "controlled-memory-v1"
    promoted_at: datetime = Field(default_factory=utc_now)


class CapabilityProposal(BaseModel):
    """AI-authored request for a governed capability; never an execution grant."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    proposal_id: str = Field(default_factory=lambda: f"capability-{uuid4().hex[:24]}")
    action: CapabilityAction
    objective: str = Field(min_length=8, max_length=2_000)
    exact_target: str | None = Field(default=None, max_length=2_000)
    exact_scope_reference: str | None = Field(default=None, max_length=500)
    evidence_reference: str | None = Field(default=None, max_length=2_000)
    requested_by: Literal["ai", "human"] = "ai"
    requested_at: datetime = Field(default_factory=utc_now)
    execution_authority: Literal["none"] = "none"


class CapabilityDecision(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    proposal_id: str
    approved: bool
    decided_by: str = Field(min_length=2, max_length=128)
    approver_role: Literal[
        "authorization_owner",
        "security_analyst",
        "publisher",
        "test_environment_owner",
    ]
    reason: str = Field(min_length=8, max_length=2_000)
    decided_at: datetime = Field(default_factory=utc_now)
