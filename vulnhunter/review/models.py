"""Immutable second-review and adjudication records."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from vulnhunter.observations.models import ObservationSummary, ReviewLabel

IndependentReviewOutcome = Literal["confirmed", "false_positive"]
ReviewCaseState = Literal[
    "unreviewed",
    "pending_second_review",
    "consensus",
    "disputed",
    "adjudicated",
    "legacy_final",
    "legacy_needs_review",
]


class ReviewDecisionSummary(BaseModel):
    """One immutable primary-review decision by a pseudonymous reviewer."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: int = Field(ge=1)
    observation_id: int = Field(ge=1)
    reviewer_id: str = Field(min_length=2, max_length=64)
    outcome: IndependentReviewOutcome
    note: str | None = Field(default=None, max_length=2_000)
    created_at: datetime


class ReviewAdjudicationSummary(BaseModel):
    """One final resolution of a disagreement by an independent adjudicator."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: int = Field(ge=1)
    observation_id: int = Field(ge=1)
    adjudicator_id: str = Field(min_length=2, max_length=64)
    outcome: IndependentReviewOutcome
    rationale: str = Field(min_length=1, max_length=2_000)
    created_at: datetime


class ReviewCaseSummary(BaseModel):
    """Current auditable state of one observation's review case."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    observation: ObservationSummary
    state: ReviewCaseState
    effective_label: ReviewLabel
    decisions: tuple[ReviewDecisionSummary, ...] = ()
    adjudication: ReviewAdjudicationSummary | None = None
