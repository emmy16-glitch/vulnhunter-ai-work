"""Strict models for controlled synthetic impact simulation."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from vulnhunter.agent.models import sha256_json

_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")


def _utc(value: datetime, *, field: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must be timezone-aware")
    return value.astimezone(UTC)


def _identifier(value: str) -> str:
    normalized = value.strip().lower()
    if _IDENTIFIER.fullmatch(normalized) is None:
        raise ValueError(
            "identifier must contain lowercase letters, numbers, dots, dashes, or underscores"
        )
    return normalized


class LabState(StrEnum):
    """Persisted lifecycle states for one emulation run."""

    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    QUEUED = "queued"
    PROVISIONING = "provisioning"
    RUNNING = "running"
    EVALUATING = "evaluating"
    CLEANING = "cleaning"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    BLOCKED = "blocked"
    FAILED = "failed"


TERMINAL_LAB_STATES = frozenset(
    {LabState.COMPLETED, LabState.CANCELLED, LabState.BLOCKED, LabState.FAILED}
)


class TrialOutcome(StrEnum):
    """One bounded trial result."""

    CONFIRMED = "confirmed"
    NOT_REPRODUCED = "not_reproduced"
    INCONCLUSIVE = "inconclusive"
    CANCELLED = "cancelled"
    FAILED = "failed"


class LabScenario(BaseModel):
    """Reviewed simulation scenario; never free-form operator code."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    scenario_id: str
    version: str
    title: str = Field(min_length=3, max_length=120)
    summary: str = Field(min_length=3, max_length=500)
    risk_label: Literal["controlled"]
    tool_ids: tuple[str, ...] = Field(min_length=1, max_length=8)
    variations: tuple[str, ...] = Field(min_length=1, max_length=10)
    expected_evidence: tuple[str, ...] = Field(min_length=1, max_length=10)
    prohibited_operations: tuple[str, ...] = Field(min_length=1, max_length=30)

    @field_validator("scenario_id")
    @classmethod
    def validate_scenario_id(cls, value: str) -> str:
        return _identifier(value)


class LabPlan(BaseModel):
    """Immutable plan bound to one assessment finding and human approval."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    lab_id: str
    assessment_id: str
    finding_reference: str = Field(min_length=3, max_length=256)
    authorization_id: str = Field(min_length=3, max_length=256)
    target_reference: str = Field(min_length=3, max_length=500)
    scenario_id: str
    scenario_version: str
    requested_by: str = Field(min_length=1, max_length=150)
    requested_at: datetime
    maximum_trials: int = Field(ge=1, le=10)
    minimum_trials: int = Field(ge=1, le=10)
    required_confirmations: int = Field(ge=1, le=10)
    per_trial_timeout_seconds: int = Field(ge=5, le=300)
    total_timeout_seconds: int = Field(ge=30, le=3_600)
    variations: tuple[str, ...] = Field(min_length=1, max_length=10)
    network_mode: Literal["isolated-no-egress"] = "isolated-no-egress"
    synthetic_data_only: Literal[True] = True
    arbitrary_commands_allowed: Literal[False] = False
    public_targets_allowed: Literal[False] = False
    plan_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("lab_id", "assessment_id", "scenario_id")
    @classmethod
    def validate_ids(cls, value: str) -> str:
        return _identifier(value)

    @field_validator("requested_at")
    @classmethod
    def validate_requested_at(cls, value: datetime) -> datetime:
        return _utc(value, field="requested_at")

    @model_validator(mode="after")
    def validate_trial_policy(self) -> Self:
        if self.minimum_trials > self.maximum_trials:
            raise ValueError("minimum_trials must not exceed maximum_trials")
        if self.required_confirmations > self.maximum_trials:
            raise ValueError("required_confirmations must not exceed maximum_trials")
        if len(self.variations) < self.maximum_trials:
            raise ValueError(
                "the signed plan must contain one reviewed variation per possible trial"
            )
        return self

    def fingerprint(self) -> str:
        return sha256_json(self.model_dump(mode="json", exclude={"plan_digest"}))

    @classmethod
    def create(
        cls,
        *,
        lab_id: str,
        assessment_id: str,
        finding_reference: str,
        authorization_id: str,
        target_reference: str,
        scenario: LabScenario,
        requested_by: str,
        requested_at: datetime,
        maximum_trials: int,
        per_trial_timeout_seconds: int = 60,
        total_timeout_seconds: int = 900,
    ) -> Self:
        minimum_trials = min(3, maximum_trials)
        required_confirmations = min(2, maximum_trials)
        variations = tuple(
            scenario.variations[index % len(scenario.variations)] for index in range(maximum_trials)
        )
        provisional = cls(
            lab_id=lab_id,
            assessment_id=assessment_id,
            finding_reference=finding_reference,
            authorization_id=authorization_id,
            target_reference=target_reference,
            scenario_id=scenario.scenario_id,
            scenario_version=scenario.version,
            requested_by=requested_by,
            requested_at=requested_at,
            maximum_trials=maximum_trials,
            minimum_trials=minimum_trials,
            required_confirmations=required_confirmations,
            per_trial_timeout_seconds=per_trial_timeout_seconds,
            total_timeout_seconds=total_timeout_seconds,
            variations=variations,
            plan_digest="0" * 64,
        )
        return provisional.model_copy(update={"plan_digest": provisional.fingerprint()})


class LabTrialResult(BaseModel):
    """Persisted bounded result from one clean-snapshot trial."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    trial_number: int = Field(ge=1, le=10)
    variation: str = Field(min_length=1, max_length=120)
    outcome: TrialOutcome
    summary: str = Field(min_length=1, max_length=500)
    started_at: datetime
    completed_at: datetime
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    artifact_names: tuple[str, ...] = Field(default=(), max_length=20)
    snapshot_restored: bool
    metadata: dict[str, object] = Field(default_factory=dict)

    @field_validator("started_at", "completed_at")
    @classmethod
    def validate_timestamps(cls, value: datetime) -> datetime:
        return _utc(value, field="trial timestamp")


class LabRecord(BaseModel):
    """Mutable persisted envelope for one signed plan."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    plan: LabPlan
    state: LabState = LabState.AWAITING_APPROVAL
    approved_by: str | None = Field(default=None, max_length=150)
    approved_at: datetime | None = None
    approved_plan_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    queued_by: str | None = Field(default=None, max_length=150)
    current_trial: int = Field(default=0, ge=0, le=10)
    confirmed_trials: int = Field(default=0, ge=0, le=10)
    inconclusive_trials: int = Field(default=0, ge=0, le=10)
    failed_trials: int = Field(default=0, ge=0, le=10)
    trials: tuple[LabTrialResult, ...] = Field(default=(), max_length=10)
    cancellation_requested: bool = False
    cancellation_reason: str | None = Field(default=None, max_length=500)
    cleanup_verified: bool = False
    result: str | None = Field(default=None, max_length=120)
    human_review_state: Literal["pending", "accepted", "rejected"] = "pending"
    active_summary: str = Field(default="Waiting for independent approval.", max_length=500)
    created_at: datetime
    updated_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    revision: int = Field(default=1, ge=1)

    @field_validator("created_at", "updated_at", "approved_at", "started_at", "completed_at")
    @classmethod
    def validate_record_timestamps(cls, value: datetime | None) -> datetime | None:
        return _utc(value, field="record timestamp") if value is not None else None

    @property
    def terminal(self) -> bool:
        return self.state in TERMINAL_LAB_STATES
