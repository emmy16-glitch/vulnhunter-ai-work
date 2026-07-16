"""Strict immutable models for safe bounded-agent activity events."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

ActivityEventType = Literal[
    "run_created",
    "objective_received",
    "planning_started",
    "plan_proposed",
    "role_selected",
    "skill_selected",
    "authorization_check_started",
    "authorization_check_passed",
    "authorization_check_failed",
    "scope_check_started",
    "scope_check_passed",
    "scope_check_failed",
    "policy_check_started",
    "policy_allowed",
    "policy_denied",
    "approval_requested",
    "approval_granted",
    "approval_rejected",
    "tool_execution_started",
    "tool_progress",
    "tool_execution_completed",
    "tool_execution_failed",
    "evaluation_started",
    "evaluation_completed",
    "retry_scheduled",
    "run_paused",
    "run_resumed",
    "stop_requested",
    "run_stopped",
    "run_blocked",
    "run_failed",
    "run_completed",
]
ActivityRunState = Literal[
    "created",
    "planning",
    "checking_authorization",
    "checking_scope",
    "checking_policy",
    "awaiting_approval",
    "executing",
    "evaluating",
    "paused",
    "stopping",
    "stopped",
    "cancelled",
    "blocked",
    "failed",
    "completed",
]
ActivitySource = Literal[
    "runtime",
    "planner",
    "policy",
    "approval",
    "tool",
    "evaluator",
    "operator",
    "system",
]
PolicyOutcome = Literal[
    "not_checked",
    "allowed",
    "denied",
    "requires_approval",
    "unavailable",
]
ApprovalRequirement = Literal["not_required", "required", "unavailable"]
ApprovalState = Literal[
    "not_applicable",
    "pending",
    "granted",
    "rejected",
    "unavailable",
]
ExecutionState = Literal[
    "not_started",
    "queued",
    "running",
    "succeeded",
    "failed",
    "cancelled",
    "blocked",
    "unavailable",
]
RiskLevel = Literal["low", "moderate", "high", "critical", "unknown"]

TERMINAL_RUN_STATES = frozenset({"stopped", "cancelled", "blocked", "failed", "completed"})


class ActivityEventDraft(BaseModel):
    """One safe operational transition before append-only sequencing."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    run_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")
    timestamp: datetime
    event_type: ActivityEventType
    summary: str = Field(min_length=1, max_length=500)
    run_state: ActivityRunState
    source: ActivitySource
    role_id: str | None = Field(default=None, max_length=128)
    skill_id: str | None = Field(default=None, max_length=128)
    tool_id: str | None = Field(default=None, max_length=128)
    authorization_reference: str | None = Field(default=None, max_length=256)
    scope_reference: str | None = Field(default=None, max_length=256)
    policy_outcome: PolicyOutcome = "not_checked"
    approval_requirement: ApprovalRequirement = "not_required"
    approval_state: ApprovalState = "not_applicable"
    execution_state: ExecutionState = "not_started"
    risk_level: RiskLevel = "unknown"
    audit_reference: str | None = Field(default=None, max_length=256)
    error_code: str | None = Field(default=None, max_length=128)
    error_message: str | None = Field(default=None, max_length=500)
    metadata: dict[str, object] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def timestamp_must_be_timezone_aware(cls, value: datetime) -> datetime:
        """Normalize every event time to UTC and reject ambiguous timestamps."""
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must be timezone-aware")
        return value.astimezone(UTC)


class ActivityEvent(ActivityEventDraft):
    """One immutable, hash-chained activity event."""

    event_id: str = Field(pattern=r"^evt_[0-9a-f]{24}$")
    sequence: int = Field(ge=1)
    previous_event_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    event_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ActivityFeedSnapshot(BaseModel):
    """Safe ordered view of one run's activity events."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    run_id: str
    events: tuple[ActivityEvent, ...]
    after_sequence: int = Field(ge=0)
    last_sequence: int = Field(ge=0)
    run_state: ActivityRunState | None
    terminal: bool


class ActivityIntegrityResult(BaseModel):
    """Read-only verification result for one append-only event stream."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    run_id: str
    valid: bool
    event_count: int = Field(ge=0)
    last_sequence: int = Field(ge=0)
    last_event_sha256: str | None
    errors: tuple[str, ...]
