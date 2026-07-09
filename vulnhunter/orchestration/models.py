"""Immutable contracts for bounded engineering orchestration loops."""

from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_ACTOR_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.-]{1,63}$")


class VerifierKind(StrEnum):
    """Deterministic verifier commands supported by the harness."""

    RUFF_CHECK = "ruff_check"
    COMPILEALL = "compileall"
    PYTEST = "pytest"
    RUFF_FORMAT_CHECK = "ruff_format_check"
    GIT_DIFF_CHECK = "git_diff_check"
    MYPY = "mypy"
    BUILD = "build"
    BENCHMARK_FIXTURES = "benchmark_fixtures"


class LoopState(StrEnum):
    """Allowed lifecycle states for one orchestration loop."""

    ACTIVE = "active"
    AWAITING_SECURITY = "awaiting_security"
    AWAITING_REVIEW = "awaiting_review"
    AWAITING_HUMAN = "awaiting_human"
    AWAITING_DOCUMENTATION = "awaiting_documentation"
    COMPLETED = "completed"
    REJECTED = "rejected"
    ESCALATED = "escalated"
    ROLLED_BACK = "rolled_back"


class ReviewDecision(StrEnum):
    """Independent reviewer decision."""

    APPROVE = "approve"
    CHANGES_REQUIRED = "changes_required"


class HumanDecision(StrEnum):
    """Human approval decision."""

    APPROVE = "approve"
    REJECT = "reject"


class StopControls(BaseModel):
    """Hard stop and escalation controls for one loop."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    maximum_iterations: int = Field(default=5, ge=1, le=50)
    maximum_elapsed_seconds: int = Field(default=3_600, ge=60, le=86_400)
    per_check_timeout_seconds: int = Field(default=180, ge=5, le=3_600)
    maximum_consecutive_failures: int = Field(default=3, ge=1, le=20)
    maximum_repeated_error_count: int = Field(default=2, ge=1, le=20)
    maximum_no_progress_count: int = Field(default=2, ge=1, le=20)
    maximum_changed_files: int = Field(default=40, ge=1, le=2_000)
    maximum_diff_bytes: int = Field(default=2_000_000, ge=1_024, le=50_000_000)


class ResourceBudget(BaseModel):
    """Recorded and enforced resource ceilings."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    maximum_tokens: int | None = Field(default=None, ge=1, le=100_000_000)
    maximum_cost_usd: float | None = Field(default=None, ge=0, le=1_000_000)


class LoopSpec(BaseModel):
    """The six mandatory definitions for a bounded loop."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    title: str = Field(min_length=3, max_length=120)
    objective: str = Field(min_length=20, max_length=2_000)
    required_context: tuple[str, ...] = Field(min_length=1, max_length=50)
    allowed_actions: tuple[
        Literal[
            "edit_allowed_files",
            "run_deterministic_verifiers",
            "record_redacted_evidence",
            "update_documentation",
        ],
        ...,
    ] = Field(min_length=1)
    allowed_paths: tuple[str, ...] = Field(min_length=1, max_length=100)
    verifiers: tuple[VerifierKind, ...] = Field(min_length=1)
    required_evidence: tuple[str, ...] = Field(min_length=1, max_length=50)
    recovery_instructions: tuple[str, ...] = Field(min_length=1, max_length=30)
    documentation_paths: tuple[str, ...] = Field(min_length=1, max_length=30)
    stop_controls: StopControls = StopControls()
    resource_budget: ResourceBudget = ResourceBudget()

    @field_validator(
        "required_context",
        "required_evidence",
        "recovery_instructions",
        mode="before",
    )
    @classmethod
    def validate_non_blank_items(cls, value):
        items = tuple(str(item).strip() for item in value)
        if any(not item for item in items):
            raise ValueError("List items must not be blank.")
        return items

    @field_validator("allowed_paths", "documentation_paths", mode="before")
    @classmethod
    def validate_relative_patterns(cls, value):
        patterns = tuple(str(item).strip().replace("\\", "/") for item in value)
        for pattern in patterns:
            if not pattern:
                raise ValueError("Path patterns must not be blank.")
            path = PurePosixPath(pattern)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError("Path patterns must be repository-relative and traversal-free.")
        return patterns

    @field_validator("verifiers")
    @classmethod
    def verifier_order_is_unique(cls, value: tuple[VerifierKind, ...]):
        if len(set(value)) != len(value):
            raise ValueError("Verifier kinds must be unique.")
        return value

    @model_validator(mode="after")
    def enforce_action_contract(self):
        required_actions = {
            "edit_allowed_files",
            "run_deterministic_verifiers",
            "record_redacted_evidence",
            "update_documentation",
        }
        if set(self.allowed_actions) != required_actions:
            raise ValueError(
                "allowed_actions must explicitly contain all four bounded loop actions."
            )
        return self


class LoopManifest(BaseModel):
    """Mutable summary with immutable embedded specification."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(default=1, ge=1)
    loop_id: str = Field(min_length=8, max_length=80)
    spec: LoopSpec
    creator_id: str
    builder_id: str
    repository_root: str
    baseline_commit: str = Field(min_length=7, max_length=64)
    baseline_tree: str = Field(min_length=40, max_length=64)
    created_at: datetime
    updated_at: datetime
    state: LoopState = LoopState.ACTIVE
    iteration_count: int = Field(default=0, ge=0)
    consecutive_failures: int = Field(default=0, ge=0)
    repeated_error_count: int = Field(default=0, ge=0)
    no_progress_count: int = Field(default=0, ge=0)
    tokens_used: int = Field(default=0, ge=0)
    cost_usd: float = Field(default=0, ge=0)
    latest_change_fingerprint: str | None = None
    latest_failure_signature: str | None = None
    latest_runner_id: str | None = None
    latest_security_verifier_id: str | None = None
    latest_reviewer_id: str | None = None
    human_approver_id: str | None = None

    @field_validator(
        "creator_id",
        "builder_id",
        "latest_runner_id",
        "latest_security_verifier_id",
        "latest_reviewer_id",
        "human_approver_id",
    )
    @classmethod
    def validate_actor_fields(cls, value: str | None):
        if value is None:
            return None
        return normalize_actor_id(value)


class CommandEvidence(BaseModel):
    """Redacted evidence for one deterministic verifier command."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    verifier: VerifierKind
    argv: tuple[str, ...]
    exit_code: int
    passed: bool
    duration_seconds: float = Field(ge=0)
    output_sha256: str = Field(min_length=64, max_length=64)
    output_excerpt: str = Field(max_length=16_000)
    timed_out: bool = False


class EvaluationEvidence(BaseModel):
    """Proof bundle for one loop iteration."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    iteration: int = Field(ge=1)
    runner_id: str
    created_at: datetime
    changed_files: tuple[str, ...]
    changed_files_count: int = Field(ge=0)
    diff_bytes: int = Field(ge=0)
    diff_sha256: str = Field(min_length=64, max_length=64)
    change_fingerprint: str = Field(min_length=64, max_length=64)
    out_of_scope_paths: tuple[str, ...] = ()
    checks: tuple[CommandEvidence, ...]
    passed: bool
    failure_signature: str | None = None
    tokens_used: int = Field(default=0, ge=0)
    cost_usd: float = Field(default=0, ge=0)

    @field_validator("runner_id")
    @classmethod
    def validate_runner(cls, value: str):
        return normalize_actor_id(value)


class SecurityEvidence(BaseModel):
    """Independent deterministic security-policy evidence."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    iteration: int = Field(ge=1)
    verifier_id: str
    created_at: datetime
    passed: bool
    findings: tuple[str, ...]
    diff_sha256: str = Field(min_length=64, max_length=64)

    @field_validator("verifier_id")
    @classmethod
    def validate_verifier(cls, value: str):
        return normalize_actor_id(value)


class ReviewRecord(BaseModel):
    """Independent review of implementation and evidence."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    iteration: int = Field(ge=1)
    reviewer_id: str
    created_at: datetime
    decision: ReviewDecision
    summary: str = Field(min_length=10, max_length=4_000)
    limitations: tuple[str, ...] = ()

    @field_validator("reviewer_id")
    @classmethod
    def validate_reviewer(cls, value: str):
        return normalize_actor_id(value)


class HumanApprovalRecord(BaseModel):
    """Human decision after independent review."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    iteration: int = Field(ge=1)
    human_id: str
    created_at: datetime
    decision: HumanDecision
    note: str = Field(min_length=5, max_length=4_000)

    @field_validator("human_id")
    @classmethod
    def validate_human(cls, value: str):
        return normalize_actor_id(value)


class LearningRecord(BaseModel):
    """Final documentation and learning evidence."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    iteration: int = Field(ge=1)
    actor_id: str
    created_at: datetime
    summary: str = Field(min_length=20, max_length=8_000)
    limitations: tuple[str, ...] = Field(min_length=1, max_length=30)
    documentation_paths: tuple[str, ...] = Field(min_length=1, max_length=30)

    @field_validator("actor_id")
    @classmethod
    def validate_actor(cls, value: str):
        return normalize_actor_id(value)


class AuditEvent(BaseModel):
    """One hash-chained append-only loop event."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    sequence: int = Field(ge=1)
    loop_id: str
    event_type: str = Field(min_length=3, max_length=80)
    actor_id: str
    created_at: datetime
    payload: dict[str, object]
    previous_hash: str
    event_hash: str = Field(min_length=64, max_length=64)

    @field_validator("actor_id")
    @classmethod
    def validate_actor(cls, value: str):
        return normalize_actor_id(value)


def normalize_actor_id(value: str) -> str:
    """Return a stable pseudonymous role identifier."""
    normalized = value.strip().lower()
    if not _ACTOR_PATTERN.fullmatch(normalized):
        raise ValueError(
            "Actor IDs must be 2-64 lowercase letters, digits, dots, underscores, "
            "or hyphens, and must start with a letter or digit."
        )
    return normalized


NonNegativeInt = Annotated[int, Field(ge=0)]
