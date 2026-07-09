"""Immutable contracts for transactional autoresearch experiments."""

from __future__ import annotations

import math
import re
from datetime import datetime
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from vulnhunter.orchestration import CommandEvidence, VerifierKind

_ACTOR_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.-]{1,63}$")
_METRIC_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{1,63}$")
_STRATEGY_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{1,63}$")


class ResourceAccess(StrEnum):
    """Access classes for experiment resources."""

    EDITABLE = "editable"
    READ_ONLY = "read_only"
    INACCESSIBLE = "inaccessible"


class ObjectiveDirection(StrEnum):
    """Whether a larger or smaller metric is preferable."""

    MAXIMIZE = "maximize"
    MINIMIZE = "minimize"


class ExperimentState(StrEnum):
    """Lifecycle states for one isolated experiment."""

    DRAFT = "draft"
    PREPARED = "prepared"
    BASELINE_RECORDED = "baseline_recorded"
    CANDIDATE_READY = "candidate_ready"
    EVALUATED = "evaluated"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"
    PROMOTED = "promoted"
    ESCALATED = "escalated"
    ABORTED = "aborted"


class DecisionOutcome(StrEnum):
    """Deterministic keep-or-revert outcome."""

    ACCEPT = "accept"
    REJECT = "reject"
    INCONCLUSIVE = "inconclusive"


class PathRule(BaseModel):
    """One repository-relative resource access rule."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    pattern: str = Field(min_length=1, max_length=240)
    access: ResourceAccess
    rationale: str = Field(min_length=10, max_length=500)

    @field_validator("pattern")
    @classmethod
    def validate_pattern(cls, value: str) -> str:
        normalized = value.strip().replace("\\", "/")
        path = PurePosixPath(normalized)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("Path rules must be repository-relative and traversal-free.")
        return normalized


class EvaluatorPolicy(BaseModel):
    """Trusted resource boundaries and evaluator invariants."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: int = Field(default=1, ge=1)
    name: str = Field(min_length=3, max_length=120)
    rules: tuple[PathRule, ...] = Field(min_length=1)
    fixed_verifiers: tuple[VerifierKind, ...] = Field(min_length=1)
    safety_invariants: tuple[str, ...] = Field(min_length=1, max_length=50)
    protected_labels: tuple[str, ...] = Field(default=(), max_length=50)

    @field_validator("fixed_verifiers")
    @classmethod
    def unique_verifiers(cls, value: tuple[VerifierKind, ...]):
        if len(value) != len(set(value)):
            raise ValueError("Fixed verifier kinds must be unique.")
        return value

    @field_validator("safety_invariants", "protected_labels", mode="before")
    @classmethod
    def non_blank_items(cls, value):
        items = tuple(str(item).strip() for item in value)
        if any(not item for item in items):
            raise ValueError("Policy list entries must not be blank.")
        return items


class ObjectiveSpec(BaseModel):
    """Primary metric and minimum meaningful improvement."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    metric: str
    direction: ObjectiveDirection
    minimum_delta: float = Field(default=0.0, ge=0)

    @field_validator("metric")
    @classmethod
    def validate_metric(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not _METRIC_PATTERN.fullmatch(normalized):
            raise ValueError("Metric names must be stable lowercase identifiers.")
        return normalized

    @field_validator("minimum_delta")
    @classmethod
    def finite_delta(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("Metric deltas must be finite.")
        return value


class RegressionGate(BaseModel):
    """Maximum tolerated degradation for a non-objective metric."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    metric: str
    direction: ObjectiveDirection
    maximum_degradation: float = Field(default=0.0, ge=0)

    @field_validator("metric")
    @classmethod
    def validate_metric(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not _METRIC_PATTERN.fullmatch(normalized):
            raise ValueError("Metric names must be stable lowercase identifiers.")
        return normalized

    @field_validator("maximum_degradation")
    @classmethod
    def finite_degradation(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("Regression tolerances must be finite.")
        return value


class ExperimentLimits(BaseModel):
    """Hard resource and lifecycle ceilings for one experiment."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    maximum_changed_files: int = Field(default=20, ge=1, le=500)
    maximum_diff_bytes: int = Field(default=500_000, ge=1_024, le=25_000_000)
    maximum_elapsed_seconds: int = Field(default=7_200, ge=60, le=172_800)
    per_check_timeout_seconds: int = Field(default=300, ge=5, le=3_600)
    maximum_tokens: int | None = Field(default=None, ge=1, le=100_000_000)
    maximum_cost_usd: float | None = Field(default=None, ge=0, le=1_000_000)


class ExperimentSpec(BaseModel):
    """One bounded hypothesis evaluated against immutable gates."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    title: str = Field(min_length=3, max_length=120)
    hypothesis: str = Field(min_length=20, max_length=2_000)
    strategy_family: str = Field(min_length=2, max_length=64)
    editable_paths: tuple[str, ...] = Field(min_length=1, max_length=100)
    objective: ObjectiveSpec
    regression_gates: tuple[RegressionGate, ...] = Field(default=(), max_length=50)
    required_safety_checks: tuple[str, ...] = Field(min_length=1, max_length=50)
    verifiers: tuple[VerifierKind, ...] = Field(min_length=1)
    limits: ExperimentLimits = ExperimentLimits()

    @field_validator("strategy_family")
    @classmethod
    def validate_strategy_family(cls, value: str) -> str:
        normalized = value.strip().lower().replace(" ", "_")
        if not _STRATEGY_PATTERN.fullmatch(normalized):
            raise ValueError("Strategy family must be a stable lowercase identifier.")
        return normalized

    @field_validator("editable_paths", mode="before")
    @classmethod
    def validate_paths(cls, value):
        patterns = tuple(str(item).strip().replace("\\", "/") for item in value)
        for pattern in patterns:
            path = PurePosixPath(pattern)
            if not pattern or path.is_absolute() or ".." in path.parts:
                raise ValueError(
                    "Editable patterns must be repository-relative and traversal-free."
                )
        return patterns

    @field_validator("required_safety_checks", mode="before")
    @classmethod
    def validate_checks(cls, value):
        checks = tuple(str(item).strip().lower() for item in value)
        if any(not _METRIC_PATTERN.fullmatch(item) for item in checks):
            raise ValueError("Safety-check names must be stable lowercase identifiers.")
        if len(checks) != len(set(checks)):
            raise ValueError("Safety-check names must be unique.")
        return checks

    @field_validator("verifiers")
    @classmethod
    def unique_verifiers(cls, value: tuple[VerifierKind, ...]):
        if len(value) != len(set(value)):
            raise ValueError("Verifier kinds must be unique.")
        return value

    @model_validator(mode="after")
    def no_duplicate_metric_gates(self):
        gate_names = [gate.metric for gate in self.regression_gates]
        if len(gate_names) != len(set(gate_names)):
            raise ValueError("Regression-gate metric names must be unique.")
        if self.objective.metric in gate_names:
            raise ValueError("The objective metric must not also be a regression gate.")
        return self


class MetricReport(BaseModel):
    """Trusted evaluator output recorded without executable content."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: int = Field(default=1, ge=1)
    metrics: dict[str, float]
    safety_checks: dict[str, bool] = Field(default_factory=dict)
    notes: tuple[str, ...] = ()

    @field_validator("metrics")
    @classmethod
    def validate_metrics(cls, value: dict[str, float]) -> dict[str, float]:
        normalized: dict[str, float] = {}
        for name, number in value.items():
            metric = str(name).strip().lower()
            numeric = float(number)
            if not _METRIC_PATTERN.fullmatch(metric):
                raise ValueError(f"Invalid metric name: {name}")
            if not math.isfinite(numeric):
                raise ValueError(f"Metric {metric} must be finite.")
            normalized[metric] = numeric
        if not normalized:
            raise ValueError("At least one metric is required.")
        return normalized

    @field_validator("safety_checks")
    @classmethod
    def validate_safety(cls, value: dict[str, bool]) -> dict[str, bool]:
        normalized: dict[str, bool] = {}
        for name, passed in value.items():
            check = str(name).strip().lower()
            if not _METRIC_PATTERN.fullmatch(check):
                raise ValueError(f"Invalid safety-check name: {name}")
            normalized[check] = bool(passed)
        return normalized


class RecordedMetricReport(BaseModel):
    """Metric report plus provenance of the trusted evaluator actor and file."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    report: MetricReport
    evaluator_id: str
    recorded_at: datetime
    source_path: str
    source_sha256: str = Field(min_length=64, max_length=64)

    @field_validator("evaluator_id")
    @classmethod
    def validate_evaluator(cls, value: str) -> str:
        return normalize_actor_id(value)


class ProtectedFileRecord(BaseModel):
    """Hash of one read-only evaluator or policy resource."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str
    access: ResourceAccess
    sha256: str = Field(min_length=64, max_length=64)


class ProtectedSnapshot(BaseModel):
    """Trusted baseline inventory stored outside the candidate worktree."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    created_at: datetime
    repository_commit: str = Field(min_length=7, max_length=64)
    policy_sha256: str = Field(min_length=64, max_length=64)
    files: tuple[ProtectedFileRecord, ...]
    snapshot_sha256: str = Field(min_length=64, max_length=64)


class ExperimentManifest(BaseModel):
    """Mutable lifecycle summary for one isolated experiment."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(default=1, ge=1)
    experiment_id: str = Field(min_length=8, max_length=96)
    spec: ExperimentSpec
    creator_id: str
    builder_id: str
    repository_root: str
    store_root: str
    worktree_path: str | None = None
    branch_name: str | None = None
    baseline_commit: str = Field(min_length=7, max_length=64)
    baseline_tree: str = Field(min_length=40, max_length=64)
    policy_sha256: str = Field(min_length=64, max_length=64)
    protected_snapshot_sha256: str = Field(min_length=64, max_length=64)
    created_at: datetime
    updated_at: datetime
    state: ExperimentState = ExperimentState.DRAFT
    candidate_commit: str | None = None
    candidate_tree: str | None = None
    patch_sha256: str | None = None
    latest_evaluator_id: str | None = None
    latest_decider_id: str | None = None
    human_promoter_id: str | None = None
    decision: DecisionOutcome | None = None
    tokens_used: int = Field(default=0, ge=0)
    cost_usd: float = Field(default=0, ge=0)
    meta_policy_generation: int = Field(default=0, ge=0)

    @field_validator(
        "creator_id",
        "builder_id",
        "latest_evaluator_id",
        "latest_decider_id",
        "human_promoter_id",
    )
    @classmethod
    def validate_actors(cls, value: str | None):
        if value is None:
            return None
        return normalize_actor_id(value)


class ExperimentEvaluation(BaseModel):
    """Complete candidate proof bundle used by the deterministic gate."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    experiment_id: str
    evaluator_id: str
    created_at: datetime
    baseline_commit: str
    candidate_commit: str
    changed_files: tuple[str, ...]
    diff_bytes: int = Field(ge=0)
    diff_sha256: str = Field(min_length=64, max_length=64)
    protected_snapshot_valid: bool
    protected_violations: tuple[str, ...] = ()
    boundary_violations: tuple[str, ...] = ()
    checks: tuple[CommandEvidence, ...]
    baseline_report_sha256: str = Field(min_length=64, max_length=64)
    candidate_report_sha256: str = Field(min_length=64, max_length=64)
    objective_delta: float | None = None
    objective_passed: bool
    regression_failures: tuple[str, ...] = ()
    safety_failures: tuple[str, ...] = ()
    passed: bool
    failure_signature: str | None = None

    @field_validator("evaluator_id")
    @classmethod
    def validate_evaluator(cls, value: str) -> str:
        return normalize_actor_id(value)


class ExperimentDecision(BaseModel):
    """Deterministic keep, reject, or inconclusive decision."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    experiment_id: str
    decider_id: str
    created_at: datetime
    outcome: DecisionOutcome
    reasons: tuple[str, ...]
    baseline_value: float
    candidate_value: float
    objective_delta: float
    diff_sha256: str = Field(min_length=64, max_length=64)
    evaluation_sha256: str = Field(min_length=64, max_length=64)

    @field_validator("decider_id")
    @classmethod
    def validate_decider(cls, value: str) -> str:
        return normalize_actor_id(value)


class SearchPolicy(BaseModel):
    """Human-approved outer-loop guidance that cannot alter evaluator gates."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: int = Field(default=1, ge=1)
    generation: int = Field(default=0, ge=0)
    strategy_weights: dict[str, float]
    maximum_same_strategy_streak: int = Field(default=2, ge=1, le=20)
    novelty_floor: float = Field(default=0.35, ge=0, le=1)
    stagnation_window: int = Field(default=5, ge=2, le=100)
    approved_by: str | None = None
    approved_at: datetime | None = None

    @field_validator("strategy_weights")
    @classmethod
    def validate_weights(cls, value: dict[str, float]) -> dict[str, float]:
        normalized: dict[str, float] = {}
        for name, weight in value.items():
            strategy = str(name).strip().lower().replace(" ", "_")
            numeric = float(weight)
            if not _STRATEGY_PATTERN.fullmatch(strategy):
                raise ValueError(f"Invalid strategy family: {name}")
            if not math.isfinite(numeric) or numeric < 0:
                raise ValueError("Strategy weights must be finite and non-negative.")
            normalized[strategy] = numeric
        if not normalized or sum(normalized.values()) <= 0:
            raise ValueError("At least one positive strategy weight is required.")
        return normalized

    @field_validator("approved_by")
    @classmethod
    def validate_approver(cls, value: str | None):
        if value is None:
            return None
        return normalize_actor_id(value)


class MetaAnalysis(BaseModel):
    """Non-executable outer-loop analysis of search stagnation and diversity."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    created_at: datetime
    source_experiment_ids: tuple[str, ...]
    repeated_hypotheses: tuple[str, ...]
    overused_strategies: tuple[str, ...]
    underused_strategies: tuple[str, ...]
    rejection_rate: float = Field(ge=0, le=1)
    stagnation_detected: bool
    recommendations: tuple[str, ...]
    proposed_policy: SearchPolicy
    requires_human_approval: Literal[True] = True


class ResearchEvent(BaseModel):
    """Hash-chained experiment audit event."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    sequence: int = Field(ge=1)
    experiment_id: str
    event_type: str
    actor_id: str
    created_at: datetime
    payload: dict[str, object]
    previous_hash: str = Field(min_length=64, max_length=64)
    event_hash: str = Field(min_length=64, max_length=64)

    @field_validator("actor_id")
    @classmethod
    def validate_actor(cls, value: str) -> str:
        return normalize_actor_id(value)


def normalize_actor_id(value: str) -> str:
    """Normalize a pseudonymous actor identifier."""
    normalized = value.strip().lower()
    if not _ACTOR_PATTERN.fullmatch(normalized):
        raise ValueError(
            "Actor IDs must be 2-64 lowercase letters, numbers, dots, underscores, or hyphens."
        )
    return normalized
