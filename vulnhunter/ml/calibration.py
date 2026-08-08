"""Development-calibration, OOD and abstention contracts for review-priority ML."""

from __future__ import annotations

import math
from collections.abc import Sequence
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from vulnhunter.ml.dataset import dataset_sha256
from vulnhunter.ml.models import Prediction, TrainingExample

_ZERO_EPSILON = 1e-12


class CalibrationBoundaryError(RuntimeError):
    """A calibration, OOD or abstention invariant failed closed."""


class ReliabilityBin(BaseModel):
    """One deterministic probability-calibration bin."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    lower: float = Field(ge=0, le=1)
    upper: float = Field(gt=0, le=1)
    samples: int = Field(ge=1)
    mean_probability: float = Field(ge=0, le=1)
    observed_positive_rate: float = Field(ge=0, le=1)

    @model_validator(mode="after")
    def ordered_bounds(self) -> Self:
        if self.lower >= self.upper:
            raise ValueError("reliability bin bounds must be ordered")
        return self


class CalibrationMetrics(BaseModel):
    """Bounded calibration metrics for one labelled development partition."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    samples: int = Field(ge=1)
    brier_score: float = Field(ge=0, le=1)
    log_loss: float = Field(ge=0)
    expected_calibration_error: float = Field(ge=0, le=1)
    maximum_calibration_error: float = Field(ge=0, le=1)
    reliability: tuple[ReliabilityBin, ...]


class PlattCalibrationArtifact(BaseModel):
    """Immutable calibrator bound to one exact base model and calibration dataset."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[1] = 1
    method: Literal["platt"] = "platt"
    base_model_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    calibration_dataset_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    calibration_group_ids: tuple[str, ...] = Field(min_length=1)
    slope: float
    intercept: float
    known_categories: tuple[str, ...]
    abstention_margin: float = Field(ge=0, lt=0.5)
    metrics_before: CalibrationMetrics
    metrics_after: CalibrationMetrics
    external_holdout_used: Literal[False] = False

    @field_validator("calibration_group_ids", "known_categories")
    @classmethod
    def unique_sorted_values(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        cleaned = tuple(sorted(set(item.strip() for item in value if item.strip())))
        if value and not cleaned:
            raise ValueError("calibration metadata cannot be empty")
        return cleaned


class CalibratedAdvisoryPrediction(BaseModel):
    """Task-scoped advisory decision with explicit abstention and OOD reason codes."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    task: Literal["review_priority"] = "review_priority"
    decision: Literal["confirmed", "false_positive", "abstain"]
    calibrated_positive_probability: float = Field(ge=0, le=1)
    raw_positive_probability: float = Field(ge=0, le=1)
    ood_score: float = Field(ge=0, le=1)
    reason_codes: tuple[str, ...]
    advisory_only: Literal[True] = True

    @model_validator(mode="after")
    def abstention_has_reason(self) -> Self:
        if self.decision == "abstain" and not self.reason_codes:
            raise ValueError("abstention requires at least one explicit reason code")
        return self


def _bounded_probability(value: float) -> float:
    return min(max(float(value), _ZERO_EPSILON), 1.0 - _ZERO_EPSILON)


def _logit(value: float) -> float:
    probability = _bounded_probability(value)
    return math.log(probability / (1.0 - probability))


def _sigmoid(value: float) -> float:
    if value >= 0:
        exponent = math.exp(-value)
        return 1.0 / (1.0 + exponent)
    exponent = math.exp(value)
    return exponent / (1.0 + exponent)


def calibration_metrics(
    examples: Sequence[TrainingExample],
    probabilities: Sequence[float],
    *,
    bins: int = 10,
) -> CalibrationMetrics:
    """Calculate Brier/log-loss/ECE/MCE without treating raw posterior as confidence."""

    if not examples or len(examples) != len(probabilities):
        raise CalibrationBoundaryError("calibration metrics require aligned labelled samples")
    if bins < 2 or bins > 100:
        raise CalibrationBoundaryError("calibration bin count must be between 2 and 100")

    labels = tuple(1.0 if item.label == "confirmed" else 0.0 for item in examples)
    bounded = tuple(_bounded_probability(value) for value in probabilities)
    brier = sum(
        (probability - label) ** 2 for probability, label in zip(bounded, labels, strict=True)
    )
    log_loss = -sum(
        label * math.log(probability) + (1.0 - label) * math.log(1.0 - probability)
        for probability, label in zip(bounded, labels, strict=True)
    )

    reliability: list[ReliabilityBin] = []
    weighted_gap = 0.0
    maximum_gap = 0.0
    for index in range(bins):
        lower = index / bins
        upper = (index + 1) / bins
        members = tuple(
            (probability, label)
            for probability, label in zip(bounded, labels, strict=True)
            if lower <= probability < upper or (index == bins - 1 and probability == 1.0)
        )
        if not members:
            continue
        mean_probability = sum(item[0] for item in members) / len(members)
        observed_rate = sum(item[1] for item in members) / len(members)
        gap = abs(mean_probability - observed_rate)
        weighted_gap += gap * len(members)
        maximum_gap = max(maximum_gap, gap)
        reliability.append(
            ReliabilityBin(
                lower=lower,
                upper=upper,
                samples=len(members),
                mean_probability=mean_probability,
                observed_positive_rate=observed_rate,
            )
        )

    count = len(examples)
    return CalibrationMetrics(
        samples=count,
        brier_score=brier / count,
        log_loss=log_loss / count,
        expected_calibration_error=weighted_gap / count,
        maximum_calibration_error=maximum_gap,
        reliability=tuple(reliability),
    )


def fit_platt_calibrator(
    examples: Sequence[TrainingExample],
    predictions: Sequence[Prediction],
    *,
    base_model_sha256: str,
    calibration_group_ids: Sequence[str],
    known_categories: Sequence[str],
    abstention_margin: float = 0.1,
    learning_rate: float = 0.05,
    iterations: int = 600,
) -> PlattCalibrationArtifact:
    """Fit deterministic Platt scaling using development-calibration labels only."""

    if len(examples) < 4 or len(examples) != len(predictions):
        raise CalibrationBoundaryError("Platt calibration requires at least four aligned samples")
    if {item.label for item in examples} != {"confirmed", "false_positive"}:
        raise CalibrationBoundaryError("calibration partition must contain both human labels")
    if not calibration_group_ids:
        raise CalibrationBoundaryError("calibration group provenance is required")
    if learning_rate <= 0 or iterations < 1 or iterations > 100_000:
        raise CalibrationBoundaryError("calibration optimization settings are out of bounds")

    raw = tuple(item.probabilities["confirmed"] for item in predictions)
    features = tuple(_logit(value) for value in raw)
    labels = tuple(1.0 if item.label == "confirmed" else 0.0 for item in examples)
    slope = 1.0
    intercept = 0.0
    count = len(examples)
    for _ in range(iterations):
        outputs = tuple(_sigmoid(slope * value + intercept) for value in features)
        slope_gradient = (
            sum(
                (output - label) * value
                for output, label, value in zip(outputs, labels, features, strict=True)
            )
            / count
        )
        intercept_gradient = (
            sum(output - label for output, label in zip(outputs, labels, strict=True)) / count
        )
        slope -= learning_rate * slope_gradient
        intercept -= learning_rate * intercept_gradient

    calibrated = tuple(_sigmoid(slope * value + intercept) for value in features)
    canonical_examples = tuple(
        sorted(examples, key=lambda item: (item.scan_id, item.observation_id))
    )
    return PlattCalibrationArtifact(
        base_model_sha256=base_model_sha256,
        calibration_dataset_sha256=dataset_sha256(canonical_examples),
        calibration_group_ids=tuple(calibration_group_ids),
        slope=slope,
        intercept=intercept,
        known_categories=tuple(known_categories),
        abstention_margin=abstention_margin,
        metrics_before=calibration_metrics(examples, raw),
        metrics_after=calibration_metrics(examples, calibrated),
    )


def apply_platt_calibrator(
    raw_positive_probability: float,
    artifact: PlattCalibrationArtifact,
) -> float:
    """Apply one exact calibrator to a raw positive posterior."""

    return _sigmoid(artifact.slope * _logit(raw_positive_probability) + artifact.intercept)


def calibrated_advisory_prediction(
    example: TrainingExample,
    prediction: Prediction,
    artifact: PlattCalibrationArtifact,
    *,
    base_model_sha256: str,
) -> CalibratedAdvisoryPrediction:
    """Return calibrated advisory output or abstain on deterministic OOD/low margin."""

    if base_model_sha256 != artifact.base_model_sha256:
        raise CalibrationBoundaryError("calibrator is bound to a different base model")
    raw = prediction.probabilities["confirmed"]
    calibrated = apply_platt_calibrator(raw, artifact)
    reasons: list[str] = []
    ood_score = 0.0
    if artifact.known_categories and example.category not in artifact.known_categories:
        reasons.append("OOD_UNSEEN_CATEGORY")
        ood_score = 1.0
    if abs(calibrated - 0.5) < artifact.abstention_margin:
        reasons.append("LOW_CALIBRATED_MARGIN")

    if reasons:
        decision: Literal["confirmed", "false_positive", "abstain"] = "abstain"
    else:
        decision = "confirmed" if calibrated >= 0.5 else "false_positive"
    return CalibratedAdvisoryPrediction(
        decision=decision,
        calibrated_positive_probability=calibrated,
        raw_positive_probability=raw,
        ood_score=ood_score,
        reason_codes=tuple(reasons),
    )


__all__ = [
    "CalibratedAdvisoryPrediction",
    "CalibrationBoundaryError",
    "CalibrationMetrics",
    "PlattCalibrationArtifact",
    "ReliabilityBin",
    "apply_platt_calibrator",
    "calibrated_advisory_prediction",
    "calibration_metrics",
    "fit_platt_calibrator",
]
