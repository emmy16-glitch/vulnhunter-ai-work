"""Reproducible holdout diagnostics without changing labels or retraining."""

from __future__ import annotations

from collections import defaultdict

from pydantic import BaseModel, ConfigDict, Field

from vulnhunter.exceptions import ModelArtifactError
from vulnhunter.ml.dataset import dataset_sha256
from vulnhunter.ml.estimators import evaluate_predictions
from vulnhunter.ml.models import (
    EvaluationMetrics,
    ModelArtifact,
    Prediction,
    TrainingExample,
    TrainingLabel,
)
from vulnhunter.ml.quality import assess_dataset_quality
from vulnhunter.ml.training import predict


class DiagnosticCase(BaseModel):
    """One holdout error or correct decision with redacted context."""

    model_config = ConfigDict(frozen=True)

    observation_id: int = Field(ge=1)
    scan_id: int = Field(ge=1)
    category: str
    url: str
    actual_label: TrainingLabel
    predicted_label: TrainingLabel
    confirmed_probability: float = Field(ge=0, le=1)


class DiagnosticSlice(BaseModel):
    """Metrics for one category or scan group."""

    model_config = ConfigDict(frozen=True)

    key: str
    metrics: EvaluationMetrics


class DiagnosticReport(BaseModel):
    """Complete reproducible report for one untouched holdout partition."""

    model_config = ConfigDict(frozen=True)

    metrics: EvaluationMetrics
    false_negatives: tuple[DiagnosticCase, ...] = ()
    false_positives: tuple[DiagnosticCase, ...] = ()
    by_category: tuple[DiagnosticSlice, ...] = ()
    by_scan: tuple[DiagnosticSlice, ...] = ()


def _case(example: TrainingExample, prediction: Prediction) -> DiagnosticCase:
    return DiagnosticCase(
        observation_id=example.observation_id,
        scan_id=example.scan_id,
        category=example.category,
        url=example.url,
        actual_label=example.label,
        predicted_label=prediction.label,
        confirmed_probability=prediction.probabilities["confirmed"],
    )


def _slice_metrics(
    pairs: list[tuple[TrainingExample, Prediction]],
    *,
    key: str,
) -> DiagnosticSlice:
    examples = tuple(example for example, _ in pairs)
    predictions = tuple(prediction for _, prediction in pairs)
    return DiagnosticSlice(
        key=key,
        metrics=evaluate_predictions(examples, predictions),
    )


def diagnose_holdout(
    examples: tuple[TrainingExample, ...],
    artifact: ModelArtifact,
) -> DiagnosticReport:
    """Recompute predictions only for the artifact's locked holdout scans."""
    prepared = assess_dataset_quality(
        examples,
        minimum_samples=4,
        minimum_per_class=2,
        minimum_scans=4,
        minimum_scans_per_class=2,
        test_fraction=0.2,
        random_seed=artifact.random_seed,
    )
    if prepared.report.conflicting_fingerprints:
        raise ModelArtifactError("Current reviewed data contains conflicting labels.")
    canonical = prepared.examples
    if dataset_sha256(canonical) != artifact.dataset_sha256:
        raise ModelArtifactError(
            "The reviewed dataset no longer matches the model artifact provenance."
        )

    holdout_ids = set(artifact.holdout_scan_ids)
    holdout = tuple(example for example in canonical if example.scan_id in holdout_ids)
    if len(holdout) != artifact.holdout_samples:
        raise ModelArtifactError("The holdout sample count no longer matches the model artifact.")

    predictions = tuple(predict(example, artifact) for example in holdout)
    metrics = evaluate_predictions(holdout, predictions)
    if metrics != artifact.evaluation:
        raise ModelArtifactError("Recomputed holdout metrics do not match the model artifact.")

    false_negatives: list[DiagnosticCase] = []
    false_positives: list[DiagnosticCase] = []
    category_pairs: dict[str, list[tuple[TrainingExample, Prediction]]] = defaultdict(list)
    scan_pairs: dict[int, list[tuple[TrainingExample, Prediction]]] = defaultdict(list)

    for example, prediction in zip(holdout, predictions, strict=True):
        category_pairs[example.category].append((example, prediction))
        scan_pairs[example.scan_id].append((example, prediction))
        if example.label == "confirmed" and prediction.label == "false_positive":
            false_negatives.append(_case(example, prediction))
        elif example.label == "false_positive" and prediction.label == "confirmed":
            false_positives.append(_case(example, prediction))

    return DiagnosticReport(
        metrics=metrics,
        false_negatives=tuple(sorted(false_negatives, key=lambda item: item.observation_id)),
        false_positives=tuple(sorted(false_positives, key=lambda item: item.observation_id)),
        by_category=tuple(
            _slice_metrics(category_pairs[key], key=key) for key in sorted(category_pairs)
        ),
        by_scan=tuple(_slice_metrics(scan_pairs[key], key=str(key)) for key in sorted(scan_pairs)),
    )
