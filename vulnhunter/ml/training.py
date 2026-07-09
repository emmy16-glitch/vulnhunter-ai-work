"""Deterministic training, evaluation, persistence, and prediction."""

from __future__ import annotations

import json
import math
import os
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from vulnhunter import __version__
from vulnhunter.exceptions import InsufficientTrainingDataError, ModelArtifactError
from vulnhunter.ml.dataset import dataset_sha256
from vulnhunter.ml.features import build_feature_schema, vectorize, vectorize_many
from vulnhunter.ml.models import (
    EvaluationMetrics,
    ModelArtifact,
    ObservationInput,
    Prediction,
    TrainingExample,
    TrainingLabel,
)
from vulnhunter.ml.quality import assess_dataset_quality
from vulnhunter.ml.splitting import split_by_scan_groups

_MAXIMUM_MODEL_BYTES = 10 * 1024 * 1024


def _fit_probabilities(
    examples: tuple[TrainingExample, ...],
    vectors: tuple[tuple[float, ...], ...],
    *,
    alpha: float,
) -> tuple[
    dict[TrainingLabel, float],
    dict[TrainingLabel, tuple[float, ...]],
    dict[TrainingLabel, int],
]:
    if alpha <= 0:
        raise ValueError("alpha must be greater than zero.")

    feature_count = len(vectors[0])
    class_counts: Counter[TrainingLabel] = Counter(example.label for example in examples)
    total_samples = len(examples)
    class_log_priors: dict[TrainingLabel, float] = {}
    feature_log_probabilities: dict[TrainingLabel, tuple[float, ...]] = {}

    for label in ("confirmed", "false_positive"):
        class_log_priors[label] = math.log(class_counts[label] / total_samples)
        totals = [0.0] * feature_count

        for example, vector in zip(examples, vectors, strict=True):
            if example.label != label:
                continue
            totals = [left + right for left, right in zip(totals, vector, strict=True)]

        denominator = sum(totals) + alpha * feature_count
        feature_log_probabilities[label] = tuple(
            math.log((value + alpha) / denominator) for value in totals
        )

    return class_log_priors, feature_log_probabilities, dict(class_counts)


def _predict_vector(
    vector: tuple[float, ...],
    *,
    class_log_priors: dict[TrainingLabel, float],
    feature_log_probabilities: dict[TrainingLabel, tuple[float, ...]],
) -> Prediction:
    scores: dict[TrainingLabel, float] = {}

    for label in ("confirmed", "false_positive"):
        probabilities = feature_log_probabilities[label]
        if len(probabilities) != len(vector):
            raise ModelArtifactError("The model feature dimensions are inconsistent.")

        scores[label] = class_log_priors[label] + sum(
            value * probability for value, probability in zip(vector, probabilities, strict=True)
        )

    maximum_score = max(scores.values())
    exponentials = {label: math.exp(score - maximum_score) for label, score in scores.items()}
    denominator = sum(exponentials.values())
    probabilities = {label: value / denominator for label, value in exponentials.items()}
    predicted_label = max(
        ("confirmed", "false_positive"),
        key=lambda label: (probabilities[label], label == "confirmed"),
    )

    return Prediction(
        label=predicted_label,
        confidence=probabilities[predicted_label],
        probabilities=probabilities,
    )


def _evaluate(
    examples: tuple[TrainingExample, ...],
    predictions: tuple[Prediction, ...],
) -> EvaluationMetrics:
    true_positive = false_positive = true_negative = false_negative = 0

    for example, prediction in zip(examples, predictions, strict=True):
        if example.label == "confirmed" and prediction.label == "confirmed":
            true_positive += 1
        elif example.label == "false_positive" and prediction.label == "confirmed":
            false_positive += 1
        elif example.label == "false_positive" and prediction.label == "false_positive":
            true_negative += 1
        else:
            false_negative += 1

    total = len(examples)
    accuracy = (true_positive + true_negative) / total
    precision_denominator = true_positive + false_positive
    recall_denominator = true_positive + false_negative
    precision = true_positive / precision_denominator if precision_denominator else 0.0
    recall = true_positive / recall_denominator if recall_denominator else 0.0
    f1_denominator = precision + recall
    f1_score = 2 * precision * recall / f1_denominator if f1_denominator else 0.0

    return EvaluationMetrics(
        test_samples=total,
        true_positive=true_positive,
        false_positive=false_positive,
        true_negative=true_negative,
        false_negative=false_negative,
        accuracy=accuracy,
        precision=precision,
        recall=recall,
        f1_score=f1_score,
    )


def train_baseline(
    examples: tuple[TrainingExample, ...],
    *,
    minimum_samples: int = 20,
    minimum_per_class: int = 5,
    minimum_scans: int = 4,
    minimum_scans_per_class: int = 2,
    test_fraction: float = 0.2,
    random_seed: int = 42,
    alpha: float = 1.0,
    maximum_tokens: int = 128,
) -> ModelArtifact:
    """Train a deduplicated baseline with scan-isolated holdout evaluation."""
    prepared = assess_dataset_quality(
        examples,
        minimum_samples=minimum_samples,
        minimum_per_class=minimum_per_class,
        minimum_scans=minimum_scans,
        minimum_scans_per_class=minimum_scans_per_class,
        test_fraction=test_fraction,
        random_seed=random_seed,
    )

    if not prepared.report.ready:
        raise InsufficientTrainingDataError(
            "Training data failed quality gates: " + " ".join(prepared.report.blocking_reasons)
        )

    canonical_examples = prepared.examples
    train_examples, holdout_examples = split_by_scan_groups(
        canonical_examples,
        test_fraction=test_fraction,
        random_seed=random_seed,
    )
    schema = build_feature_schema(train_examples, maximum_tokens=maximum_tokens)
    train_vectors = vectorize_many(train_examples, schema)

    if not train_vectors or not train_vectors[0]:
        raise ModelArtifactError("Feature engineering produced an empty model input.")

    class_log_priors, feature_log_probabilities, class_counts = _fit_probabilities(
        train_examples,
        train_vectors,
        alpha=alpha,
    )
    holdout_predictions = tuple(
        _predict_vector(
            vectorize(example, schema),
            class_log_priors=class_log_priors,
            feature_log_probabilities=feature_log_probabilities,
        )
        for example in holdout_examples
    )
    evaluation = _evaluate(holdout_examples, holdout_predictions)

    training_scan_ids = tuple(sorted({example.scan_id for example in train_examples}))
    holdout_scan_ids = tuple(sorted({example.scan_id for example in holdout_examples}))

    return ModelArtifact(
        created_at=datetime.now(UTC),
        application_version=__version__,
        random_seed=random_seed,
        alpha=alpha,
        training_samples=len(train_examples),
        holdout_samples=len(holdout_examples),
        class_counts=class_counts,
        dataset_sha256=dataset_sha256(canonical_examples),
        feature_schema=schema,
        class_log_priors=class_log_priors,
        feature_log_probabilities=feature_log_probabilities,
        evaluation=evaluation,
        source_samples=prepared.report.source_samples,
        deduplicated_samples=prepared.report.unique_samples,
        duplicate_samples_removed=prepared.report.duplicate_samples,
        split_strategy="scan_group_stratified",
        training_scan_ids=training_scan_ids,
        holdout_scan_ids=holdout_scan_ids,
    )


def predict(example: ObservationInput, artifact: ModelArtifact) -> Prediction:
    """Predict one observation using a validated model artifact."""
    vector = vectorize(example, artifact.feature_schema)
    expected_features = len(artifact.feature_schema.feature_names)

    if len(vector) != expected_features:
        raise ModelArtifactError("The feature vector does not match the model schema.")

    return _predict_vector(
        vector,
        class_log_priors=artifact.class_log_priors,
        feature_log_probabilities=artifact.feature_log_probabilities,
    )


def save_model(artifact: ModelArtifact, output_path: Path) -> None:
    """Atomically persist a private model JSON artifact."""
    resolved_path = output_path.expanduser().resolve()
    resolved_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = resolved_path.with_suffix(resolved_path.suffix + ".tmp")

    try:
        payload = artifact.model_dump_json(indent=2).encode("utf-8")

        if len(payload) > _MAXIMUM_MODEL_BYTES:
            raise ModelArtifactError("The generated model exceeds the 10 MiB safety limit.")

        with temporary_path.open("wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())

        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, resolved_path)
    finally:
        temporary_path.unlink(missing_ok=True)


def load_model(model_path: Path) -> ModelArtifact:
    """Load and validate a bounded model artifact without executing code."""
    resolved_path = model_path.expanduser().resolve()

    try:
        size = resolved_path.stat().st_size
    except OSError as exc:
        raise ModelArtifactError(f"Unable to read model artifact: {exc}") from exc

    if size > _MAXIMUM_MODEL_BYTES:
        raise ModelArtifactError("The model artifact exceeds the 10 MiB safety limit.")

    try:
        payload = resolved_path.read_text(encoding="utf-8")
        artifact = ModelArtifact.model_validate_json(payload)
    except (OSError, UnicodeError, ValidationError, json.JSONDecodeError) as exc:
        raise ModelArtifactError("The model artifact is malformed or incompatible.") from exc

    feature_count = len(artifact.feature_schema.feature_names)
    for label in artifact.labels:
        if len(artifact.feature_log_probabilities[label]) != feature_count:
            raise ModelArtifactError("The model artifact has inconsistent feature dimensions.")

    return artifact
