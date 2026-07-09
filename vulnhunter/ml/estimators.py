"""Small deterministic Naive Bayes estimators without external ML dependencies."""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass

from vulnhunter.exceptions import ModelArtifactError
from vulnhunter.ml.models import (
    EvaluationMetrics,
    ModelType,
    Prediction,
    TrainingExample,
    TrainingLabel,
)


@dataclass(frozen=True, slots=True)
class FittedParameters:
    """Validated numeric parameters produced by one Naive Bayes fit."""

    model_type: ModelType
    alpha: float
    class_log_priors: dict[TrainingLabel, float]
    feature_log_probabilities: dict[TrainingLabel, tuple[float, ...]]
    feature_log_complements: dict[TrainingLabel, tuple[float, ...]]
    class_counts: dict[TrainingLabel, int]


def _validate_training_input(
    examples: tuple[TrainingExample, ...],
    vectors: tuple[tuple[float, ...], ...],
    alpha: float,
) -> int:
    if alpha <= 0:
        raise ValueError("alpha must be greater than zero.")
    if not examples or not vectors or len(examples) != len(vectors):
        raise ValueError("Examples and vectors must be non-empty and aligned.")
    feature_count = len(vectors[0])
    if feature_count < 1 or any(len(vector) != feature_count for vector in vectors):
        raise ValueError("All feature vectors must have one consistent non-zero dimension.")
    if {example.label for example in examples} != {"confirmed", "false_positive"}:
        raise ValueError("Both training labels are required to fit a model.")
    return feature_count


def fit_model(
    examples: tuple[TrainingExample, ...],
    vectors: tuple[tuple[float, ...], ...],
    *,
    model_type: ModelType,
    alpha: float,
) -> FittedParameters:
    """Fit Multinomial or Bernoulli Naive Bayes deterministically."""
    feature_count = _validate_training_input(examples, vectors, alpha)
    class_counts: Counter[TrainingLabel] = Counter(example.label for example in examples)
    total_samples = len(examples)
    class_log_priors: dict[TrainingLabel, float] = {}
    feature_log_probabilities: dict[TrainingLabel, tuple[float, ...]] = {}
    feature_log_complements: dict[TrainingLabel, tuple[float, ...]] = {}

    for label in ("confirmed", "false_positive"):
        class_log_priors[label] = math.log(class_counts[label] / total_samples)
        labelled_vectors = tuple(
            vector
            for example, vector in zip(examples, vectors, strict=True)
            if example.label == label
        )

        if model_type == "multinomial_naive_bayes":
            totals = [0.0] * feature_count
            for vector in labelled_vectors:
                totals = [left + right for left, right in zip(totals, vector, strict=True)]
            denominator = sum(totals) + alpha * feature_count
            feature_log_probabilities[label] = tuple(
                math.log((value + alpha) / denominator) for value in totals
            )
            continue

        present_counts = [0] * feature_count
        for vector in labelled_vectors:
            present_counts = [
                count + (1 if value > 0 else 0)
                for count, value in zip(present_counts, vector, strict=True)
            ]
        denominator = len(labelled_vectors) + 2 * alpha
        probabilities = tuple((count + alpha) / denominator for count in present_counts)
        feature_log_probabilities[label] = tuple(math.log(value) for value in probabilities)
        feature_log_complements[label] = tuple(math.log1p(-value) for value in probabilities)

    return FittedParameters(
        model_type=model_type,
        alpha=alpha,
        class_log_priors=class_log_priors,
        feature_log_probabilities=feature_log_probabilities,
        feature_log_complements=feature_log_complements,
        class_counts=dict(class_counts),
    )


def predict_vector(
    vector: tuple[float, ...],
    *,
    parameters: FittedParameters,
    decision_threshold: float,
) -> Prediction:
    """Return posterior probabilities and apply an explicit positive threshold."""
    if decision_threshold <= 0 or decision_threshold >= 1:
        raise ValueError("decision_threshold must be between zero and one.")

    scores: dict[TrainingLabel, float] = {}
    for label in ("confirmed", "false_positive"):
        probabilities = parameters.feature_log_probabilities[label]
        if len(probabilities) != len(vector):
            raise ModelArtifactError("The model feature dimensions are inconsistent.")

        if parameters.model_type == "multinomial_naive_bayes":
            contribution = sum(
                value * probability
                for value, probability in zip(vector, probabilities, strict=True)
            )
        else:
            complements = parameters.feature_log_complements.get(label)
            if complements is None or len(complements) != len(vector):
                raise ModelArtifactError("The Bernoulli complement dimensions are inconsistent.")
            contribution = sum(
                probability if value > 0 else complement
                for value, probability, complement in zip(
                    vector,
                    probabilities,
                    complements,
                    strict=True,
                )
            )

        scores[label] = parameters.class_log_priors[label] + contribution

    maximum_score = max(scores.values())
    exponentials = {label: math.exp(score - maximum_score) for label, score in scores.items()}
    denominator = sum(exponentials.values())
    posterior = {label: value / denominator for label, value in exponentials.items()}
    predicted_label: TrainingLabel = (
        "confirmed" if posterior["confirmed"] >= decision_threshold else "false_positive"
    )

    return Prediction(
        label=predicted_label,
        confidence=posterior[predicted_label],
        probabilities=posterior,
    )


def evaluate_predictions(
    examples: tuple[TrainingExample, ...],
    predictions: tuple[Prediction, ...],
) -> EvaluationMetrics:
    """Calculate a complete binary confusion matrix and derived metrics."""
    if not examples or len(examples) != len(predictions):
        raise ValueError("Examples and predictions must be non-empty and aligned.")

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
