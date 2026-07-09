"""Training-only grouped cross-validation and deterministic model selection."""

from __future__ import annotations

import itertools
from collections import Counter
from dataclasses import dataclass

from vulnhunter.exceptions import InsufficientTrainingDataError
from vulnhunter.ml.estimators import evaluate_predictions, fit_model, predict_vector
from vulnhunter.ml.features import build_feature_schema, vectorize, vectorize_many
from vulnhunter.ml.models import (
    EvaluationMetrics,
    ModelType,
    TrainingExample,
    TrainingLabel,
    TuningSummary,
)

DEFAULT_ALGORITHMS: tuple[ModelType, ...] = (
    "bernoulli_naive_bayes",
    "multinomial_naive_bayes",
)
DEFAULT_ALPHAS = (0.1, 0.5, 1.0, 2.0)
DEFAULT_THRESHOLDS = (0.30, 0.40, 0.50, 0.60, 0.70)


@dataclass(frozen=True, slots=True)
class GroupFold:
    """One scan-disjoint training and validation fold."""

    train_examples: tuple[TrainingExample, ...]
    validation_examples: tuple[TrainingExample, ...]


@dataclass(frozen=True, slots=True)
class TuningResult:
    """Selected candidate and its training-only cross-validation provenance."""

    model_type: ModelType
    alpha: float
    decision_threshold: float
    summary: TuningSummary


def _has_both_labels(examples: tuple[TrainingExample, ...]) -> bool:
    return {example.label for example in examples} == {"confirmed", "false_positive"}


def build_two_fold_group_cv(
    examples: tuple[TrainingExample, ...],
) -> tuple[GroupFold, GroupFold]:
    """Partition complete scans into two balanced validation folds.

    Every example appears in validation exactly once. Both folds and their
    complementary training sets must contain both labels.
    """
    scan_ids = tuple(sorted({example.scan_id for example in examples}))
    if len(scan_ids) < 4:
        raise InsufficientTrainingDataError(
            "Grouped model selection requires at least four independent scans."
        )

    total_counts: Counter[TrainingLabel] = Counter(example.label for example in examples)
    target_size = len(examples) / 2
    target_confirmed = total_counts["confirmed"] / 2
    target_false_positive = total_counts["false_positive"] / 2
    anchor = scan_ids[0]
    best: tuple[tuple[float, float, int, tuple[int, ...]], tuple[int, ...]] | None = None

    for size in range(1, len(scan_ids)):
        for candidate in itertools.combinations(scan_ids, size):
            if anchor not in candidate:
                continue
            candidate_ids = set(candidate)
            complement = tuple(scan_id for scan_id in scan_ids if scan_id not in candidate_ids)
            if not complement:
                continue

            first = tuple(example for example in examples if example.scan_id in candidate_ids)
            second = tuple(example for example in examples if example.scan_id not in candidate_ids)
            if not _has_both_labels(first) or not _has_both_labels(second):
                continue

            counts: Counter[TrainingLabel] = Counter(example.label for example in first)
            size_error = abs(len(first) - target_size) / max(1, len(examples))
            class_error = abs(counts["confirmed"] - target_confirmed) / max(
                1, total_counts["confirmed"]
            ) + abs(counts["false_positive"] - target_false_positive) / max(
                1, total_counts["false_positive"]
            )
            scan_error = abs(len(candidate) - len(complement))
            score = (size_error + class_error, class_error, scan_error, candidate)
            if best is None or score < best[0]:
                best = (score, candidate)

    if best is None:
        raise InsufficientTrainingDataError(
            "No two-fold scan-group partition can preserve both labels in every fold. "
            "Collect reviewed examples across more independent scans."
        )

    first_ids = set(best[1])
    first_validation = tuple(
        sorted(
            (example for example in examples if example.scan_id in first_ids),
            key=lambda item: item.observation_id,
        )
    )
    second_validation = tuple(
        sorted(
            (example for example in examples if example.scan_id not in first_ids),
            key=lambda item: item.observation_id,
        )
    )
    return (
        GroupFold(train_examples=second_validation, validation_examples=first_validation),
        GroupFold(train_examples=first_validation, validation_examples=second_validation),
    )


def tune_model(
    training_examples: tuple[TrainingExample, ...],
    *,
    maximum_tokens: int = 128,
    algorithms: tuple[ModelType, ...] = DEFAULT_ALGORITHMS,
    alphas: tuple[float, ...] = DEFAULT_ALPHAS,
    thresholds: tuple[float, ...] = DEFAULT_THRESHOLDS,
) -> TuningResult:
    """Select a candidate using only grouped cross-validation on training scans."""
    if not algorithms or not alphas or not thresholds:
        raise ValueError("Model-selection candidate grids must not be empty.")
    if len(algorithms) != len(set(algorithms)):
        raise ValueError("algorithms must not contain duplicates.")
    if len(alphas) != len(set(alphas)) or any(value <= 0 for value in alphas):
        raise ValueError("alphas must be unique and greater than zero.")
    if len(thresholds) != len(set(thresholds)) or any(
        value <= 0 or value >= 1 for value in thresholds
    ):
        raise ValueError("thresholds must be unique and between zero and one.")

    folds = build_two_fold_group_cv(training_examples)
    best: tuple[tuple[float, ...], ModelType, float, float, EvaluationMetrics] | None = None
    candidate_index = 0

    for model_type in algorithms:
        for alpha in alphas:
            for threshold in thresholds:
                all_examples: list[TrainingExample] = []
                all_predictions = []

                for fold in folds:
                    schema = build_feature_schema(
                        fold.train_examples,
                        maximum_tokens=maximum_tokens,
                    )
                    parameters = fit_model(
                        fold.train_examples,
                        vectorize_many(fold.train_examples, schema),
                        model_type=model_type,
                        alpha=alpha,
                    )
                    predictions = tuple(
                        predict_vector(
                            vectorize(example, schema),
                            parameters=parameters,
                            decision_threshold=threshold,
                        )
                        for example in fold.validation_examples
                    )
                    all_examples.extend(fold.validation_examples)
                    all_predictions.extend(predictions)

                metrics = evaluate_predictions(tuple(all_examples), tuple(all_predictions))
                rank = (
                    metrics.f1_score,
                    metrics.recall,
                    metrics.precision,
                    metrics.accuracy,
                    -abs(threshold - 0.5),
                    -candidate_index,
                )
                if best is None or rank > best[0]:
                    best = (rank, model_type, alpha, threshold, metrics)
                candidate_index += 1

    if best is None:
        raise InsufficientTrainingDataError("No model-selection candidate could be evaluated.")

    _, selected_model_type, selected_alpha, selected_threshold, selected_metrics = best
    summary = TuningSummary(
        fold_count=len(folds),
        candidate_count=len(algorithms) * len(alphas) * len(thresholds),
        algorithm_candidates=algorithms,
        alpha_candidates=alphas,
        threshold_candidates=thresholds,
        selected_model_type=selected_model_type,
        selected_alpha=selected_alpha,
        selected_threshold=selected_threshold,
        cross_validation=selected_metrics,
    )
    return TuningResult(
        model_type=selected_model_type,
        alpha=selected_alpha,
        decision_threshold=selected_threshold,
        summary=summary,
    )
