"""Development-only evaluation, ranking and grouped uncertainty contracts."""

from __future__ import annotations

import math
import random
from collections.abc import Iterable, Sequence
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class EvaluationBoundaryError(RuntimeError):
    """An evaluation invariant failed closed."""


class EvaluationSample(BaseModel):
    """One governed labelled development example and its advisory score."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    observation_id: str = Field(min_length=1)
    application_family_id: str = Field(min_length=1)
    category: str = Field(min_length=1)
    severity: str = Field(min_length=1)
    label: Literal["confirmed", "false_positive"]
    positive_probability: float = Field(ge=0, le=1)
    abstained: bool = False


class CoreClassificationMetrics(BaseModel):
    """Classification metrics over covered recommendations only."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    samples: int = Field(ge=1)
    covered_samples: int = Field(ge=0)
    abstained_samples: int = Field(ge=0)
    coverage: float = Field(ge=0, le=1)
    true_positive: int = Field(ge=0)
    false_positive: int = Field(ge=0)
    true_negative: int = Field(ge=0)
    false_negative: int = Field(ge=0)
    accuracy: float | None = Field(default=None, ge=0, le=1)
    precision: float | None = Field(default=None, ge=0, le=1)
    recall: float | None = Field(default=None, ge=0, le=1)
    f1: float | None = Field(default=None, ge=0, le=1)
    specificity: float | None = Field(default=None, ge=0, le=1)
    balanced_accuracy: float | None = Field(default=None, ge=0, le=1)
    matthews_correlation_coefficient: float | None = Field(default=None, ge=-1, le=1)
    average_precision: float | None = Field(default=None, ge=0, le=1)
    roc_auc: float | None = Field(default=None, ge=0, le=1)

    @model_validator(mode="after")
    def counts_match(self):
        covered = (
            self.true_positive + self.false_positive + self.true_negative + self.false_negative
        )
        if covered != self.covered_samples:
            raise ValueError("confusion-matrix counts must equal covered samples")
        if self.covered_samples + self.abstained_samples != self.samples:
            raise ValueError("covered and abstained samples must equal total samples")
        return self


class ReviewBudgetMetric(BaseModel):
    """Ranking utility at one explicit review budget."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    budget: int = Field(ge=1)
    reviewed: int = Field(ge=0)
    confirmed_in_budget: int = Field(ge=0)
    precision_at_budget: float | None = Field(default=None, ge=0, le=1)
    recall_at_budget: float = Field(ge=0, le=1)
    number_needed_to_review: float | None = Field(default=None, ge=1)


class RankingMetrics(BaseModel):
    """Review-prioritisation metrics without fabricated time-saved claims."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    samples: int = Field(ge=1)
    confirmed_samples: int = Field(ge=1)
    sortable_samples: int = Field(ge=0)
    recommendation_coverage: float = Field(ge=0, le=1)
    average_precision: float | None = Field(default=None, ge=0, le=1)
    budgets: tuple[ReviewBudgetMetric, ...]
    reviewer_time_saved_measured: Literal[False] = False


class EvaluationSlice(BaseModel):
    """One sample-counted generalisation slice."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    dimension: Literal["application_family", "category", "severity"]
    value: str = Field(min_length=1)
    samples: int = Field(ge=1)
    metrics: CoreClassificationMetrics


class GroupBootstrapInterval(BaseModel):
    """Application-family-grouped bootstrap interval for one metric."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    metric: Literal["recall", "precision", "balanced_accuracy", "average_precision"]
    groups: int = Field(ge=2)
    iterations: int = Field(ge=100)
    seed: int
    estimate: float = Field(ge=0, le=1)
    lower: float = Field(ge=0, le=1)
    upper: float = Field(ge=0, le=1)

    @model_validator(mode="after")
    def ordered_interval(self):
        if not self.lower <= self.estimate <= self.upper:
            raise ValueError("bootstrap interval must contain its estimate")
        return self


class ThresholdSensitivityPoint(BaseModel):
    """Covered-sample metrics for one frozen candidate threshold."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    threshold: float = Field(gt=0, lt=1)
    coverage: float = Field(ge=0, le=1)
    precision: float | None = Field(default=None, ge=0, le=1)
    recall: float | None = Field(default=None, ge=0, le=1)
    false_negative: int = Field(ge=0)


class RepeatedSeedSummary(BaseModel):
    """Bounded stability summary supplied from repeated development runs."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    metric: str = Field(min_length=1)
    seeds: tuple[int, ...] = Field(min_length=2)
    values: tuple[float, ...] = Field(min_length=2)
    mean: float
    minimum: float
    maximum: float

    @model_validator(mode="after")
    def aligned(self):
        if len(self.seeds) != len(self.values):
            raise ValueError("repeated-seed values must align with seeds")
        if len(set(self.seeds)) != len(self.seeds):
            raise ValueError("repeated-seed identities must be unique")
        return self


class CompleteEvaluationReport(BaseModel):
    """Development-only evaluation report; locked external holdout is inaccessible here."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[1] = 1
    development_only: Literal[True] = True
    external_holdout_used: Literal[False] = False
    threshold: float = Field(gt=0, lt=1)
    samples: int = Field(ge=2)
    application_families: int = Field(ge=1)
    core: CoreClassificationMetrics
    ranking: RankingMetrics
    slices: tuple[EvaluationSlice, ...]
    threshold_sensitivity: tuple[ThresholdSensitivityPoint, ...]
    family_bootstrap: GroupBootstrapInterval | None = None
    repeated_seed_summary: RepeatedSeedSummary | None = None
    limitations: tuple[str, ...]


def _safe_ratio(numerator: float, denominator: float) -> float | None:
    if denominator == 0:
        return None
    return numerator / denominator


def _average_precision(samples: Sequence[EvaluationSample]) -> float | None:
    positives = sum(item.label == "confirmed" for item in samples)
    if positives == 0:
        return None
    ranked = sorted(samples, key=lambda item: (-item.positive_probability, item.observation_id))
    found = 0
    total = 0.0
    for index, item in enumerate(ranked, start=1):
        if item.label != "confirmed":
            continue
        found += 1
        total += found / index
    return total / positives


def _roc_auc(samples: Sequence[EvaluationSample]) -> float | None:
    positives = tuple(item for item in samples if item.label == "confirmed")
    negatives = tuple(item for item in samples if item.label == "false_positive")
    if not positives or not negatives:
        return None
    wins = 0.0
    for positive in positives:
        for negative in negatives:
            if positive.positive_probability > negative.positive_probability:
                wins += 1.0
            elif positive.positive_probability == negative.positive_probability:
                wins += 0.5
    return wins / (len(positives) * len(negatives))


def classification_metrics(
    samples: Sequence[EvaluationSample],
    *,
    threshold: float = 0.5,
) -> CoreClassificationMetrics:
    """Evaluate non-abstained recommendations without converting abstention to negative."""

    if not samples:
        raise EvaluationBoundaryError("evaluation requires labelled samples")
    if not 0 < threshold < 1:
        raise EvaluationBoundaryError("evaluation threshold must be between zero and one")

    covered = tuple(item for item in samples if not item.abstained)
    tp = fp = tn = fn = 0
    for item in covered:
        predicted_positive = item.positive_probability >= threshold
        actual_positive = item.label == "confirmed"
        if predicted_positive and actual_positive:
            tp += 1
        elif predicted_positive:
            fp += 1
        elif actual_positive:
            fn += 1
        else:
            tn += 1

    precision = _safe_ratio(tp, tp + fp)
    recall = _safe_ratio(tp, tp + fn)
    specificity = _safe_ratio(tn, tn + fp)
    accuracy = _safe_ratio(tp + tn, len(covered))
    f1 = None
    if precision is not None and recall is not None and precision + recall:
        f1 = 2 * precision * recall / (precision + recall)
    balanced = None
    if recall is not None and specificity is not None:
        balanced = (recall + specificity) / 2
    mcc_denominator = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = None if mcc_denominator == 0 else ((tp * tn) - (fp * fn)) / mcc_denominator

    return CoreClassificationMetrics(
        samples=len(samples),
        covered_samples=len(covered),
        abstained_samples=len(samples) - len(covered),
        coverage=len(covered) / len(samples),
        true_positive=tp,
        false_positive=fp,
        true_negative=tn,
        false_negative=fn,
        accuracy=accuracy,
        precision=precision,
        recall=recall,
        f1=f1,
        specificity=specificity,
        balanced_accuracy=balanced,
        matthews_correlation_coefficient=mcc,
        average_precision=_average_precision(covered),
        roc_auc=_roc_auc(covered),
    )


def review_ranking_metrics(
    samples: Sequence[EvaluationSample],
    *,
    budgets: Sequence[int] = (10, 25, 50),
) -> RankingMetrics:
    """Report prioritisation utility at explicit budgets with abstentions left unsorted."""

    if not samples:
        raise EvaluationBoundaryError("ranking evaluation requires labelled samples")
    confirmed = sum(item.label == "confirmed" for item in samples)
    if confirmed == 0:
        raise EvaluationBoundaryError("ranking evaluation requires at least one confirmed example")
    sortable = sorted(
        (item for item in samples if not item.abstained),
        key=lambda item: (-item.positive_probability, item.observation_id),
    )
    clean_budgets = tuple(sorted(set(value for value in budgets if value > 0)))
    if not clean_budgets:
        raise EvaluationBoundaryError("at least one positive review budget is required")

    results: list[ReviewBudgetMetric] = []
    for budget in clean_budgets:
        selected = sortable[:budget]
        found = sum(item.label == "confirmed" for item in selected)
        reviewed = len(selected)
        results.append(
            ReviewBudgetMetric(
                budget=budget,
                reviewed=reviewed,
                confirmed_in_budget=found,
                precision_at_budget=_safe_ratio(found, reviewed),
                recall_at_budget=found / confirmed,
                number_needed_to_review=None if found == 0 else reviewed / found,
            )
        )

    return RankingMetrics(
        samples=len(samples),
        confirmed_samples=confirmed,
        sortable_samples=len(sortable),
        recommendation_coverage=len(sortable) / len(samples),
        average_precision=_average_precision(sortable),
        budgets=tuple(results),
    )


def _slice_report(
    samples: Sequence[EvaluationSample],
    *,
    dimension: Literal["application_family", "category", "severity"],
    threshold: float,
) -> tuple[EvaluationSlice, ...]:
    attribute = {
        "application_family": "application_family_id",
        "category": "category",
        "severity": "severity",
    }[dimension]
    values = sorted({getattr(item, attribute) for item in samples})
    return tuple(
        EvaluationSlice(
            dimension=dimension,
            value=value,
            samples=len(subset),
            metrics=classification_metrics(subset, threshold=threshold),
        )
        for value in values
        if (subset := tuple(item for item in samples if getattr(item, attribute) == value))
    )


def threshold_sensitivity(
    samples: Sequence[EvaluationSample],
    thresholds: Sequence[float],
) -> tuple[ThresholdSensitivityPoint, ...]:
    """Evaluate frozen-score sensitivity without selecting a threshold from external evidence."""

    unique = tuple(sorted(set(float(value) for value in thresholds)))
    if not unique or any(value <= 0 or value >= 1 for value in unique):
        raise EvaluationBoundaryError("threshold sensitivity values must be inside zero and one")
    return tuple(
        ThresholdSensitivityPoint(
            threshold=value,
            coverage=(metrics := classification_metrics(samples, threshold=value)).coverage,
            precision=metrics.precision,
            recall=metrics.recall,
            false_negative=metrics.false_negative,
        )
        for value in unique
    )


def _metric_value(metrics: CoreClassificationMetrics, metric: str) -> float | None:
    return getattr(metrics, metric)


def grouped_bootstrap_interval(
    samples: Sequence[EvaluationSample],
    *,
    metric: Literal["recall", "precision", "balanced_accuracy", "average_precision"] = "recall",
    threshold: float = 0.5,
    iterations: int = 500,
    seed: int = 17,
) -> GroupBootstrapInterval:
    """Bootstrap whole application families rather than individual observations."""

    families = sorted({item.application_family_id for item in samples})
    if len(families) < 2:
        raise EvaluationBoundaryError(
            "grouped bootstrap requires at least two application families"
        )
    if iterations < 100 or iterations > 10_000:
        raise EvaluationBoundaryError("bootstrap iterations must be between 100 and 10000")
    estimate = _metric_value(classification_metrics(samples, threshold=threshold), metric)
    if estimate is None:
        raise EvaluationBoundaryError(f"metric {metric} is unavailable for the supplied samples")

    by_family = {
        family: tuple(item for item in samples if item.application_family_id == family)
        for family in families
    }
    rng = random.Random(seed)
    values: list[float] = []
    for _ in range(iterations):
        selected = [rng.choice(families) for _ in families]
        bootstrap: list[EvaluationSample] = []
        for index, family in enumerate(selected):
            for item in by_family[family]:
                bootstrap.append(
                    item.model_copy(
                        update={"observation_id": f"bootstrap-{index}-{item.observation_id}"}
                    )
                )
        value = _metric_value(classification_metrics(tuple(bootstrap), threshold=threshold), metric)
        if value is not None:
            values.append(value)
    if len(values) < max(50, iterations // 2):
        raise EvaluationBoundaryError("too few valid grouped bootstrap replicates")
    values.sort()
    lower = values[max(0, int(0.025 * (len(values) - 1)))]
    upper = values[min(len(values) - 1, int(0.975 * (len(values) - 1)))]
    return GroupBootstrapInterval(
        metric=metric,
        groups=len(families),
        iterations=iterations,
        seed=seed,
        estimate=estimate,
        lower=min(lower, estimate),
        upper=max(upper, estimate),
    )


def summarize_repeated_seed_metric(
    metric: str,
    runs: Iterable[tuple[int, float]],
) -> RepeatedSeedSummary:
    """Summarise caller-produced repeated development runs without fabricating reruns."""

    ordered = tuple(sorted((int(seed), float(value)) for seed, value in runs))
    if len(ordered) < 2:
        raise EvaluationBoundaryError("repeated-seed summary requires at least two runs")
    seeds = tuple(item[0] for item in ordered)
    values = tuple(item[1] for item in ordered)
    if len(set(seeds)) != len(seeds):
        raise EvaluationBoundaryError("repeated-seed identities must be unique")
    return RepeatedSeedSummary(
        metric=metric,
        seeds=seeds,
        values=values,
        mean=sum(values) / len(values),
        minimum=min(values),
        maximum=max(values),
    )


def build_complete_evaluation_report(
    samples: Sequence[EvaluationSample],
    *,
    threshold: float = 0.5,
    review_budgets: Sequence[int] = (10, 25, 50),
    sensitivity_thresholds: Sequence[float] = (0.35, 0.5, 0.65),
    bootstrap_iterations: int = 500,
    bootstrap_seed: int = 17,
    repeated_seed_summary: RepeatedSeedSummary | None = None,
) -> CompleteEvaluationReport:
    """Build the P3.8 development report without opening the locked external holdout."""

    if len(samples) < 2:
        raise EvaluationBoundaryError("complete evaluation requires at least two samples")
    if {item.label for item in samples} != {"confirmed", "false_positive"}:
        raise EvaluationBoundaryError("complete evaluation requires both human labels")
    core = classification_metrics(samples, threshold=threshold)
    ranking = review_ranking_metrics(samples, budgets=review_budgets)
    slices = (
        *_slice_report(samples, dimension="application_family", threshold=threshold),
        *_slice_report(samples, dimension="category", threshold=threshold),
        *_slice_report(samples, dimension="severity", threshold=threshold),
    )
    families = len({item.application_family_id for item in samples})
    bootstrap = None
    if families >= 2 and core.recall is not None:
        bootstrap = grouped_bootstrap_interval(
            samples,
            metric="recall",
            threshold=threshold,
            iterations=bootstrap_iterations,
            seed=bootstrap_seed,
        )
    return CompleteEvaluationReport(
        threshold=threshold,
        samples=len(samples),
        application_families=families,
        core=core,
        ranking=ranking,
        slices=tuple(slices),
        threshold_sensitivity=threshold_sensitivity(samples, sensitivity_thresholds),
        family_bootstrap=bootstrap,
        repeated_seed_summary=repeated_seed_summary,
        limitations=(
            (
                "Development-only evaluation; locked external holdout is not "
                "accessible through this API."
            ),
            "Reviewer time saved is not reported without measurements from real review tasks.",
            (
                "Bootstrap uncertainty resamples whole application families and does not "
                "establish real-world performance."
            ),
        ),
    )


__all__ = [
    "CompleteEvaluationReport",
    "CoreClassificationMetrics",
    "EvaluationBoundaryError",
    "EvaluationSample",
    "EvaluationSlice",
    "GroupBootstrapInterval",
    "RankingMetrics",
    "RepeatedSeedSummary",
    "ReviewBudgetMetric",
    "ThresholdSensitivityPoint",
    "build_complete_evaluation_report",
    "classification_metrics",
    "grouped_bootstrap_interval",
    "review_ranking_metrics",
    "summarize_repeated_seed_metric",
    "threshold_sensitivity",
]
