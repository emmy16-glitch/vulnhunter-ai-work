import pytest

from vulnhunter.ml.evaluation import (
    EvaluationBoundaryError,
    EvaluationSample,
    build_complete_evaluation_report,
    classification_metrics,
    grouped_bootstrap_interval,
    review_ranking_metrics,
    summarize_repeated_seed_metric,
    threshold_sensitivity,
)


def _sample(
    observation_id: str,
    *,
    family: str,
    label: str,
    probability: float,
    category: str = "headers",
    severity: str = "medium",
    abstained: bool = False,
) -> EvaluationSample:
    return EvaluationSample(
        observation_id=observation_id,
        application_family_id=family,
        category=category,
        severity=severity,
        label=label,
        positive_probability=probability,
        abstained=abstained,
    )


def _samples() -> tuple[EvaluationSample, ...]:
    return (
        _sample("a1", family="family-a", label="confirmed", probability=0.92),
        _sample("a2", family="family-a", label="false_positive", probability=0.20),
        _sample(
            "a3",
            family="family-a",
            label="confirmed",
            probability=0.48,
            category="debug",
            severity="high",
        ),
        _sample("b1", family="family-b", label="confirmed", probability=0.78),
        _sample("b2", family="family-b", label="false_positive", probability=0.60),
        _sample(
            "b3",
            family="family-b",
            label="false_positive",
            probability=0.15,
            category="debug",
            severity="low",
            abstained=True,
        ),
    )


def test_core_metrics_keep_abstention_out_of_negative_class() -> None:
    metrics = classification_metrics(_samples(), threshold=0.5)

    assert metrics.samples == 6
    assert metrics.covered_samples == 5
    assert metrics.abstained_samples == 1
    assert metrics.true_positive == 2
    assert metrics.false_positive == 1
    assert metrics.false_negative == 1
    assert metrics.true_negative == 1
    assert metrics.coverage == pytest.approx(5 / 6)
    assert metrics.matthews_correlation_coefficient is not None
    assert metrics.average_precision is not None
    assert metrics.roc_auc is not None


def test_review_budget_metrics_are_explicit_and_do_not_invent_time_saved() -> None:
    ranking = review_ranking_metrics(_samples(), budgets=(2, 4, 10))

    assert ranking.samples == 6
    assert ranking.confirmed_samples == 3
    assert ranking.sortable_samples == 5
    assert ranking.recommendation_coverage == pytest.approx(5 / 6)
    assert ranking.reviewer_time_saved_measured is False
    assert tuple(item.budget for item in ranking.budgets) == (2, 4, 10)
    assert ranking.budgets[0].confirmed_in_budget == 2
    assert ranking.budgets[0].precision_at_budget == 1.0
    assert ranking.budgets[0].recall_at_budget == pytest.approx(2 / 3)


def test_complete_report_has_sample_counted_slices_and_no_external_holdout() -> None:
    repeated = summarize_repeated_seed_metric(
        "balanced_accuracy",
        ((11, 0.72), (17, 0.75), (29, 0.73)),
    )
    report = build_complete_evaluation_report(
        _samples(),
        threshold=0.5,
        review_budgets=(2, 4),
        sensitivity_thresholds=(0.4, 0.5, 0.7),
        bootstrap_iterations=120,
        bootstrap_seed=23,
        repeated_seed_summary=repeated,
    )

    assert report.development_only is True
    assert report.external_holdout_used is False
    assert report.application_families == 2
    assert report.family_bootstrap is not None
    assert report.family_bootstrap.groups == 2
    assert report.family_bootstrap.iterations == 120
    assert report.repeated_seed_summary == repeated
    assert all(item.samples == item.metrics.samples for item in report.slices)
    dimensions = {item.dimension for item in report.slices}
    assert dimensions == {"application_family", "category", "severity"}
    assert any("locked external holdout" in item for item in report.limitations)
    assert any("Reviewer time saved" in item for item in report.limitations)


def test_threshold_sensitivity_reports_false_negative_effects() -> None:
    points = threshold_sensitivity(_samples(), (0.4, 0.5, 0.8))

    assert tuple(item.threshold for item in points) == (0.4, 0.5, 0.8)
    assert points[0].false_negative <= points[-1].false_negative
    assert all(item.coverage == pytest.approx(5 / 6) for item in points)


def test_grouped_bootstrap_resamples_application_families() -> None:
    interval = grouped_bootstrap_interval(
        _samples(),
        metric="recall",
        threshold=0.5,
        iterations=150,
        seed=7,
    )

    assert interval.groups == 2
    assert interval.iterations == 150
    assert interval.lower <= interval.estimate <= interval.upper


def test_complete_evaluation_fails_closed_without_both_human_labels() -> None:
    positives = tuple(
        _sample(
            f"p{index}",
            family="family-a" if index % 2 else "family-b",
            label="confirmed",
            probability=0.8,
        )
        for index in range(1, 5)
    )

    with pytest.raises(EvaluationBoundaryError, match="both human labels"):
        build_complete_evaluation_report(positives, bootstrap_iterations=100)


def test_grouped_bootstrap_requires_multiple_application_families() -> None:
    single_family = tuple(
        _sample(
            f"s{index}",
            family="family-a",
            label="confirmed" if index % 2 else "false_positive",
            probability=0.8 if index % 2 else 0.2,
        )
        for index in range(1, 5)
    )

    with pytest.raises(EvaluationBoundaryError, match="at least two application families"):
        grouped_bootstrap_interval(single_family, iterations=100)


def test_repeated_seed_summary_rejects_duplicate_seed_identity() -> None:
    with pytest.raises(EvaluationBoundaryError, match="unique"):
        summarize_repeated_seed_metric("recall", ((7, 0.7), (7, 0.8)))
