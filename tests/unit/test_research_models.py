"""Tests for immutable autoresearch contracts."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from vulnhunter.orchestration import VerifierKind
from vulnhunter.research.models import (
    ExperimentSpec,
    MetricReport,
    ObjectiveDirection,
    ObjectiveSpec,
    RegressionGate,
    SearchPolicy,
)


def valid_spec() -> ExperimentSpec:
    return ExperimentSpec(
        title="Improve one bounded feature",
        hypothesis=(
            "A privacy-safe feature will improve the selected metric without "
            "weakening safety or reviewed-data constraints."
        ),
        strategy_family="feature_engineering",
        editable_paths=("vulnhunter/ml/features.py",),
        objective=ObjectiveSpec(
            metric="holdout_f1",
            direction=ObjectiveDirection.MAXIMIZE,
            minimum_delta=0.01,
        ),
        regression_gates=(
            RegressionGate(
                metric="holdout_recall",
                direction=ObjectiveDirection.MAXIMIZE,
                maximum_degradation=0.0,
            ),
        ),
        required_safety_checks=("redaction_preserved",),
        verifiers=(VerifierKind.GIT_DIFF_CHECK,),
    )


def test_spec_rejects_objective_as_regression_gate() -> None:
    with pytest.raises(ValidationError, match="must not also be a regression"):
        ExperimentSpec(
            **{
                **valid_spec().model_dump(),
                "regression_gates": [
                    {
                        "metric": "holdout_f1",
                        "direction": "maximize",
                        "maximum_degradation": 0.0,
                    }
                ],
            }
        )


def test_metric_report_rejects_non_finite_values() -> None:
    with pytest.raises(ValidationError, match="must be finite"):
        MetricReport(metrics={"holdout_f1": float("nan")})


def test_metric_report_normalizes_names() -> None:
    report = MetricReport(
        metrics={"Holdout_F1": 0.75},
        safety_checks={"Redaction_Preserved": True},
    )

    assert report.metrics == {"holdout_f1": 0.75}
    assert report.safety_checks == {"redaction_preserved": True}


def test_search_policy_requires_positive_total_weight() -> None:
    with pytest.raises(ValidationError, match="positive strategy weight"):
        SearchPolicy(strategy_weights={"feature_engineering": 0.0})
