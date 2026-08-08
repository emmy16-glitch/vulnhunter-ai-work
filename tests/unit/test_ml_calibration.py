import pytest

from vulnhunter.ml.calibration import (
    CalibrationBoundaryError,
    calibrated_advisory_prediction,
    calibration_metrics,
    fit_platt_calibrator,
)
from vulnhunter.ml.models import Prediction, TrainingExample


def _example(observation_id: int, label: str, category: str = "headers") -> TrainingExample:
    return TrainingExample(
        observation_id=observation_id,
        scan_id=((observation_id - 1) // 2) + 1,
        category=category,
        severity="low",
        title=f"reviewed observation {observation_id}",
        description="Redacted calibration example.",
        url=f"https://example.invalid/{observation_id}",
        evidence={},
        fingerprint=f"{observation_id:064x}",
        label=label,
    )


def _prediction(probability: float) -> Prediction:
    label = "confirmed" if probability >= 0.5 else "false_positive"
    return Prediction(
        label=label,
        confidence=max(probability, 1.0 - probability),
        probabilities={
            "confirmed": probability,
            "false_positive": 1.0 - probability,
        },
    )


def _calibration_set():
    examples = (
        _example(1, "confirmed"),
        _example(2, "false_positive"),
        _example(3, "confirmed", "debug"),
        _example(4, "false_positive", "debug"),
        _example(5, "confirmed", "headers"),
        _example(6, "false_positive", "headers"),
    )
    predictions = tuple(
        _prediction(value) for value in (0.65, 0.42, 0.74, 0.31, 0.61, 0.36)
    )
    return examples, predictions


def test_calibration_metrics_report_brier_logloss_and_reliability() -> None:
    examples, predictions = _calibration_set()
    probabilities = tuple(item.probabilities["confirmed"] for item in predictions)

    metrics = calibration_metrics(examples, probabilities, bins=5)

    assert metrics.samples == 6
    assert 0 <= metrics.brier_score <= 1
    assert metrics.log_loss >= 0
    assert 0 <= metrics.expected_calibration_error <= 1
    assert metrics.reliability


def test_platt_artifact_binds_exact_model_dataset_and_groups() -> None:
    examples, predictions = _calibration_set()
    artifact = fit_platt_calibrator(
        examples,
        predictions,
        base_model_sha256="a" * 64,
        calibration_group_ids=("family-b", "family-a", "family-b"),
        known_categories=("headers", "debug"),
    )

    assert artifact.base_model_sha256 == "a" * 64
    assert artifact.calibration_dataset_sha256 != "0" * 64
    assert artifact.calibration_group_ids == ("family-a", "family-b")
    assert artifact.known_categories == ("debug", "headers")
    assert artifact.external_holdout_used is False
    assert artifact.metrics_before.samples == artifact.metrics_after.samples == 6


def test_calibrator_requires_both_human_labels_and_group_provenance() -> None:
    examples, predictions = _calibration_set()

    with pytest.raises(CalibrationBoundaryError, match="group provenance"):
        fit_platt_calibrator(
            examples,
            predictions,
            base_model_sha256="b" * 64,
            calibration_group_ids=(),
            known_categories=("headers",),
        )

    all_positive = tuple(_example(index, "confirmed") for index in range(10, 14))
    with pytest.raises(CalibrationBoundaryError, match="both human labels"):
        fit_platt_calibrator(
            all_positive,
            tuple(_prediction(0.8) for _ in all_positive),
            base_model_sha256="b" * 64,
            calibration_group_ids=("family-a",),
            known_categories=("headers",),
        )


def test_unknown_category_abstains_instead_of_predicting_negative() -> None:
    examples, predictions = _calibration_set()
    artifact = fit_platt_calibrator(
        examples,
        predictions,
        base_model_sha256="c" * 64,
        calibration_group_ids=("family-a", "family-b"),
        known_categories=("headers", "debug"),
        abstention_margin=0.0,
    )

    result = calibrated_advisory_prediction(
        _example(20, "false_positive", category="unseen-category"),
        _prediction(0.2),
        artifact,
        base_model_sha256="c" * 64,
    )

    assert result.decision == "abstain"
    assert result.ood_score == 1.0
    assert "OOD_UNSEEN_CATEGORY" in result.reason_codes
    assert result.advisory_only is True


def test_low_calibrated_margin_abstains_with_reason() -> None:
    examples, predictions = _calibration_set()
    artifact = fit_platt_calibrator(
        examples,
        predictions,
        base_model_sha256="d" * 64,
        calibration_group_ids=("family-a", "family-b"),
        known_categories=("headers", "debug"),
        abstention_margin=0.49,
    )

    result = calibrated_advisory_prediction(
        _example(21, "confirmed", category="headers"),
        _prediction(0.51),
        artifact,
        base_model_sha256="d" * 64,
    )

    assert result.decision == "abstain"
    assert "LOW_CALIBRATED_MARGIN" in result.reason_codes


def test_calibrator_cannot_be_reused_with_a_different_base_model() -> None:
    examples, predictions = _calibration_set()
    artifact = fit_platt_calibrator(
        examples,
        predictions,
        base_model_sha256="e" * 64,
        calibration_group_ids=("family-a", "family-b"),
        known_categories=("headers", "debug"),
    )

    with pytest.raises(CalibrationBoundaryError, match="different base model"):
        calibrated_advisory_prediction(
            examples[0],
            predictions[0],
            artifact,
            base_model_sha256="f" * 64,
        )
