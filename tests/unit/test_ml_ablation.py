from vulnhunter.ml.ablation import (
    build_leakage_ablation_report,
    evaluate_feature_ablations,
    evaluate_leave_one_group_out,
)
from vulnhunter.ml.models import TrainingExample


def _example(
    observation_id: int,
    scan_id: int,
    label: str,
    category: str,
    *,
    severity: str = "low",
) -> TrainingExample:
    return TrainingExample(
        observation_id=observation_id,
        scan_id=scan_id,
        category=category,
        severity=severity,
        title=f"{category} reviewed observation {observation_id}",
        description="Redacted deterministic observation for development evaluation.",
        url=f"https://example.invalid/{category}/{observation_id}",
        evidence={
            "status_code": 200 if label == "false_positive" else 500,
            "missing_headers": ["content-security-policy"] if label == "confirmed" else [],
            "detected_indicators": ["traceback"] if label == "confirmed" else [],
        },
        fingerprint=f"{observation_id:064x}",
        label=label,
    )


def _development() -> tuple[TrainingExample, ...]:
    return (
        _example(1, 1, "confirmed", "debug", severity="high"),
        _example(2, 1, "false_positive", "debug"),
        _example(3, 2, "confirmed", "headers", severity="medium"),
        _example(4, 2, "false_positive", "headers"),
        _example(5, 3, "confirmed", "directory", severity="medium"),
        _example(6, 3, "false_positive", "directory"),
    )


def test_required_feature_family_ablations_run_on_development_data() -> None:
    examples = _development()
    results = evaluate_feature_ablations(examples[:4], examples[4:])

    assert tuple(item.name for item in results) == (
        "full_baseline",
        "structural_evidence_only",
        "no_category",
        "no_severity",
        "no_title_description_tokens",
    )
    assert all(item.feature_count > 0 for item in results)
    assert all(item.validation_samples == 2 for item in results)


def test_category_leave_one_out_preserves_whole_category_groups() -> None:
    report = evaluate_leave_one_group_out(_development(), group_kind="category")

    assert report.available is True
    assert {item.group_key for item in report.slices} == {"debug", "headers", "directory"}
    assert all(item.validation_samples == 2 for item in report.slices)


def test_unavailable_detector_and_template_provenance_is_not_invented() -> None:
    examples = _development()

    detector = evaluate_leave_one_group_out(examples, group_kind="detector")
    template = evaluate_leave_one_group_out(examples, group_kind="template_family")

    assert detector.available is False
    assert "not available" in (detector.reason or "")
    assert template.available is False
    assert "not available" in (template.reason or "")


def test_explicit_application_family_keys_enable_family_holdout() -> None:
    examples = _development()
    family_keys = {
        1: "family-a",
        2: "family-a",
        3: "family-b",
        4: "family-b",
        5: "family-c",
        6: "family-c",
    }

    report = evaluate_leave_one_group_out(
        examples,
        group_kind="application_family",
        group_keys=family_keys,
    )

    assert report.available is True
    assert {item.group_key for item in report.slices} == {"family-a", "family-b", "family-c"}


def test_incomplete_group_provenance_fails_closed_without_partial_metrics() -> None:
    examples = _development()
    report = evaluate_leave_one_group_out(
        examples,
        group_kind="detector",
        group_keys={1: "detector-a"},
    )

    assert report.available is False
    assert report.slices == ()
    assert "incomplete" in (report.reason or "")


def test_combined_report_never_claims_external_holdout_evidence() -> None:
    examples = _development()
    report = build_leakage_ablation_report(
        examples[:4],
        examples[4:],
        development_examples=examples,
    )

    assert report.evaluation_scope == "development_only"
    assert report.external_holdout_used is False
    assert len(report.feature_ablations) == 5
    by_group = {item.group_kind: item for item in report.group_ablations}
    assert by_group["category"].available is True
    assert by_group["detector"].available is False
    assert by_group["template_family"].available is False
    assert by_group["application_family"].available is False
