from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from vulnhunter.ml.models import TrainingExample
from vulnhunter.ml.tasks import (
    TASK_CONTRACTS,
    AdvisoryTaskResult,
    MLTaskContract,
    ReviewLabelContract,
    TaskContractError,
    require_binary_training_label,
    task_contract,
)

NOW = datetime(2026, 8, 8, 17, 0, tzinfo=UTC)


def _example(label="confirmed"):
    return TrainingExample(
        observation_id=1,
        scan_id=1,
        category="missing_header",
        severity="low",
        title="Reviewed observation",
        description="Reviewed redacted evidence.",
        url="http://127.0.0.1/example",
        evidence={"status_code": 200},
        fingerprint="a" * 64,
        label=label,
    )


@pytest.mark.parametrize(
    "state",
    [
        "unreviewed",
        "awaiting_second_review",
        "review_disagreement",
        "awaiting_adjudication",
    ],
)
def test_non_terminal_review_states_never_become_training_labels(state):
    review = ReviewLabelContract(review_state=state)
    assert review.review_label is None
    assert review.eligible_for_binary_training is False
    with pytest.raises(TaskContractError, match="eligible terminal human label"):
        require_binary_training_label(_example(), review)


@pytest.mark.parametrize("label", ["confirmed", "false_positive"])
def test_only_matching_terminal_human_labels_feed_binary_training(label):
    review = ReviewLabelContract(review_state=label, review_label=label)
    example = _example(label=label)
    assert review.eligible_for_binary_training is True
    assert require_binary_training_label(example, review) is example


def test_binary_training_rejects_stale_label_disagreement():
    review = ReviewLabelContract(review_state="confirmed", review_label="confirmed")
    with pytest.raises(TaskContractError, match="authoritative human review label"):
        require_binary_training_label(_example(label="false_positive"), review)


@pytest.mark.parametrize("state", ["withdrawn", "corrected"])
def test_withdrawn_and_corrected_states_require_provenance(state):
    with pytest.raises(ValidationError, match="requires provenance"):
        ReviewLabelContract(review_state=state)
    review = ReviewLabelContract(
        review_state=state,
        correction_reference="correction-2026-08",
    )
    assert review.eligible_for_binary_training is False


def test_review_label_cannot_be_set_on_non_terminal_state():
    with pytest.raises(ValidationError, match="non-terminal"):
        ReviewLabelContract(review_state="awaiting_adjudication", review_label="confirmed")


def test_all_binding_tasks_have_separate_contracts_and_metrics():
    expected = {
        "review_priority",
        "vulnerability_category",
        "severity_assistance",
        "related_finding_retrieval",
        "evidence_quality",
        "remediation_retrieval",
        "source_code_candidate_retrieval",
        "summarisation",
        "report_drafting",
    }
    assert set(TASK_CONTRACTS) == expected
    versions = {contract.schema_version for contract in TASK_CONTRACTS.values()}
    assert len(versions) == len(expected)
    assert all(contract.metrics for contract in TASK_CONTRACTS.values())
    assert all(contract.advisory_only is True for contract in TASK_CONTRACTS.values())
    assert task_contract("review_priority").requires_terminal_review_label is True
    assert task_contract("related_finding_retrieval").requires_terminal_review_label is False


def test_generic_confidence_cannot_be_a_task_metric():
    with pytest.raises(ValidationError, match="generic confidence"):
        MLTaskContract(
            task="review_priority",
            schema_version="bad-v1",
            target="overloaded task",
            metrics=("confidence",),
            output_semantics="Invalid metric contract.",
        )


def test_advisory_result_cannot_claim_human_or_future_fields():
    base = {
        "model_id": "baseline-nb",
        "model_version": "1",
        "task": "review_priority",
        "task_schema_version": "review-priority-v1",
        "output": {"suggested_review_priority": "normal_review"},
        "reason_codes": ("bounded_baseline",),
        "created_at": NOW,
    }
    assert AdvisoryTaskResult(**base).advisory_only is True
    for forbidden in (
        "review_label",
        "effective_label",
        "positive_probability_calibrated",
        "uncertainty",
        "out_of_distribution_score",
    ):
        with pytest.raises(ValidationError, match="cannot claim"):
            AdvisoryTaskResult(**{**base, "output": {forbidden: 0.5}})


def test_advisory_result_normalizes_timezone_to_utc():
    plus_two = timezone(timedelta(hours=2))
    result = AdvisoryTaskResult(
        model_id="baseline-nb",
        model_version="1",
        task="review_priority",
        task_schema_version="review-priority-v1",
        output={"suggested_review_priority": "normal_review"},
        created_at=datetime(2026, 8, 8, 19, 0, tzinfo=plus_two),
    )
    assert result.created_at == NOW
    assert result.created_at.tzinfo is UTC


def test_advisory_result_requires_exact_task_schema_version():
    with pytest.raises(ValidationError, match="does not match"):
        AdvisoryTaskResult(
            model_id="baseline-nb",
            model_version="1",
            task="review_priority",
            task_schema_version="wrong-v9",
            output={"suggested_review_priority": "normal_review"},
            created_at=NOW,
        )
