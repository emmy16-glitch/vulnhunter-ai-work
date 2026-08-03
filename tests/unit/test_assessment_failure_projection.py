from __future__ import annotations

from copy import deepcopy

import pytest

from vulnhunter.web.assessment_projection import (
    assert_mobile_projection_invariants,
    mobile_assessment_projection,
)


def _plan(*, safe_retry: bool, retry_scope: str | None) -> dict[str, object]:
    return {
        "run_id": "mobile-failure-one",
        "plan_digest": "a" * 64,
        "profile": "static",
        "artifact": {
            "attachment_id": "attachment-one",
            "artifact_id": "apk-one",
            "artifact_sha256": "b" * 64,
            "original_filename": "Sample.apk",
        },
        "execution": {
            "state": "failed",
            "job_id": "job-one",
            "reason": "The latest worker status could not be verified safely.",
            "failure": {
                "category": "storage_failure",
                "stage": "worker_status",
                "reason_code": "status_worker_spool_error",
                "reference": "vh-mobile-0123456789ab",
                "message": "The latest worker status could not be verified safely.",
                "user_action": None,
                "operator_action": "Inspect the signed spool.",
                "safe_retry": safe_retry,
                "retry_scope": retry_scope,
                "preserved": [
                    "artifact",
                    "assessment",
                    "plan",
                    "approval",
                    "previous_receipts",
                ],
            },
        },
        "assessment_graph": {
            "graph_id": "mobile-failure-one-graph",
            "workspace_id": "workspace-one",
            "assessment_kind": "apk",
            "authorization_id": "attachment-one",
            "chat_stage": "blocked",
            "nodes": [
                {"stage": "authorization", "status": "completed"},
                {"stage": "plan", "status": "completed"},
                {"stage": "approval", "status": "completed"},
                {"stage": "execution", "status": "failed"},
                {"stage": "evidence", "status": "pending"},
                {"stage": "verification", "status": "pending"},
                {"stage": "review", "status": "pending"},
                {"stage": "report", "status": "pending"},
            ],
        },
    }


def test_projection_exposes_typed_failure_without_raw_operation_identifier():
    projection = mobile_assessment_projection(_plan(safe_retry=True, retry_scope="worker_status"))

    assert projection is not None
    failure = projection["execution"]["failure"]
    assert failure == {
        "category": "storage_failure",
        "stage": "worker_status",
        "reason_code": "status_worker_spool_error",
        "reference": "vh-mobile-0123456789ab",
        "message": "The latest worker status could not be verified safely.",
        "user_action": None,
        "operator_action": "Inspect the signed spool.",
        "safe_retry": True,
        "retry_scope": "worker_status",
        "preserved": [
            "artifact",
            "assessment",
            "plan",
            "approval",
            "previous_receipts",
        ],
    }
    assert "job-one" not in str(failure)
    assert projection["execution"]["terminal"] is True
    assert projection["health"] == {
        "assessment": "attention_required",
        "worker": "unavailable",
        "provider": "not_evaluated",
    }


def test_retry_action_requires_persisted_safe_retry_and_exact_scope():
    retryable = mobile_assessment_projection(_plan(safe_retry=True, retry_scope="worker_status"))
    blocked = mobile_assessment_projection(_plan(safe_retry=False, retry_scope=None))

    assert retryable is not None
    assert blocked is not None
    assert "request_retry" in retryable["allowed_actions"]
    assert "request_retry" not in blocked["allowed_actions"]


def test_projection_invariant_rejects_retry_without_safe_contract():
    projection = mobile_assessment_projection(_plan(safe_retry=True, retry_scope="worker_status"))
    assert projection is not None
    contradictory = deepcopy(projection)
    contradictory["execution"]["failure"]["safe_retry"] = False

    with pytest.raises(ValueError, match="Task-card retry state"):
        assert_mobile_projection_invariants(contradictory)
