from __future__ import annotations

from copy import deepcopy

import pytest

from vulnhunter.web.assessment_projection import (
    assert_mobile_projection_invariants,
    mobile_assessment_projection,
)


def _plan() -> dict[str, object]:
    return {
        "run_id": "mobile-task-one",
        "plan_digest": "a" * 64,
        "profile": "static",
        "artifact": {
            "attachment_id": "attachment-one",
            "artifact_id": "apk-one",
            "artifact_sha256": "b" * 64,
            "original_filename": "Sample.apk",
        },
        "execution": {
            "state": "running",
            "job_id": "job-one",
            "progress": {
                "received_bytes": 24,
                "expected_bytes": 100,
                "active_tool": "apktool",
                "events": [
                    {"stage": "queue", "status": "completed"},
                    {"stage": "execution", "status": "running"},
                ],
                "result_summary": {
                    "captures": [{"tool_id": "apksigner"}],
                    "hunt": {"candidates": [{"title": "Candidate one"}]},
                },
            },
        },
        "assessment_graph": {
            "graph_id": "mobile-task-one-graph",
            "workspace_id": "workspace-one",
            "assessment_kind": "apk",
            "authorization_id": "attachment-one",
            "chat_stage": "executing",
            "nodes": [
                {"stage": "authorization", "status": "completed"},
                {"stage": "plan", "status": "completed"},
                {"stage": "approval", "status": "completed"},
                {"stage": "execution", "status": "running"},
                {"stage": "evidence", "status": "pending"},
                {"stage": "verification", "status": "pending"},
                {"stage": "review", "status": "pending"},
                {"stage": "report", "status": "pending"},
            ],
        },
    }


def test_task_card_uses_persisted_stage_byte_and_activity_records():
    projection = mobile_assessment_projection(_plan())

    assert projection is not None
    task = projection["task_card"]
    assert task == {
        "task_id": "mobile-task-one:mobile-assessment",
        "assessment_id": "mobile-task-one",
        "state": "running",
        "terminal": False,
        "current_stage": {"stage": "execution", "status": "running"},
        "stage_progress": {"completed": 3, "total": 8},
        "byte_progress": {"received": 24, "expected": 100},
        "activity": {
            "event_count": 2,
            "receipt_count": 1,
            "candidate_count": 1,
            "latest_event": {"stage": "execution", "status": "running"},
        },
        "failure": None,
    }
    assert "percent" not in str(task).casefold()


def test_task_card_clamps_measured_bytes_to_declared_total():
    plan = _plan()
    plan["execution"]["progress"]["received_bytes"] = 120

    projection = mobile_assessment_projection(plan)

    assert projection is not None
    assert projection["task_card"]["byte_progress"] == {
        "received": 100,
        "expected": 100,
    }


def test_task_card_survives_failure_with_preserved_contract():
    plan = _plan()
    plan["execution"] = {
        "state": "failed",
        "failure": {
            "category": "storage_failure",
            "stage": "worker_status",
            "reason_code": "status_worker_spool_error",
            "reference": "vh-mobile-0123456789ab",
            "message": "The latest worker status could not be verified safely.",
            "safe_retry": True,
            "retry_scope": "worker_status",
            "preserved": ["artifact", "assessment", "previous_receipts"],
        },
    }
    plan["assessment_graph"]["nodes"][3]["status"] = "failed"

    projection = mobile_assessment_projection(plan)

    assert projection is not None
    task = projection["task_card"]
    assert task["terminal"] is True
    assert task["current_stage"] == {"stage": "execution", "status": "failed"}
    assert task["failure"]["retry_scope"] == "worker_status"
    assert task["failure"]["preserved"] == [
        "artifact",
        "assessment",
        "previous_receipts",
    ]


def test_task_card_invariant_rejects_foreign_assessment_identity():
    projection = mobile_assessment_projection(_plan())
    assert projection is not None
    contradictory = deepcopy(projection)
    contradictory["task_card"]["assessment_id"] = "another-assessment"

    with pytest.raises(ValueError, match="task card must bind"):
        assert_mobile_projection_invariants(contradictory)
