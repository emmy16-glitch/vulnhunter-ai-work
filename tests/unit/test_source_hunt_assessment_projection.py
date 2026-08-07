from vulnhunter.web.source_hunt_assessment_projection import (
    assert_source_hunt_projection_invariants,
    source_hunt_assessment_projection,
)


def _plan(*, state: str = "running", report: dict[str, object] | None = None):
    return {
        "job_id": "source-job-1",
        "run_id": "source-job-1",
        "task_graph_id": "source-graph-1",
        "repository": {
            "repository_id": "repo-1",
            "revision": "abc123",
            "snapshot_sha256": "a" * 64,
            "file_count": 12,
            "total_bytes": 4096,
            "visibility": "private",
            "permitted_paths": ["src", "tests"],
        },
        "approval": {
            "approval_id": "approval-1",
            "approval_sha256": "b" * 64,
            "expires_at": "2026-08-04T09:00:00+00:00",
        },
        "execution": {
            "state": state,
            "safe_error": "Provider unavailable." if state in {"failed", "unavailable"} else None,
            "created_at": "2026-08-04T07:00:00+00:00",
            "started_at": "2026-08-04T07:01:00+00:00",
            "completed_at": "2026-08-04T07:02:00+00:00" if state == "completed" else None,
        },
        "report": report,
        "assessment_graph": {
            "graph_id": "source-graph-1",
            "revision": 5,
            "workspace_id": "workspace-1",
            "chat_stage": "analysis_running",
            "nodes": [
                {"stage": "request", "status": "completed"},
                {"stage": "approval", "status": "completed"},
                {"stage": "analysis", "status": state},
                {"stage": "report", "status": "completed" if report else "pending"},
            ],
        },
    }


def test_source_hunt_projection_binds_every_surface_to_one_assessment():
    projection = source_hunt_assessment_projection(_plan())
    assert projection is not None
    assert projection["assessment_id"] == "source-job-1"
    assert projection["assessment_kind"] == "source_hunt"
    assert projection["projection_contract"] == "selected-assessment/v1"
    assert projection["projection_revision"] == 5
    assert set(projection["surface_identity"].values()) == {"source-job-1"}
    assert set(projection["result_identity"].values()) == {"source-job-1"}
    assert projection["subject"] == {
        "kind": "repository_snapshot",
        "label": "repo-1@abc123",
        "repository_id": "repo-1",
        "revision": "abc123",
        "sha256": "a" * 64,
        "visibility": "private",
        "permitted_paths": ["src", "tests"],
    }
    assert projection["task_card"]["assessment_id"] == "source-job-1"
    assert projection["task_card"]["activity_timeline_id"] == "source-graph-1"
    assert projection["task_card"]["progress"] == {
        "measurement": "stage",
        "completed": 2,
        "total": 4,
        "stage": "analysis",
    }
    assert projection["task_card"]["byte_progress"] == {
        "received": 4096,
        "expected": 4096,
    }


def test_source_hunt_projection_uses_persisted_report_counts_and_abstention():
    projection = source_hunt_assessment_projection(
        _plan(
            state="completed",
            report={
                "report_id": "report-1",
                "stage": "completed",
                "surfaces_examined": 8,
                "candidate_count": 3,
                "rejected_count": 2,
                "abstained_count": 1,
            },
        )
    )
    assert projection is not None
    assert projection["evidence"] == {"record_count": 8}
    assert projection["findings"] == {
        "candidate_count": 3,
        "rejected_count": 2,
        "abstained_count": 1,
    }
    assert {key: value for key, value in projection["report"].items() if key != "formats"} == {
        "status": "completed",
        "ready": True,
        "report_id": "report-1",
    }
    assert projection["report"]["formats"]["html"]["status"] == "available"
    assert "view_report" in projection["allowed_actions"]


def test_source_hunt_failure_preserves_authority_and_never_invents_retry():
    projection = source_hunt_assessment_projection(_plan(state="failed"))
    assert projection is not None
    assert projection["health"] == {
        "assessment": "attention_required",
        "worker": "blocked",
        "provider": "not_evaluated",
    }
    assert projection["execution"]["failure"]["preserved"] == [
        "repository_snapshot",
        "remote_processing_approval",
        "assessment_graph",
    ]
    assert projection["task_card"]["failure"] == projection["execution"]["failure"]
    assert projection["task_card"]["retry"] == {
        "available": False,
        "scope": None,
        "user_action": None,
    }
    assert "request_retry" not in projection["allowed_actions"]


def test_source_hunt_unavailable_maps_to_blocked_without_hiding_worker_health():
    projection = source_hunt_assessment_projection(_plan(state="unavailable"))
    assert projection is not None
    assert projection["execution"]["state"] == "blocked"
    assert projection["task_card"]["state"] == "blocked"
    assert projection["health"] == {
        "assessment": "attention_required",
        "worker": "unavailable",
        "provider": "not_evaluated",
    }


def test_source_hunt_projection_fails_closed_without_exact_snapshot_identity():
    plan = _plan()
    plan["repository"] = {"repository_id": "repo-1", "revision": "abc123"}
    assert source_hunt_assessment_projection(plan) is None


def test_source_hunt_projection_fails_closed_without_persisted_revision():
    plan = _plan()
    plan["assessment_graph"].pop("revision")
    assert source_hunt_assessment_projection(plan) is None


def test_source_hunt_projection_rejects_cross_surface_identity():
    projection = source_hunt_assessment_projection(_plan())
    assert projection is not None
    projection["surface_identity"]["reports"] = "another-assessment"
    try:
        assert_source_hunt_projection_invariants(projection)
    except ValueError as exc:
        assert "Every Source Hunt surface" in str(exc)
    else:
        raise AssertionError("Cross-assessment surface identity must fail closed.")
