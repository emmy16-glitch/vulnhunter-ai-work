from pathlib import Path

from vulnhunter.web.conversation_state import enrich_run_payload
from vulnhunter.web.website_assessment_projection import (
    assert_website_projection_invariants,
    website_assessment_projection,
)


def _payload(*, state: str = "running") -> dict[str, object]:
    return {
        "run_id": "assessment-1",
        "state": state,
        "target": "http://192.168.1.25:8080/app",
        "profile": "passive",
        "scanner": "nuclei",
        "approval_state": "approved",
        "created_at": "2026-08-04T07:00:00+00:00",
        "updated_at": "2026-08-04T07:02:00+00:00",
        "terminal": state in {"completed", "failed"},
        "blocking_reason": "Worker unavailable." if state == "failed" else None,
        "findings": [{"finding_id": "finding-1"}],
        "artifacts": [{"filename": "receipt.json"}],
        "task_graph": {
            "graph_id": "graph-1",
            "workspace_id": "workspace-1",
            "authorization_id": "authorization-1",
            "chat_stage": "analysis_running",
            "nodes": [
                {"stage": "scope", "status": "completed"},
                {"stage": "approval", "status": "completed"},
                {"stage": "scanner", "status": state},
                {"stage": "verification", "status": "pending"},
            ],
        },
    }


def test_website_projection_binds_every_surface_and_graph_authorization():
    projection = website_assessment_projection(_payload())
    assert projection is not None
    assert projection["assessment_id"] == "assessment-1"
    assert projection["assessment_kind"] == "website"
    assert set(projection["surface_identity"].values()) == {"assessment-1"}
    assert projection["authority"]["authorization_id"] == "authorization-1"
    assert projection["subject"]["target"] == "http://192.168.1.25:8080/app"
    assert projection["task_card"]["assessment_id"] == "assessment-1"


def test_website_projection_uses_persisted_stage_activity_and_result_counts():
    payload = _payload()
    payload["events"] = [
        {"event_type": "scanner_started", "summary": "Scanner started."},
        {"event_type": "scanner_progress", "summary": "Receipt persisted."},
    ]
    projection = website_assessment_projection(payload)
    assert projection is not None
    assert projection["stage_summary"] == {"total": 4, "completed": 2, "blocked": 0}
    assert projection["task_card"]["stage_progress"] == {"completed": 2, "total": 4}
    assert projection["task_card"]["activity"]["event_count"] == 2
    assert projection["evidence"] == {"record_count": 1}
    assert projection["findings"] == {"candidate_count": 1}
    assert projection["report"] == {
        "status": "not_available",
        "ready": False,
        "report_id": None,
    }


def test_website_failure_preserves_state_and_never_invents_retry():
    projection = website_assessment_projection(_payload(state="failed"))
    assert projection is not None
    assert projection["health"] == {
        "assessment": "attention_required",
        "worker": "blocked",
        "provider": "not_evaluated",
    }
    assert projection["execution"]["failure"]["preserved"] == [
        "authorization",
        "assessment_graph",
        "activity_receipts",
        "evidence",
    ]
    assert projection["task_card"]["retry"] == {
        "available": False,
        "scope": None,
        "user_action": None,
    }
    assert "request_retry" not in projection["allowed_actions"]


def test_website_projection_fails_closed_without_graph_authority():
    payload = _payload()
    payload["task_graph"] = {"graph_id": "graph-1", "nodes": []}
    assert website_assessment_projection(payload) is None


def test_website_projection_rejects_cross_surface_identity():
    projection = website_assessment_projection(_payload())
    assert projection is not None
    projection["surface_identity"]["reports"] = "another-assessment"
    try:
        assert_website_projection_invariants(projection)
    except ValueError as exc:
        assert "Every website surface" in str(exc)
    else:
        raise AssertionError("Cross-assessment website identity must fail closed.")


def test_enriched_website_run_uses_persisted_stages_and_no_percentage():
    enriched = enrich_run_payload(
        _payload(),
        raw_events=[{"event_type": "scanner_progress", "summary": "Receipt persisted."}],
        template_count=2,
    )
    assert enriched["progress_label"] == "2 of 4 persisted stages complete"
    assert "progress_percent" not in enriched
    assert enriched["assessment_projection"]["assessment_id"] == "assessment-1"


def test_source_contains_no_browser_mapped_percentage_contract():
    source = (
        Path(__file__).resolve().parents[2]
        / "vulnhunter"
        / "web"
        / "conversation_state.py"
    ).read_text(encoding="utf-8")
    assert 'result["progress_percent"] = round' not in source
    assert 'result.pop("progress_percent", None)' in source
    assert "_persisted_stage_progress" in source
