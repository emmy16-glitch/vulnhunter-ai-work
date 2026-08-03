from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import pytest

from vulnhunter.web.assessment_projection import (
    assert_mobile_projection_invariants,
    mobile_assessment_projection,
)
from vulnhunter.web.mobile_conversation_state import remember_mobile_plan


class Session(dict):
    modified = False


_SURFACE_IDENTITY = {
    "chat": "assessment-one",
    "activity": "assessment-one",
    "inspector": "assessment-one",
    "history": "assessment-one",
    "findings": "assessment-one",
    "evidence": "assessment-one",
    "graph": "assessment-one",
    "reports": "assessment-one",
}


def _plan(*, execution_state: str = "queued") -> dict[str, object]:
    return {
        "run_id": "mobile-aabbccddeeff00112233",
        "plan_digest": "c" * 64,
        "profile": "static_and_native",
        "artifact": {
            "attachment_id": "attachment-aabbccddeeff00112233",
            "artifact_id": "apk-aabbccddeeff001122334455",
            "artifact_sha256": "d" * 64,
            "original_filename": "Digi Volt.apk",
        },
        "execution": {
            "state": execution_state,
            "job_id": "job-aabbccddeeff00112233",
            "progress": {
                "active_tool": "jadx",
                "events": [{"detail": "JADX started"}],
                "result_summary": {
                    "captures": [{"tool": "apkanalyzer"}],
                    "hunt": {"candidates": [{"title": "Candidate"}]},
                },
            },
        },
        "assessment_graph": {
            "graph_id": "mobile-aabbccddeeff00112233-graph",
            "workspace_id": "workspace-aabbccddeeff00112233",
            "assessment_kind": "apk",
            "authorization_id": "attachment-aabbccddeeff00112233",
            "chat_stage": "collecting_evidence",
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


def test_mobile_projection_exposes_one_id_for_every_assessment_surface():
    projection = mobile_assessment_projection(_plan())

    assert projection is not None
    assert projection["assessment_id"] == "mobile-aabbccddeeff00112233"
    assert projection["graph_id"] == "mobile-aabbccddeeff00112233-graph"
    assert projection["workspace_id"] == "workspace-aabbccddeeff00112233"
    assert projection["selected"] is True
    assert set(projection["surface_identity"]) == {
        "chat",
        "activity",
        "inspector",
        "history",
        "findings",
        "evidence",
        "graph",
        "reports",
    }
    assert set(projection["surface_identity"].values()) == {"mobile-aabbccddeeff00112233"}
    assert projection["subject"]["label"] == "Digi Volt.apk"
    assert projection["lifecycle"] == "collecting_evidence"
    assert projection["execution"]["state"] == "queued"
    assert projection["authority"]["approval_status"] == "completed"
    assert projection["stage_summary"] == {"total": 8, "completed": 3, "blocked": 0}
    assert projection["activity"] == {
        "event_count": 1,
        "tool_receipt_count": 1,
        "active_tool": "jadx",
    }
    assert projection["evidence"]["record_count"] == 1
    assert projection["findings"]["candidate_count"] == 1
    assert projection["report"] == {"status": "pending", "ready": False}
    assert projection["allowed_actions"] == [
        "view_activity",
        "view_evidence",
        "view_findings",
        "request_cancel",
    ]
    assert len(projection["stages"]) == 8


def test_failed_projection_does_not_invent_retry_or_report_readiness():
    projection = mobile_assessment_projection(_plan(execution_state="failed"))

    assert projection is not None
    assert projection["execution"]["terminal"] is True
    assert projection["allowed_actions"] == [
        "view_activity",
        "view_evidence",
        "view_findings",
    ]
    assert projection["report"]["ready"] is False


def test_incomplete_legacy_plan_does_not_invent_an_active_assessment():
    assert mobile_assessment_projection({"artifact": {"artifact_id": "apk-one"}}) is None


def test_projection_invariants_reject_subjectless_or_unbound_state():
    with pytest.raises(ValueError, match="assessment and graph identifiers"):
        assert_mobile_projection_invariants({"subject": {"label": "Digi Volt.apk"}})

    base = {
        "assessment_id": "assessment-one",
        "graph_id": "graph-one",
        "selected": True,
        "surface_identity": _SURFACE_IDENTITY,
        "subject": {"label": "Digi Volt.apk"},
        "execution": {"state": "queued"},
        "task_card": {
            "assessment_id": "assessment-one",
            "stage_progress": {"completed": 0, "total": 0},
            "byte_progress": {"received": None, "expected": None},
        },
        "report": {"status": "pending", "ready": False},
    }

    with pytest.raises(ValueError, match="selected assessment"):
        assert_mobile_projection_invariants({**base, "selected": False})

    with pytest.raises(ValueError, match="Every assessment surface"):
        assert_mobile_projection_invariants(
            {
                **base,
                "surface_identity": {**_SURFACE_IDENTITY, "history": "assessment-two"},
            }
        )

    with pytest.raises(ValueError, match="selected subject"):
        assert_mobile_projection_invariants({**base, "subject": {}})

    with pytest.raises(ValueError, match="execution state"):
        assert_mobile_projection_invariants({**base, "execution": {}})

    with pytest.raises(ValueError, match="Report readiness"):
        assert_mobile_projection_invariants(
            {**base, "report": {"status": "pending", "ready": True}}
        )


def test_remembered_mobile_plan_cannot_expose_artifact_without_selected_assessment(
    settings,
    tmp_path,
):
    settings.VULNHUNTER_TASK_GRAPH_ROOT = tmp_path / "graphs"
    workspace_id = uuid4()
    request = SimpleNamespace(
        session=Session(),
        user=SimpleNamespace(username="Mobile Operator"),
        vulnhunter_thread=SimpleNamespace(thread_id=workspace_id),
    )
    plan = {
        "run_id": "mobile-aabbccddeeff00112233",
        "plan_digest": "c" * 64,
        "profile": "static",
        "artifact": {
            "attachment_id": "attachment-aabbccddeeff00112233",
            "artifact_id": "apk-aabbccddeeff001122334455",
            "artifact_sha256": "d" * 64,
            "original_filename": "Digi Volt.apk",
        },
        "execution": {"state": "queued", "job_id": "job-aabbccddeeff00112233"},
    }

    remember_mobile_plan(request, plan)

    projection = plan["assessment"]
    assert projection["assessment_id"] == plan["run_id"]
    assert projection["workspace_id"] == str(workspace_id)
    assert projection["subject"]["artifact_id"] == plan["artifact"]["artifact_id"]
    assert set(projection["surface_identity"].values()) == {plan["run_id"]}
    assert request.session["vulnhunter_conversation_mobile_plan"]["assessment"] == projection
