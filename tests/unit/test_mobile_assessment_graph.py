from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

from vulnhunter.assessment_graph import MobileAssessmentGraphService
from vulnhunter.web.mobile_conversation_state import current_mobile_plan, remember_mobile_plan

NOW = datetime(2026, 7, 31, 17, 30, tzinfo=UTC)


class Session(dict):
    modified = False


def _service(tmp_path):
    return MobileAssessmentGraphService(tmp_path / "graphs", clock=lambda: NOW)


def _create(service, *, run_id: str, state: str):
    return service.create(
        run_id=run_id,
        workspace_id=str(uuid4()),
        owner_id="mobile-operator",
        authorization_id="attachment-aabbccddeeff00112233",
        artifact_id="apk-aabbccddeeff001122334455",
        artifact_sha256="a" * 64,
        expires_at=NOW + timedelta(hours=2),
        profile="static",
        plan_digest="b" * 64,
        execution_state=state,
        execution_reason=("Worker disabled." if state == "gated" else None),
    )


def test_apk_graph_is_bound_to_artifact_plan_and_workspace(tmp_path):
    service = _service(tmp_path)
    bundle = _create(service, run_id="mobile-authoritative-one", state="queued")

    payload = service.status_payload("mobile-authoritative-one")

    assert payload is not None
    assert payload["assessment_kind"] == "apk"
    assert payload["workspace_id"] == str(bundle.workspace_id)
    assert payload["chat_stage"] == "collecting_evidence"
    assert len(payload["nodes"]) == 8
    assert payload["nodes"][0]["status"] == "completed"
    assert payload["nodes"][3]["status"] == "running"
    assert bundle.target_reference == f"apk-sha256:{'a' * 64}"
    assert all(manifest.parent_manifest_sha256 == "b" * 64 for manifest in bundle.manifests)


def test_completed_worker_projects_evidence_and_waits_for_verification(tmp_path):
    service = _service(tmp_path)
    _create(service, run_id="mobile-authoritative-two", state="queued")

    assert service.project_execution("mobile-authoritative-two", state="completed")
    payload = service.status_payload("mobile-authoritative-two")

    assert payload is not None
    assert payload["chat_stage"] == "awaiting_verification"
    statuses = {item["stage"]: item["status"] for item in payload["nodes"]}
    assert statuses["execution"] == "completed"
    assert statuses["evidence"] == "completed"
    assert statuses["verification"] == "ready"
    assert statuses["review"] == "pending"


def test_gated_worker_blocks_execution_and_cancels_downstream(tmp_path):
    service = _service(tmp_path)
    _create(service, run_id="mobile-authoritative-three", state="gated")

    payload = service.status_payload("mobile-authoritative-three")

    assert payload is not None
    assert payload["chat_stage"] == "blocked"
    statuses = {item["stage"]: item["status"] for item in payload["nodes"]}
    assert statuses["authorization"] == "completed"
    assert statuses["plan"] == "completed"
    assert statuses["approval"] == "completed"
    assert statuses["execution"] == "blocked"
    assert all(
        statuses[stage] == "cancelled"
        for stage in ("evidence", "verification", "review", "report")
    )


def test_remembered_mobile_plan_mutates_into_durable_graph_projection(settings, tmp_path):
    settings.VULNHUNTER_TASK_GRAPH_ROOT = tmp_path / "graphs"
    workspace_id = uuid4()
    request = SimpleNamespace(
        session=Session(),
        user=SimpleNamespace(username="Mobile Operator"),
        vulnhunter_thread=SimpleNamespace(thread_id=workspace_id),
    )
    plan = {
        "plan_id": "analysis-aabbccddeeff00112233",
        "run_id": "mobile-aabbccddeeff00112233",
        "task_graph_id": "analysis-aabbccddeeff00112233-graph",
        "plan_digest": "c" * 64,
        "profile": "static",
        "artifact": {
            "attachment_id": "attachment-aabbccddeeff00112233",
            "artifact_id": "apk-aabbccddeeff001122334455",
            "artifact_sha256": "d" * 64,
        },
        "execution": {"state": "queued", "job_id": "job-aabbccddeeff00112233"},
    }

    remember_mobile_plan(request, plan)

    graph = plan["assessment_graph"]
    assert isinstance(graph, dict)
    assert graph["workspace_id"] == str(workspace_id)
    assert graph["assessment_kind"] == "apk"
    assert graph["chat_stage"] == "collecting_evidence"
    assert plan["tool_task_graph_id"] == "analysis-aabbccddeeff00112233-graph"
    assert plan["task_graph_id"] == "mobile-aabbccddeeff00112233-graph"
    assert request.session["vulnhunter_conversation_mobile_plan"] == plan

    stored = dict(plan)
    stored["execution"] = {"state": "completed"}
    request.session["vulnhunter_conversation_mobile_plan"] = stored
    refreshed = current_mobile_plan(request, requested_by="mobile-operator")

    assert refreshed is not None
    assert refreshed["assessment_graph"]["chat_stage"] == "awaiting_verification"
