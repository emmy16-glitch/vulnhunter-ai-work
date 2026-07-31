from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from vulnhunter.assessment_graph import ActiveValidationAssessmentGraphService

NOW = datetime(2026, 7, 31, 19, 0, tzinfo=UTC)


def _service(tmp_path):
    return ActiveValidationAssessmentGraphService(tmp_path / "graphs", clock=lambda: NOW)


def _create(service, *, suffix: str, state: str = "awaiting_approval"):
    return service.create(
        run_id=f"lab_{suffix * 24}",
        workspace_id=str(uuid4()),
        owner_id="validation-operator",
        authorization_id=f"authorization-{suffix * 24}",
        assessment_id=f"assessment-{suffix * 24}",
        finding_reference=f"evidence-{suffix * 24}",
        target_reference="http://10.23.0.15:8080/",
        scenario_id="synthetic-file-impact",
        plan_digest=suffix * 64,
        expires_at=NOW + timedelta(hours=2),
        state=state,
    )


def test_active_validation_graph_binds_parent_finding_plan_and_workspace(tmp_path):
    service = _service(tmp_path)
    bundle = _create(service, suffix="1")

    payload = service.status_payload("lab_" + "1" * 24)

    assert payload is not None
    assert payload["assessment_kind"] == "active_validation"
    assert payload["workspace_id"] == str(bundle.workspace_id)
    assert payload["chat_stage"] == "awaiting_independent_approval"
    assert bundle.target_reference == f"active-validation:evidence-{'1' * 24}"
    assert len(payload["nodes"]) == 8
    statuses = {item["stage"]: item["status"] for item in payload["nodes"]}
    assert statuses["authorization"] == "completed"
    assert statuses["plan"] == "completed"
    assert statuses["approval"] == "waiting_for_human_approval"
    assert statuses["execution"] == "pending"
    assert all(manifest.parent_manifest_sha256 == "1" * 64 for manifest in bundle.manifests)


def test_active_validation_projects_approval_queue_worker_evaluation_and_review(tmp_path):
    service = _service(tmp_path)
    _create(service, suffix="2")
    run_id = "lab_" + "2" * 24

    assert service.project_state(run_id, state="approved")
    approved = service.status_payload(run_id)
    assert approved is not None
    assert approved["chat_stage"] == "ready_to_queue"

    assert service.project_state(run_id, state="queued")
    queued = service.status_payload(run_id)
    assert queued is not None
    assert queued["chat_stage"] == "queued_for_validation"

    assert service.project_state(run_id, state="running")
    running = service.status_payload(run_id)
    assert running is not None
    assert running["chat_stage"] == "running_validation_trials"

    assert service.project_state(run_id, state="evaluating")
    evaluating = service.status_payload(run_id)
    assert evaluating is not None
    assert evaluating["chat_stage"] == "evaluating_validation_evidence"

    assert service.project_state(run_id, state="completed")
    completed = service.status_payload(run_id)
    assert completed is not None
    assert completed["chat_stage"] == "awaiting_human_review"
    statuses = {item["stage"]: item["status"] for item in completed["nodes"]}
    assert statuses["execution"] == "completed"
    assert statuses["evidence"] == "completed"
    assert statuses["verification"] == "completed"
    assert statuses["review"] == "ready"
    assert statuses["report"] == "pending"


def test_active_validation_cancellation_preserves_completed_foundations(tmp_path):
    service = _service(tmp_path)
    _create(service, suffix="3")
    run_id = "lab_" + "3" * 24

    assert service.project_state(run_id, state="cancelled", reason="Operator stopped the run.")
    payload = service.status_payload(run_id)

    assert payload is not None
    statuses = {item["stage"]: item["status"] for item in payload["nodes"]}
    assert statuses["authorization"] == "completed"
    assert statuses["plan"] == "completed"
    assert all(
        statuses[stage] == "cancelled"
        for stage in ("approval", "execution", "evidence", "verification", "review", "report")
    )


def test_active_validation_failure_cancels_untrusted_downstream_claims(tmp_path):
    service = _service(tmp_path)
    _create(service, suffix="4")
    run_id = "lab_" + "4" * 24
    service.project_state(run_id, state="approved")
    service.project_state(run_id, state="queued")
    service.project_state(run_id, state="running")

    assert service.project_state(
        run_id,
        state="failed",
        reason="The isolated worker failed safely.",
    )
    payload = service.status_payload(run_id)

    assert payload is not None
    statuses = {item["stage"]: item["status"] for item in payload["nodes"]}
    assert statuses["execution"] == "failed"
    assert all(
        statuses[stage] == "cancelled"
        for stage in ("evidence", "verification", "review", "report")
    )
