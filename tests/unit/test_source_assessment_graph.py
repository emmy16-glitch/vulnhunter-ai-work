from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from vulnhunter.assessment_graph import SourceAssessmentGraphService

NOW = datetime(2026, 7, 31, 18, 30, tzinfo=UTC)


def _service(tmp_path):
    return SourceAssessmentGraphService(tmp_path / "graphs", clock=lambda: NOW)


def _create(service, *, suffix: str, state: str = "queued"):
    return service.create(
        run_id=f"source-job-{suffix * 32}",
        workspace_id=str(uuid4()),
        owner_id="source-operator",
        authorization_id=f"source-approval-{suffix * 24}",
        repository_id=f"repository-{suffix * 12}",
        revision=suffix * 40,
        snapshot_sha256=suffix * 64,
        approval_sha256=("a" if suffix != "a" else "b") * 64,
        plan_digest=("c" if suffix != "c" else "d") * 64,
        expires_at=NOW + timedelta(hours=1),
        model="openai/gpt-oss-120b",
        execution_state=state,
        execution_reason=("Provider unavailable." if state == "failed" else None),
    )


def test_source_graph_binds_workspace_snapshot_approval_and_plan(tmp_path):
    service = _service(tmp_path)
    bundle = _create(service, suffix="1")

    payload = service.status_payload("source-job-" + "1" * 32)

    assert payload is not None
    assert payload["assessment_kind"] == "source"
    assert payload["workspace_id"] == str(bundle.workspace_id)
    assert payload["chat_stage"] == "queued_for_analysis"
    assert bundle.target_reference == f"source-snapshot:{'1' * 64}"
    assert len(payload["nodes"]) == 8
    statuses = {item["stage"]: item["status"] for item in payload["nodes"]}
    assert statuses["authorization"] == "completed"
    assert statuses["plan"] == "completed"
    assert statuses["approval"] == "completed"
    assert statuses["execution"] == "pending"
    assert all(manifest.parent_manifest_sha256 == "c" * 64 for manifest in bundle.manifests)


def test_source_worker_running_projects_collecting_evidence(tmp_path):
    service = _service(tmp_path)
    _create(service, suffix="2")
    run_id = "source-job-" + "2" * 32

    assert service.project_execution(run_id, state="running")
    payload = service.status_payload(run_id)

    assert payload is not None
    assert payload["chat_stage"] == "collecting_evidence"
    statuses = {item["stage"]: item["status"] for item in payload["nodes"]}
    assert statuses["execution"] == "running"
    assert statuses["evidence"] == "pending"


def test_source_worker_completion_waits_for_independent_verification(tmp_path):
    service = _service(tmp_path)
    _create(service, suffix="3")
    run_id = "source-job-" + "3" * 32

    assert service.project_execution(run_id, state="completed")
    payload = service.status_payload(run_id)

    assert payload is not None
    assert payload["chat_stage"] == "awaiting_verification"
    statuses = {item["stage"]: item["status"] for item in payload["nodes"]}
    assert statuses["execution"] == "completed"
    assert statuses["evidence"] == "completed"
    assert statuses["verification"] == "ready"
    assert statuses["review"] == "pending"
    assert statuses["report"] == "pending"


def test_source_worker_failure_cancels_untrusted_downstream_claims(tmp_path):
    service = _service(tmp_path)
    _create(service, suffix="4")
    run_id = "source-job-" + "4" * 32

    assert service.project_execution(
        run_id,
        state="failed",
        reason="The provider response failed validation.",
    )
    payload = service.status_payload(run_id)

    assert payload is not None
    assert payload["chat_stage"] == "failed_safely"
    statuses = {item["stage"]: item["status"] for item in payload["nodes"]}
    assert statuses["execution"] == "failed"
    assert all(
        statuses[stage] == "cancelled"
        for stage in ("evidence", "verification", "review", "report")
    )
