from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from vulnhunter.assessment_graph import RemediationAssessmentGraphService

NOW = datetime(2026, 7, 31, 20, 15, tzinfo=UTC)


def _service(tmp_path):
    return RemediationAssessmentGraphService(tmp_path / "graphs", clock=lambda: NOW)


def _create(service, *, suffix: str, state: str = "ready_for_implementation"):
    remediation_id = "remediation-" + suffix * 32
    bundle = service.create(
        remediation_id=remediation_id,
        workspace_id=str(uuid4()),
        owner_id="developer-01",
        campaign_id="campaign-01",
        finding_id="finding-01",
        finding_fingerprint=suffix * 64,
        source_finding_revision=3,
        plan_sha256=suffix * 64,
        target_references=("app/users.py", "GET /users/{id}"),
        expires_at=NOW + timedelta(days=7),
        state=state,
    )
    return remediation_id, bundle


def test_remediation_graph_binds_exact_finding_plan_and_workspace(tmp_path):
    service = _service(tmp_path)
    remediation_id, bundle = _create(service, suffix="1")

    payload = service.status_payload(remediation_id)

    assert payload is not None
    assert payload["assessment_kind"] == "remediation"
    assert payload["workspace_id"] == str(bundle.workspace_id)
    assert payload["target_reference"] == "finding:finding-01"
    assert payload["chat_stage"] == "awaiting_developer_implementation"
    statuses = {item["stage"]: item["status"] for item in payload["nodes"]}
    assert statuses["authorization"] == "completed"
    assert statuses["plan"] == "completed"
    assert statuses["approval"] == "completed"
    assert statuses["execution"] == "ready"
    assert statuses["evidence"] == "pending"
    assert statuses["verification"] == "pending"
    assert all(manifest.parent_manifest_sha256 == "1" * 64 for manifest in bundle.manifests)
    execution_manifest = next(
        manifest
        for manifest in bundle.manifests
        if manifest.action == "finding.remediation.implement"
    )
    assert execution_manifest.approval_required is True
    assert execution_manifest.action_class.value == "consequential"
    assert execution_manifest.tool_id == "human-developer-workspace"


def test_remediation_cancellation_preserves_foundations_and_cancels_future_claims(tmp_path):
    service = _service(tmp_path)
    remediation_id, _bundle = _create(service, suffix="2")

    assert service.project_state(
        remediation_id,
        state="cancelled",
        reason="Owner withdrew the exact plan.",
    )
    payload = service.status_payload(remediation_id)

    assert payload is not None
    assert payload["chat_stage"] == "remediation_cancelled"
    statuses = {item["stage"]: item["status"] for item in payload["nodes"]}
    assert statuses["authorization"] == "completed"
    assert statuses["plan"] == "completed"
    assert statuses["approval"] == "completed"
    assert all(
        statuses[stage] == "cancelled"
        for stage in ("execution", "evidence", "verification", "review", "report")
    )


def test_remediation_failure_blocks_implementation_and_downstream_claims(tmp_path):
    service = _service(tmp_path)
    remediation_id, _bundle = _create(service, suffix="3")

    assert service.project_state(
        remediation_id,
        state="failed",
        reason="The plan could not be projected safely.",
    )
    payload = service.status_payload(remediation_id)

    assert payload is not None
    assert payload["chat_stage"] == "remediation_failed_safe"
    statuses = {item["stage"]: item["status"] for item in payload["nodes"]}
    assert statuses["execution"] == "blocked"
    assert all(
        statuses[stage] == "cancelled"
        for stage in ("evidence", "verification", "review", "report")
    )
