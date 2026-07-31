from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from vulnhunter.assessment_graph import RemediationAssessmentGraphService

NOW = datetime(2026, 7, 31, 21, 45, tzinfo=UTC)


def _service(tmp_path):
    return RemediationAssessmentGraphService(tmp_path / "graphs", clock=lambda: NOW)


def _create(service):
    remediation_id = "remediation-" + "a" * 32
    service.create(
        remediation_id=remediation_id,
        workspace_id=str(uuid4()),
        owner_id="developer-01",
        campaign_id="campaign-01",
        finding_id="finding-01",
        finding_fingerprint="b" * 64,
        source_finding_revision=1,
        plan_sha256="c" * 64,
        target_references=("app/users.py",),
        expires_at=NOW + timedelta(days=7),
        state="ready_for_implementation",
    )
    return remediation_id


def _nodes(payload):
    return {item["stage"]: item for item in payload["nodes"]}


def test_non_fixed_verification_returns_bounded_stages_to_rework(tmp_path):
    service = _service(tmp_path)
    remediation_id = _create(service)

    assert service.project_fix_verification(
        remediation_id,
        receipt_id="fix-verification-" + "d" * 24,
        verdict="not_fixed",
    )
    payload = service.status_payload(remediation_id)

    assert payload is not None
    assert payload["chat_stage"] == "fix_verification_requires_rework"
    nodes = _nodes(payload)
    for stage in ("execution", "evidence", "verification"):
        assert nodes[stage]["status"] == "ready"
        assert nodes[stage]["attempts"] == 1
        assert "not_fixed" in str(nodes[stage]["last_error"])
    assert nodes["review"]["status"] == "pending"


def test_same_receipt_projection_is_idempotent(tmp_path):
    service = _service(tmp_path)
    remediation_id = _create(service)
    receipt_id = "fix-verification-" + "e" * 24

    service.project_fix_verification(
        remediation_id,
        receipt_id=receipt_id,
        verdict="regression_detected",
    )
    first = service.status_payload(remediation_id)
    service.project_fix_verification(
        remediation_id,
        receipt_id=receipt_id,
        verdict="regression_detected",
    )
    second = service.status_payload(remediation_id)

    assert first == second


def test_later_fixed_receipt_completes_verification_and_opens_retest_boundary(tmp_path):
    service = _service(tmp_path)
    remediation_id = _create(service)

    service.project_fix_verification(
        remediation_id,
        receipt_id="fix-verification-" + "f" * 24,
        verdict="partially_fixed",
    )
    assert service.project_fix_verification(
        remediation_id,
        receipt_id="fix-verification-" + "1" * 24,
        verdict="fixed",
    )
    payload = service.status_payload(remediation_id)

    assert payload is not None
    assert payload["chat_stage"] == "fix_verified_awaiting_retest"
    nodes = _nodes(payload)
    for stage in ("execution", "evidence", "verification"):
        assert nodes[stage]["status"] == "completed"
        assert nodes[stage]["attempts"] == 2
    assert nodes["review"]["status"] == "ready"
    assert nodes["report"]["status"] == "pending"
