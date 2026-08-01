from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from vulnhunter.assessment_graph import AssessmentGraphError, RemediationAssessmentGraphService

NOW = datetime(2026, 8, 1, 9, 45, tzinfo=UTC)


def _service(tmp_path):
    return RemediationAssessmentGraphService(tmp_path / "graphs", clock=lambda: NOW)


def _ready_for_report(service):
    remediation_id = "remediation-" + "a" * 32
    service.create(
        remediation_id=remediation_id,
        workspace_id=str(uuid4()),
        owner_id="developer-owner",
        campaign_id="campaign-01",
        finding_id="finding-01",
        finding_fingerprint="b" * 64,
        source_finding_revision=1,
        plan_sha256="c" * 64,
        target_references=("app/users.py",),
        expires_at=NOW + timedelta(days=7),
        state="review_approved",
    )
    return remediation_id


def _nodes(payload):
    return {item["stage"]: item for item in payload["nodes"]}


def test_passed_retest_replay_is_idempotent_after_review_completion(tmp_path):
    service = _service(tmp_path)
    remediation_id = _ready_for_report(service)
    before = service.status_payload(remediation_id)

    assert service.project_retest_outcome(
        remediation_id,
        receipt_id="retest-receipt-" + "9" * 24,
        outcome="passed",
    )

    assert service.status_payload(remediation_id) == before


def test_report_generation_completes_only_report_stage(tmp_path):
    service = _service(tmp_path)
    remediation_id = _ready_for_report(service)

    assert service.project_report_generation(
        remediation_id,
        report_id="final-report-" + "d" * 24,
        manifest_id="report-manifest-" + "e" * 24,
    )
    payload = service.status_payload(remediation_id)

    assert payload is not None
    assert payload["chat_stage"] == "final_report_generated_awaiting_release"
    assert payload["report_state"] == "generated_unreleased"
    nodes = _nodes(payload)
    assert nodes["review"]["status"] == "completed"
    assert nodes["report"]["status"] == "completed"
    assert "report-manifest-" in nodes["report"]["last_error"]


def test_same_report_projection_is_idempotent(tmp_path):
    service = _service(tmp_path)
    remediation_id = _ready_for_report(service)
    report_id = "final-report-" + "f" * 24
    manifest_id = "report-manifest-" + "1" * 24

    service.project_report_generation(
        remediation_id,
        report_id=report_id,
        manifest_id=manifest_id,
    )
    first = service.status_payload(remediation_id)
    service.project_report_generation(
        remediation_id,
        report_id=report_id,
        manifest_id=manifest_id,
    )
    second = service.status_payload(remediation_id)

    assert first == second


def test_report_stage_rejects_a_different_manifest_after_completion(tmp_path):
    service = _service(tmp_path)
    remediation_id = _ready_for_report(service)
    service.project_report_generation(
        remediation_id,
        report_id="final-report-" + "2" * 24,
        manifest_id="report-manifest-" + "3" * 24,
    )

    with pytest.raises(AssessmentGraphError, match="different final report"):
        service.project_report_generation(
            remediation_id,
            report_id="final-report-" + "4" * 24,
            manifest_id="report-manifest-" + "5" * 24,
        )
