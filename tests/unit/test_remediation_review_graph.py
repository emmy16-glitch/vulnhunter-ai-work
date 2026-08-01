from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from vulnhunter.assessment_graph import RemediationAssessmentGraphService

NOW = datetime(2026, 8, 1, 7, 15, tzinfo=UTC)


def _service(tmp_path):
    return RemediationAssessmentGraphService(tmp_path / "graphs", clock=lambda: NOW)


def _ready_for_review(service):
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
        state="awaiting_review",
    )
    return remediation_id


def _nodes(payload):
    return {item["stage"]: item for item in payload["nodes"]}


def test_approved_review_completes_review_and_only_opens_report_readiness(tmp_path):
    service = _service(tmp_path)
    remediation_id = _ready_for_review(service)

    assert service.project_review_decision(
        remediation_id,
        receipt_id="remediation-review-" + "d" * 24,
        outcome="approved",
    )
    payload = service.status_payload(remediation_id)

    assert payload is not None
    assert payload["chat_stage"] == "remediation_review_approved_ready_for_report"
    assert payload["report_state"] == "ready_for_generation"
    nodes = _nodes(payload)
    assert nodes["review"]["status"] == "completed"
    assert nodes["report"]["status"] == "ready"


def test_changes_requested_returns_review_to_bounded_ready_state(tmp_path):
    service = _service(tmp_path)
    remediation_id = _ready_for_review(service)

    service.project_review_decision(
        remediation_id,
        receipt_id="remediation-review-" + "e" * 24,
        outcome="changes_requested",
        reason="Approved scope was not respected.",
    )
    payload = service.status_payload(remediation_id)

    assert payload is not None
    assert payload["chat_stage"] == "remediation_review_requires_rework"
    assert payload["report_state"] == "blocked_review_rework"
    nodes = _nodes(payload)
    assert nodes["review"]["status"] == "ready"
    assert nodes["report"]["status"] == "pending"


def test_cannot_verify_keeps_report_blocked_without_false_failure_claim(tmp_path):
    service = _service(tmp_path)
    remediation_id = _ready_for_review(service)

    service.project_review_decision(
        remediation_id,
        receipt_id="remediation-review-" + "f" * 24,
        outcome="cannot_verify",
        reason="Broader regression evidence is incomplete.",
    )
    payload = service.status_payload(remediation_id)

    assert payload is not None
    assert payload["chat_stage"] == "remediation_review_cannot_verify"
    assert payload["report_state"] == "blocked_review_uncertain"
    nodes = _nodes(payload)
    assert nodes["review"]["status"] == "ready"
    assert nodes["report"]["status"] == "pending"


def test_later_retest_pass_clears_prior_review_rework_marker(tmp_path):
    service = _service(tmp_path)
    remediation_id = _ready_for_review(service)
    service.project_review_decision(
        remediation_id,
        receipt_id="remediation-review-" + "1" * 24,
        outcome="changes_requested",
        reason="The first revision exceeded scope.",
    )

    service.project_retest_outcome(
        remediation_id,
        receipt_id="retest-receipt-" + "2" * 24,
        outcome="passed",
    )
    payload = service.status_payload(remediation_id)

    assert payload is not None
    assert payload["chat_stage"] == "retest_passed_awaiting_independent_review"
    assert payload["report_state"] == "blocked_pending_independent_review"
    assert _nodes(payload)["review"]["status"] == "ready"
    assert _nodes(payload)["review"]["last_error"] is None


def test_same_review_receipt_projection_is_idempotent(tmp_path):
    service = _service(tmp_path)
    remediation_id = _ready_for_review(service)
    receipt_id = "remediation-review-" + "3" * 24

    service.project_review_decision(
        remediation_id,
        receipt_id=receipt_id,
        outcome="approved",
    )
    first = service.status_payload(remediation_id)
    service.project_review_decision(
        remediation_id,
        receipt_id=receipt_id,
        outcome="approved",
    )
    second = service.status_payload(remediation_id)

    assert first == second
