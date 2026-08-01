from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from vulnhunter.assessment_graph import RetestAssessmentGraphService

NOW = datetime(2026, 8, 1, 6, 45, tzinfo=UTC)


def _service(tmp_path):
    return RetestAssessmentGraphService(tmp_path / "graphs", clock=lambda: NOW)


def _create(service):
    retest_id = "retest-" + "a" * 32
    service.create(
        retest_id=retest_id,
        workspace_id=str(uuid4()),
        owner_id="retest-operator",
        campaign_id="campaign-01",
        finding_id="finding-01",
        finding_fingerprint="b" * 64,
        source_finding_revision=3,
        remediation_id="remediation-" + "c" * 32,
        fix_verification_receipt_id="fix-verification-" + "d" * 24,
        fixed_revision="e" * 40,
        plan_sha256="f" * 64,
        check_references=("GET /users/{id} as another authorised test identity",),
        expires_at=NOW + timedelta(days=2),
    )
    return retest_id


def _nodes(payload):
    return {item["stage"]: item for item in payload["nodes"]}


def test_new_retest_graph_is_ready_without_claiming_evidence_or_review(tmp_path):
    service = _service(tmp_path)
    retest_id = _create(service)

    payload = service.status_payload(retest_id)

    assert payload is not None
    assert payload["chat_stage"] == "retest_ready_for_evidence"
    assert payload["report_state"] == "blocked_pending_retest"
    nodes = _nodes(payload)
    assert nodes["execution"]["status"] == "ready"
    assert nodes["evidence"]["status"] == "pending"
    assert nodes["verification"]["status"] == "pending"
    assert nodes["review"]["status"] == "pending"
    assert nodes["report"]["status"] == "pending"


def test_passed_retest_opens_independent_review_but_not_report(tmp_path):
    service = _service(tmp_path)
    retest_id = _create(service)

    assert service.project_outcome(
        retest_id,
        receipt_id="retest-receipt-" + "1" * 24,
        outcome="passed",
    )
    payload = service.status_payload(retest_id)

    assert payload is not None
    assert payload["chat_stage"] == "retest_passed_awaiting_independent_review"
    assert payload["report_state"] == "blocked_pending_independent_review"
    nodes = _nodes(payload)
    for stage in ("execution", "evidence", "verification"):
        assert nodes[stage]["status"] == "completed"
    assert nodes["review"]["status"] == "ready"
    assert nodes["report"]["status"] == "pending"


def test_failed_retest_blocks_review_and_report(tmp_path):
    service = _service(tmp_path)
    retest_id = _create(service)

    assert service.project_outcome(
        retest_id,
        receipt_id="retest-receipt-" + "2" * 24,
        outcome="failed",
        reason="The original authorised check still reproduces the finding.",
    )
    payload = service.status_payload(retest_id)

    assert payload is not None
    assert payload["chat_stage"] == "retest_requires_rework"
    assert payload["report_state"] == "blocked_rework_required"
    nodes = _nodes(payload)
    assert nodes["execution"]["status"] == "completed"
    assert nodes["evidence"]["status"] == "completed"
    assert nodes["verification"]["status"] == "failed"
    assert nodes["review"]["status"] == "cancelled"
    assert nodes["report"]["status"] == "cancelled"


def test_cannot_verify_is_truthful_and_does_not_open_review(tmp_path):
    service = _service(tmp_path)
    retest_id = _create(service)

    service.project_outcome(
        retest_id,
        receipt_id="retest-receipt-" + "3" * 24,
        outcome="cannot_verify",
        reason="No deterministic check receipt was available.",
    )
    payload = service.status_payload(retest_id)

    assert payload is not None
    assert payload["chat_stage"] == "retest_cannot_verify"
    nodes = _nodes(payload)
    assert nodes["verification"]["status"] == "blocked"
    assert nodes["review"]["status"] == "cancelled"
    assert nodes["report"]["status"] == "cancelled"


def test_retest_cancellation_is_terminal_and_idempotent(tmp_path):
    service = _service(tmp_path)
    retest_id = _create(service)
    receipt_id = "retest-receipt-" + "4" * 24

    service.project_outcome(
        retest_id,
        receipt_id=receipt_id,
        outcome="cancelled",
        reason="The operator cancelled before evidence collection.",
    )
    first = service.status_payload(retest_id)
    service.project_outcome(
        retest_id,
        receipt_id=receipt_id,
        outcome="cancelled",
        reason="The operator cancelled before evidence collection.",
    )
    second = service.status_payload(retest_id)

    assert first == second
    assert second is not None
    assert second["chat_stage"] == "retest_cancelled"
    nodes = _nodes(second)
    for stage in ("execution", "evidence", "verification", "review", "report"):
        assert nodes[stage]["status"] == "cancelled"
