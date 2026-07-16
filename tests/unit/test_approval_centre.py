from datetime import UTC, datetime, timedelta

import pytest

from vulnhunter.approvals import (
    ApprovalDecision,
    ApprovalRequest,
    ApprovalStatus,
    ApprovalStore,
)
from vulnhunter.approvals.store import ApprovalConflictError


def _request():
    now = datetime.now(UTC)
    return ApprovalRequest(
        request_id="approval-01",
        campaign_id="campaign-01",
        run_id="run-01",
        action_manifest_sha256="a" * 64,
        requested_by="operator-01",
        summary="Approve one bounded network discovery action.",
        risk_summary="The tool will contact the approved laboratory target.",
        requested_at=now,
        expires_at=now + timedelta(minutes=10),
    )


def test_approval_is_hash_bound_one_time_and_audited(tmp_path):
    store = ApprovalStore(tmp_path / "approvals.db")
    created = store.create(_request())
    assert created.status == ApprovalStatus.PENDING

    approved = store.decide(
        request_id=created.request_id,
        actor_id="approver-01",
        decision=ApprovalDecision.APPROVE_ONCE,
        reason="Scope and limits verified.",
    )
    assert approved.status == ApprovalStatus.APPROVED

    with pytest.raises(ApprovalConflictError, match="different action"):
        store.consume(
            request_id=created.request_id,
            action_manifest_sha256="b" * 64,
            execution_id="execution-01",
            actor_id="runtime-01",
        )

    consumed = store.consume(
        request_id=created.request_id,
        action_manifest_sha256="a" * 64,
        execution_id="execution-01",
        actor_id="runtime-01",
    )
    assert consumed.status == ApprovalStatus.CONSUMED

    with pytest.raises(ApprovalConflictError, match="not active"):
        store.consume(
            request_id=created.request_id,
            action_manifest_sha256="a" * 64,
            execution_id="execution-02",
            actor_id="runtime-01",
        )

    events = store.events(created.request_id)
    assert [event.event_type for event in events] == [
        "approval_requested",
        "approval_approve_once",
        "approval_consumed",
    ]


def test_approval_ledger_chains_each_request_independently(tmp_path):
    store = ApprovalStore(tmp_path / "approvals.db")
    first = store.create(_request())
    second_request = _request().model_copy(update={"request_id": "approval-02", "run_id": "run-02"})
    second = store.create(second_request)

    assert [event.event_type for event in store.events(first.request_id)] == ["approval_requested"]
    assert [event.event_type for event in store.events(second.request_id)] == ["approval_requested"]


def test_requester_cannot_self_approve_or_self_consume(tmp_path):
    store = ApprovalStore(tmp_path / "approvals.db")
    created = store.create(_request())

    with pytest.raises(ApprovalConflictError, match="cannot decide"):
        store.decide(
            request_id=created.request_id,
            actor_id=created.requested_by,
            decision=ApprovalDecision.APPROVE_ONCE,
            reason="Requester attempted self approval.",
        )

    approved = store.decide(
        request_id=created.request_id,
        actor_id="approver-01",
        decision=ApprovalDecision.APPROVE_ONCE,
        reason="Scope and limits verified.",
    )
    assert approved.status == ApprovalStatus.APPROVED

    with pytest.raises(ApprovalConflictError, match="cannot consume"):
        store.consume(
            request_id=created.request_id,
            action_manifest_sha256=created.action_manifest_sha256,
            execution_id="execution-01",
            actor_id=created.requested_by,
        )


def test_conditional_approval_fails_closed_without_canonical_execution_inputs(tmp_path):
    store = ApprovalStore(tmp_path / "approvals.db")
    created = store.create(_request())
    store.decide(
        request_id=created.request_id,
        actor_id="approver-01",
        decision=ApprovalDecision.APPROVE_WITH_CONDITIONS,
        reason="Approve only with the recorded limits.",
        conditions=("maximum_requests=10",),
    )

    with pytest.raises(ApprovalConflictError, match="canonical execution inputs"):
        store.consume(
            request_id=created.request_id,
            action_manifest_sha256=created.action_manifest_sha256,
            execution_id="execution-01",
            actor_id="runtime-01",
        )


def test_expiry_state_and_event_persist_when_decision_is_rejected(tmp_path):
    store = ApprovalStore(tmp_path / "approvals.db")
    created = store.create(_request())
    after_expiry = created.expires_at + timedelta(seconds=1)

    with pytest.raises(ApprovalConflictError, match="expired"):
        store.decide(
            request_id=created.request_id,
            actor_id="approver-01",
            decision=ApprovalDecision.APPROVE_ONCE,
            reason="This decision arrived after expiry.",
            now=after_expiry,
        )

    assert store.get(created.request_id).status == ApprovalStatus.EXPIRED
    assert store.events(created.request_id)[-1].event_type == "approval_expired"
