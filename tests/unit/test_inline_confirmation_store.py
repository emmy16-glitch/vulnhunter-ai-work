from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from vulnhunter.approvals import ApprovalRequest, ApprovalStatus
from vulnhunter.approvals.store import ApprovalConflictError
from vulnhunter.web.inline_confirmation_store import InlineConfirmationStore


def _request(now: datetime) -> ApprovalRequest:
    return ApprovalRequest(
        request_id="approval-inline-test",
        campaign_id="campaign-inline-test",
        run_id="assessment-inline-test",
        action_manifest_sha256="a" * 64,
        requested_by="vulnhunter-user",
        summary="Confirm the exact passive Nuclei command plan.",
        risk_summary="Only the reviewed passive plan may enter the isolated worker queue.",
        requested_at=now,
        expires_at=now + timedelta(minutes=10),
    )


def test_requester_can_confirm_only_the_exact_passive_plan(tmp_path):
    now = datetime(2026, 7, 23, 12, 0, tzinfo=UTC)
    store = InlineConfirmationStore(tmp_path / "approvals.sqlite3")
    store.create(_request(now))

    confirmed = store.confirm_exact_passive_plan(
        request_id="approval-inline-test",
        actor_id="vulnhunter-user",
        action_manifest_sha256="a" * 64,
        profile="passive",
        reason="Confirmed for this exact authorised passive plan.",
        now=now + timedelta(seconds=5),
    )

    assert confirmed.status is ApprovalStatus.APPROVED
    assert confirmed.decided_by == "vulnhunter-user"
    assert confirmed.action_manifest_sha256 == "a" * 64
    events = store.events(confirmed.request_id)
    assert events[-1].event_type == "exact_passive_plan_confirmed"
    assert events[-1].detail["confirmation_kind"] == "single_account_exact_plan"


@pytest.mark.parametrize("profile", ["standard", "intrusive", "retest"])
def test_inline_confirmation_rejects_non_passive_profiles(tmp_path, profile):
    now = datetime(2026, 7, 23, 12, 0, tzinfo=UTC)
    store = InlineConfirmationStore(tmp_path / f"{profile}.sqlite3")
    store.create(_request(now))

    with pytest.raises(ApprovalConflictError, match="only for the reviewed passive"):
        store.confirm_exact_passive_plan(
            request_id="approval-inline-test",
            actor_id="vulnhunter-user",
            action_manifest_sha256="a" * 64,
            profile=profile,
            reason="Confirm this exact plan safely.",
            now=now + timedelta(seconds=5),
        )


def test_inline_confirmation_rejects_actor_or_digest_changes(tmp_path):
    now = datetime(2026, 7, 23, 12, 0, tzinfo=UTC)
    store = InlineConfirmationStore(tmp_path / "approvals.sqlite3")
    store.create(_request(now))

    with pytest.raises(ApprovalConflictError, match="assessment requester"):
        store.confirm_exact_passive_plan(
            request_id="approval-inline-test",
            actor_id="another-user",
            action_manifest_sha256="a" * 64,
            profile="passive",
            reason="Confirm this exact plan safely.",
            now=now + timedelta(seconds=5),
        )

    with pytest.raises(ApprovalConflictError, match="different command-plan digest"):
        store.confirm_exact_passive_plan(
            request_id="approval-inline-test",
            actor_id="vulnhunter-user",
            action_manifest_sha256="b" * 64,
            profile="passive",
            reason="Confirm this exact plan safely.",
            now=now + timedelta(seconds=5),
        )


def test_expired_inline_plan_fails_closed(tmp_path):
    now = datetime(2026, 7, 23, 12, 0, tzinfo=UTC)
    store = InlineConfirmationStore(tmp_path / "approvals.sqlite3")
    request = _request(now).model_copy(update={"expires_at": now + timedelta(seconds=1)})
    store.create(ApprovalRequest.model_validate(request.model_dump()))

    with pytest.raises(ApprovalConflictError, match="expired"):
        store.confirm_exact_passive_plan(
            request_id="approval-inline-test",
            actor_id="vulnhunter-user",
            action_manifest_sha256="a" * 64,
            profile="passive",
            reason="Confirm this exact plan safely.",
            now=now + timedelta(seconds=2),
        )

    assert store.get("approval-inline-test").status is ApprovalStatus.EXPIRED
