from datetime import UTC, datetime, timedelta

from vulnhunter.owner import PrivilegeGrant


def test_privilege_grant_is_short_lived_and_action_bound():
    now = datetime.now(UTC)
    grant = PrivilegeGrant(
        grant_id="grant-01",
        owner_id="owner-01",
        campaign_id="campaign-01",
        action_manifest_sha256="a" * 64,
        approval_request_id="approval-01",
        issued_at=now,
        expires_at=now + timedelta(minutes=5),
        maximum_actions=1,
    )
    assert grant.is_active(now=now + timedelta(minutes=1))
    assert not grant.is_active(now=now + timedelta(minutes=6))
