from __future__ import annotations

import pytest
from governance_test_support import ADMIN_SECRET, NOW, make_governance_store

from vulnhunter.exceptions import (
    GovernanceAuthenticationError,
    GovernancePolicyError,
    GovernanceStateError,
)
from vulnhunter.governance.service import (
    authenticate_identity,
    bootstrap_administrator,
    change_identity_status,
    create_identity,
    reactivate_identity,
)


def test_bootstrap_is_allowed_only_once(tmp_path) -> None:
    governance_store = make_governance_store(tmp_path)
    bootstrap_administrator(
        governance_store,
        reviewer_id="admin-a",
        display_name="Administrator",
        secret=ADMIN_SECRET,
        now=NOW,
    )

    with pytest.raises(GovernancePolicyError, match="registry is empty"):
        bootstrap_administrator(
            governance_store,
            reviewer_id="admin-b",
            display_name="Administrator B",
            secret="another-secret-123",
            now=NOW,
        )


def test_administrator_creates_authenticated_reviewer(tmp_path) -> None:
    governance_store = make_governance_store(tmp_path)
    bootstrap_administrator(
        governance_store,
        reviewer_id="admin-a",
        display_name="Administrator",
        secret=ADMIN_SECRET,
        now=NOW,
    )
    reviewer = create_identity(
        governance_store,
        actor_id="admin-a",
        actor_secret=ADMIN_SECRET,
        reviewer_id="reviewer-a",
        display_name="Reviewer A",
        secret="reviewer-secret-123",
        roles=("reviewer",),
        conflict_tags=("team-red",),
        now=NOW,
    )

    authenticated = authenticate_identity(
        governance_store,
        reviewer.reviewer_id,
        "reviewer-secret-123",
        required_role="reviewer",
    )

    assert authenticated.reviewer_id == "reviewer-a"
    assert authenticated.conflict_tags == ("team-red",)


def test_wrong_secret_fails_authentication(tmp_path) -> None:
    governance_store = make_governance_store(tmp_path)
    bootstrap_administrator(
        governance_store,
        reviewer_id="admin-a",
        display_name="Administrator",
        secret=ADMIN_SECRET,
        now=NOW,
    )

    with pytest.raises(GovernanceAuthenticationError, match="failed"):
        authenticate_identity(governance_store, "admin-a", "wrong-secret-123")


def test_disabled_identity_cannot_authenticate(tmp_path) -> None:
    governance_store = make_governance_store(tmp_path)
    bootstrap_administrator(
        governance_store,
        reviewer_id="admin-a",
        display_name="Administrator",
        secret=ADMIN_SECRET,
        now=NOW,
    )
    create_identity(
        governance_store,
        actor_id="admin-a",
        actor_secret=ADMIN_SECRET,
        reviewer_id="reviewer-a",
        display_name="Reviewer A",
        secret="reviewer-secret-123",
        roles=("reviewer",),
        now=NOW,
    )
    change_identity_status(
        governance_store,
        actor_id="admin-a",
        actor_secret=ADMIN_SECRET,
        reviewer_id="reviewer-a",
        status="disabled",
        reason="Temporary leave",
        now=NOW,
    )

    with pytest.raises(GovernanceAuthenticationError, match="disabled"):
        authenticate_identity(
            governance_store,
            "reviewer-a",
            "reviewer-secret-123",
        )


def test_disabled_identity_can_be_reactivated(tmp_path) -> None:
    governance_store = make_governance_store(tmp_path)
    bootstrap_administrator(
        governance_store,
        reviewer_id="admin-a",
        display_name="Administrator",
        secret=ADMIN_SECRET,
        now=NOW,
    )
    create_identity(
        governance_store,
        actor_id="admin-a",
        actor_secret=ADMIN_SECRET,
        reviewer_id="reviewer-a",
        display_name="Reviewer A",
        secret="reviewer-secret-123",
        roles=("reviewer",),
        now=NOW,
    )
    change_identity_status(
        governance_store,
        actor_id="admin-a",
        actor_secret=ADMIN_SECRET,
        reviewer_id="reviewer-a",
        status="disabled",
        reason="Temporary leave",
        now=NOW,
    )

    identity = reactivate_identity(
        governance_store,
        actor_id="admin-a",
        actor_secret=ADMIN_SECRET,
        reviewer_id="reviewer-a",
        reason="Returned to duty",
        now=NOW,
    )

    assert identity.status == "active"


def test_revoked_identity_cannot_be_reactivated(tmp_path) -> None:
    governance_store = make_governance_store(tmp_path)
    bootstrap_administrator(
        governance_store,
        reviewer_id="admin-a",
        display_name="Administrator",
        secret=ADMIN_SECRET,
        now=NOW,
    )
    create_identity(
        governance_store,
        actor_id="admin-a",
        actor_secret=ADMIN_SECRET,
        reviewer_id="reviewer-a",
        display_name="Reviewer A",
        secret="reviewer-secret-123",
        roles=("reviewer",),
        now=NOW,
    )
    change_identity_status(
        governance_store,
        actor_id="admin-a",
        actor_secret=ADMIN_SECRET,
        reviewer_id="reviewer-a",
        status="revoked",
        reason="Credential compromise",
        now=NOW,
    )

    with pytest.raises(GovernanceStateError, match="cannot be reactivated"):
        reactivate_identity(
            governance_store,
            actor_id="admin-a",
            actor_secret=ADMIN_SECRET,
            reviewer_id="reviewer-a",
            reason="Invalid recovery",
            now=NOW,
        )
