from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest
from governance_test_support import (
    ADMIN_SECRET,
    APPROVER_SECRET,
    NOW,
    create_authorization,
    make_governance_store,
    prepare_identities,
)

from vulnhunter.exceptions import GovernancePolicyError, GovernanceStateError
from vulnhunter.governance.models import CampaignLimits
from vulnhunter.governance.service import (
    activate_campaign,
    approve_campaign,
    create_campaign,
    register_application,
)


def test_creator_cannot_approve_own_campaign(tmp_path: Path) -> None:
    governance_store = make_governance_store(tmp_path)
    prepare_identities(governance_store)
    authorization_store, authorization = create_authorization(tmp_path / "auth.db")
    campaign = create_campaign(
        governance_store,
        actor_id="admin-a",
        actor_secret=ADMIN_SECRET,
        title="Campaign",
        purpose="Purpose",
        owner_id="admin-a",
        limits=CampaignLimits(
            maximum_pages=20,
            maximum_depth=2,
            maximum_requests=100,
            minimum_request_delay_seconds=0.3,
        ),
        minimum_applications=1,
        minimum_application_families=1,
        minimum_reviewed_observations=1,
        now=NOW,
    )
    register_application(
        governance_store,
        authorization_store,
        actor_id="admin-a",
        actor_secret=ADMIN_SECRET,
        campaign_id=campaign.campaign_id,
        authorization_id=authorization.authorization_id,
        application_family="family-a",
        environment="local",
        now=NOW,
    )

    with pytest.raises(GovernancePolicyError, match="cannot approve"):
        approve_campaign(
            governance_store,
            authorization_store,
            actor_id="admin-a",
            actor_secret=ADMIN_SECRET,
            campaign_id=campaign.campaign_id,
            now=NOW,
        )


def test_campaign_enforces_application_family_diversity(tmp_path: Path) -> None:
    governance_store = make_governance_store(tmp_path)
    prepare_identities(governance_store)
    authorization_store, first = create_authorization(tmp_path / "auth.db")
    _, second = create_authorization(
        tmp_path / "auth.db",
        target_url="http://127.0.0.1:8000/app/",
        family_suffix="two",
    )
    campaign = create_campaign(
        governance_store,
        actor_id="admin-a",
        actor_secret=ADMIN_SECRET,
        title="Campaign",
        purpose="Purpose",
        owner_id="admin-a",
        limits=CampaignLimits(
            maximum_pages=20,
            maximum_depth=2,
            maximum_requests=100,
            minimum_request_delay_seconds=0.3,
        ),
        minimum_applications=2,
        minimum_application_families=2,
        minimum_reviewed_observations=1,
        now=NOW,
    )
    for authorization in (first, second):
        register_application(
            governance_store,
            authorization_store,
            actor_id="admin-a",
            actor_secret=ADMIN_SECRET,
            campaign_id=campaign.campaign_id,
            authorization_id=authorization.authorization_id,
            application_family="same-family",
            environment="local",
            now=NOW,
        )

    with pytest.raises(GovernancePolicyError, match="diversity"):
        approve_campaign(
            governance_store,
            authorization_store,
            actor_id="admin-b",
            actor_secret=APPROVER_SECRET,
            campaign_id=campaign.campaign_id,
            now=NOW,
        )


def test_campaign_limits_cannot_exceed_authorization(tmp_path: Path) -> None:
    governance_store = make_governance_store(tmp_path)
    prepare_identities(governance_store)
    authorization_store, authorization = create_authorization(tmp_path / "auth.db")
    campaign = create_campaign(
        governance_store,
        actor_id="admin-a",
        actor_secret=ADMIN_SECRET,
        title="Campaign",
        purpose="Purpose",
        owner_id="admin-a",
        limits=CampaignLimits(
            maximum_pages=26,
            maximum_depth=2,
            maximum_requests=100,
            minimum_request_delay_seconds=0.3,
        ),
        minimum_applications=1,
        minimum_application_families=1,
        minimum_reviewed_observations=1,
        now=NOW,
    )

    with pytest.raises(GovernancePolicyError, match="page limit"):
        register_application(
            governance_store,
            authorization_store,
            actor_id="admin-a",
            actor_secret=ADMIN_SECRET,
            campaign_id=campaign.campaign_id,
            authorization_id=authorization.authorization_id,
            application_family="family-a",
            environment="local",
            now=NOW,
        )


def test_approved_manifest_prevents_late_application_changes(tmp_path: Path) -> None:
    governance_store = make_governance_store(tmp_path)
    prepare_identities(governance_store)
    authorization_store, authorization = create_authorization(tmp_path / "auth.db")
    campaign = create_campaign(
        governance_store,
        actor_id="admin-a",
        actor_secret=ADMIN_SECRET,
        title="Campaign",
        purpose="Purpose",
        owner_id="admin-a",
        limits=CampaignLimits(
            maximum_pages=20,
            maximum_depth=2,
            maximum_requests=100,
            minimum_request_delay_seconds=0.3,
        ),
        minimum_applications=1,
        minimum_application_families=1,
        minimum_reviewed_observations=1,
        now=NOW,
    )
    register_application(
        governance_store,
        authorization_store,
        actor_id="admin-a",
        actor_secret=ADMIN_SECRET,
        campaign_id=campaign.campaign_id,
        authorization_id=authorization.authorization_id,
        application_family="family-a",
        environment="local",
        now=NOW,
    )
    approve_campaign(
        governance_store,
        authorization_store,
        actor_id="admin-b",
        actor_secret=APPROVER_SECRET,
        campaign_id=campaign.campaign_id,
        now=NOW,
    )

    with pytest.raises(GovernanceStateError, match="draft"):
        register_application(
            governance_store,
            authorization_store,
            actor_id="admin-a",
            actor_secret=ADMIN_SECRET,
            campaign_id=campaign.campaign_id,
            authorization_id=authorization.authorization_id,
            application_family="family-b",
            environment="local",
            now=NOW,
        )


def test_expired_authorization_blocks_activation(tmp_path: Path) -> None:
    governance_store = make_governance_store(tmp_path)
    prepare_identities(governance_store)
    authorization_store, authorization = create_authorization(tmp_path / "auth.db")
    campaign = create_campaign(
        governance_store,
        actor_id="admin-a",
        actor_secret=ADMIN_SECRET,
        title="Campaign",
        purpose="Purpose",
        owner_id="admin-a",
        limits=CampaignLimits(
            maximum_pages=20,
            maximum_depth=2,
            maximum_requests=100,
            minimum_request_delay_seconds=0.3,
        ),
        minimum_applications=1,
        minimum_application_families=1,
        minimum_reviewed_observations=1,
        now=NOW,
    )
    register_application(
        governance_store,
        authorization_store,
        actor_id="admin-a",
        actor_secret=ADMIN_SECRET,
        campaign_id=campaign.campaign_id,
        authorization_id=authorization.authorization_id,
        application_family="family-a",
        environment="local",
        now=NOW,
    )
    approve_campaign(
        governance_store,
        authorization_store,
        actor_id="admin-b",
        actor_secret=APPROVER_SECRET,
        campaign_id=campaign.campaign_id,
        now=NOW,
    )

    with pytest.raises(GovernancePolicyError, match="expired"):
        activate_campaign(
            governance_store,
            authorization_store,
            actor_id="admin-b",
            actor_secret=APPROVER_SECRET,
            campaign_id=campaign.campaign_id,
            now=NOW + timedelta(days=31),
        )
