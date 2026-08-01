from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from django.contrib.auth import get_user_model
from governance_test_support import ADMIN_SECRET, NOW, make_governance_store, prepare_identities

from vulnhunter.authorization import AuthorizationLimits, AuthorizationStore, issue_authorization
from vulnhunter.governance.models import CampaignLimits
from vulnhunter.governance.service import create_campaign, register_application
from vulnhunter.web.models import WebUserMapping


@pytest.mark.django_db
def test_campaign_detail_renders_protected_operations_without_local_paths(
    client,
    settings,
    tmp_path: Path,
) -> None:
    settings.PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
    settings.ALLOWED_HOSTS = ["testserver", "localhost", "127.0.0.1"]
    settings.VULNHUNTER_AUTHORIZATION_DATABASE = str(tmp_path / "auth.db")
    settings.VULNHUNTER_GOVERNANCE_DATABASE = str(tmp_path / "governance.db")
    settings.VULNHUNTER_CAMPAIGN_RELEASE_PACKAGE_ROOT = str(tmp_path / "packages")

    governance = make_governance_store(tmp_path)
    prepare_identities(governance)
    authorizations = AuthorizationStore.from_path(tmp_path / "auth.db")
    authorizations.initialize()
    target = SimpleNamespace(
        normalized_url="http://127.0.0.1:8000/app/",
        scheme="http",
        hostname="127.0.0.1",
        port=8000,
        path="/app/",
        resolved_addresses=("127.0.0.1",),
    )
    authorization = issue_authorization(
        authorizations,
        target,
        owner="Owned browser fixture",
        approved_by="Independent browser supervisor",
        purpose="Protected campaign operations rendering",
        evidence_reference="ownership-ticket-browser-001",
        expires_at=NOW + timedelta(days=30),
        limits=AuthorizationLimits(
            maximum_pages=25,
            maximum_depth=3,
            maximum_requests=120,
            minimum_request_delay_seconds=0.3,
        ),
        now=NOW,
    )
    campaign = create_campaign(
        governance,
        actor_id="admin-a",
        actor_secret=ADMIN_SECRET,
        title="Protected operations campaign",
        purpose="Render exact campaign prerequisites",
        owner_id="admin-a",
        limits=CampaignLimits(
            maximum_pages=20,
            maximum_depth=2,
            maximum_requests=100,
            minimum_request_delay_seconds=0.3,
            maximum_scans_per_application=5,
        ),
        minimum_applications=1,
        minimum_application_families=1,
        minimum_reviewed_observations=1,
        now=NOW,
    )
    register_application(
        governance,
        authorizations,
        actor_id="admin-a",
        actor_secret=ADMIN_SECRET,
        campaign_id=campaign.campaign_id,
        authorization_id=authorization.authorization_id,
        application_family="python-django",
        environment="owned-local-fixture",
        now=NOW,
    )

    user = get_user_model().objects.create_user(
        username="campaign-operator",
        password="password-1234",
    )
    WebUserMapping.objects.create(
        user=user,
        governance_identity_id="admin-a",
        product_roles=["security-auditor"],
    )
    assert client.login(username="campaign-operator", password="password-1234")

    response = client.get(f"/campaigns/{campaign.campaign_id}/")

    assert response.status_code == 200
    content = response.content.decode("utf-8")
    assert "Governed campaign operations" in content
    assert "Owned-target evidence" in content
    assert "Independent campaign approval" in content
    assert "Application-family coverage" in content
    assert "ownership-ticket-browser-001" not in content
    assert str(tmp_path / "auth.db") not in content
    assert str(tmp_path / "packages") not in content
