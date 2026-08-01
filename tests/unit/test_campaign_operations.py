from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

from governance_test_support import (
    ADMIN_SECRET,
    APPROVER_SECRET,
    NOW,
    REVIEWER_ONE_SECRET,
    REVIEWER_TWO_SECRET,
    create_active_campaign,
    create_authorization,
    create_completed_scan,
    make_governance_store,
    prepare_identities,
)

from vulnhunter.authorization import AuthorizationLimits, AuthorizationStore, issue_authorization
from vulnhunter.governance.campaign_operations import assess_campaign_operations
from vulnhunter.governance.models import CampaignLimits
from vulnhunter.governance.release_package import (
    CampaignReleasePackageStore,
    create_campaign_release_package,
)
from vulnhunter.governance.service import (
    activate_campaign,
    approve_campaign,
    assign_reviewers,
    complete_campaign,
    create_campaign,
    link_scan,
    register_application,
    release_dataset,
    submit_governed_review,
)


def _authorization_with_ownership_evidence(path: Path):
    store = AuthorizationStore.from_path(path)
    store.initialize()
    target = SimpleNamespace(
        normalized_url="http://127.0.0.1:8000/app/",
        scheme="http",
        hostname="127.0.0.1",
        port=8000,
        path="/app/",
        resolved_addresses=("127.0.0.1",),
    )
    record = issue_authorization(
        store,
        target,
        owner="Owned local fixture",
        approved_by="Independent supervisor",
        purpose="Governed real-data campaign fixture",
        evidence_reference="ownership-ticket-2026-001",
        expires_at=NOW + timedelta(days=30),
        limits=AuthorizationLimits(
            maximum_pages=25,
            maximum_depth=3,
            maximum_requests=120,
            minimum_request_delay_seconds=0.3,
        ),
        now=NOW,
    )
    return store, record


def _draft_campaign_with_evidence(tmp_path: Path):
    governance = make_governance_store(tmp_path)
    prepare_identities(governance)
    authorizations, authorization = _authorization_with_ownership_evidence(tmp_path / "auth.db")
    campaign = create_campaign(
        governance,
        actor_id="admin-a",
        actor_secret=ADMIN_SECRET,
        title="Owned campaign planning",
        purpose="Plan collection before activation",
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
    return governance, authorizations, campaign


def test_draft_operations_distinguish_prerequisites_from_approval(tmp_path: Path) -> None:
    governance, authorizations, campaign = _draft_campaign_with_evidence(tmp_path)

    snapshot = assess_campaign_operations(
        governance,
        authorizations,
        {},
        tmp_path / "packages",
        campaign_id=campaign.campaign_id,
        now=NOW,
    )

    states = {item.code: item.state for item in snapshot.prerequisites}
    assert states["governance_integrity"] == "met"
    assert states["application_count"] == "met"
    assert states["application_family_diversity"] == "met"
    assert states["exact_authorizations"] == "met"
    assert states["owned_target_evidence"] == "met"
    assert states["independent_campaign_approval"] == "blocked"
    assert snapshot.operator_activation_ready is False
    assert snapshot.genuine_collection_ready is False
    assert snapshot.ownership_evidence_count == 1
    assert snapshot.families[0].application_family == "python-django"
    assert "Request independent approval" in " ".join(snapshot.next_actions)


def test_active_operations_surface_review_workload_and_missing_evidence(tmp_path: Path) -> None:
    governance = make_governance_store(tmp_path)
    prepare_identities(governance)
    authorizations, authorization = create_authorization(tmp_path / "auth.db")
    campaign, application = create_active_campaign(
        governance,
        authorizations,
        authorization.authorization_id,
    )
    scan_database = tmp_path / "scans.db"
    repository, scan_id, observation_id = create_completed_scan(
        scan_database,
        authorizations,
        authorization.authorization_id,
    )
    link_scan(
        governance,
        authorizations,
        repository,
        actor_id="admin-a",
        actor_secret=ADMIN_SECRET,
        campaign_id=campaign.campaign_id,
        application_id=application.application_id,
        scan_database=scan_database,
        scan_id=scan_id,
        now=NOW,
    )
    assign_reviewers(
        governance,
        repository,
        actor_id="admin-a",
        actor_secret=ADMIN_SECRET,
        campaign_id=campaign.campaign_id,
        scan_database=scan_database,
        observation_id=observation_id,
        first_reviewer_id="reviewer-a",
        second_reviewer_id="reviewer-b",
        adjudicator_id="lead-c",
        now=NOW,
    )
    submit_governed_review(
        governance,
        repository,
        actor_id="reviewer-a",
        actor_secret=REVIEWER_ONE_SECRET,
        campaign_id=campaign.campaign_id,
        scan_database=scan_database,
        observation_id=observation_id,
        outcome="confirmed",
        now=NOW,
    )

    snapshot = assess_campaign_operations(
        governance,
        authorizations,
        {str(scan_database.resolve()): repository},
        tmp_path / "packages",
        campaign_id=campaign.campaign_id,
        now=NOW,
    )

    assert snapshot.campaign_status == "active"
    assert snapshot.genuine_collection_ready is False
    assert snapshot.ownership_evidence_count == 0
    assert snapshot.review_workload.total_observations == 1
    assert snapshot.review_workload.assigned_observations == 1
    assert snapshot.review_workload.awaiting_primary_review == 1
    assert snapshot.review_workload.final_observations == 0
    assert snapshot.release_package.state == "not_released"
    assert "ownership evidence reference" in " ".join(snapshot.blockers)


def test_completed_release_reports_verified_append_only_package(tmp_path: Path) -> None:
    governance = make_governance_store(tmp_path)
    prepare_identities(governance)
    authorizations, authorization = _authorization_with_ownership_evidence(tmp_path / "auth.db")
    campaign = create_campaign(
        governance,
        actor_id="admin-a",
        actor_secret=ADMIN_SECRET,
        title="Completed owned campaign",
        purpose="Verify exact campaign release package status",
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
    application = register_application(
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
    approve_campaign(
        governance,
        authorizations,
        actor_id="admin-b",
        actor_secret=APPROVER_SECRET,
        campaign_id=campaign.campaign_id,
        now=NOW,
    )
    campaign = activate_campaign(
        governance,
        authorizations,
        actor_id="admin-b",
        actor_secret=APPROVER_SECRET,
        campaign_id=campaign.campaign_id,
        now=NOW,
    )
    scan_database = tmp_path / "scans.db"
    repository, scan_id, observation_id = create_completed_scan(
        scan_database,
        authorizations,
        authorization.authorization_id,
    )
    link_scan(
        governance,
        authorizations,
        repository,
        actor_id="admin-a",
        actor_secret=ADMIN_SECRET,
        campaign_id=campaign.campaign_id,
        application_id=application.application_id,
        scan_database=scan_database,
        scan_id=scan_id,
        now=NOW,
    )
    assign_reviewers(
        governance,
        repository,
        actor_id="admin-a",
        actor_secret=ADMIN_SECRET,
        campaign_id=campaign.campaign_id,
        scan_database=scan_database,
        observation_id=observation_id,
        first_reviewer_id="reviewer-a",
        second_reviewer_id="reviewer-b",
        adjudicator_id="lead-c",
        now=NOW,
    )
    submit_governed_review(
        governance,
        repository,
        actor_id="reviewer-a",
        actor_secret=REVIEWER_ONE_SECRET,
        campaign_id=campaign.campaign_id,
        scan_database=scan_database,
        observation_id=observation_id,
        outcome="confirmed",
        now=NOW,
    )
    submit_governed_review(
        governance,
        repository,
        actor_id="reviewer-b",
        actor_secret=REVIEWER_TWO_SECRET,
        campaign_id=campaign.campaign_id,
        scan_database=scan_database,
        observation_id=observation_id,
        outcome="confirmed",
        now=NOW,
    )
    repositories = {str(scan_database.resolve()): repository}
    complete_campaign(
        governance,
        authorizations,
        repositories,
        actor_id="admin-a",
        actor_secret=ADMIN_SECRET,
        campaign_id=campaign.campaign_id,
        now=NOW,
    )
    release_dataset(
        governance,
        authorizations,
        repositories,
        actor_id="admin-a",
        actor_secret=ADMIN_SECRET,
        campaign_id=campaign.campaign_id,
        now=NOW,
    )
    package_root = tmp_path / "packages"
    create_campaign_release_package(
        governance,
        CampaignReleasePackageStore(package_root),
        repositories,
        campaign_id=campaign.campaign_id,
    )

    snapshot = assess_campaign_operations(
        governance,
        authorizations,
        repositories,
        package_root,
        campaign_id=campaign.campaign_id,
        now=NOW,
    )

    assert snapshot.campaign_status == "completed"
    assert snapshot.genuine_collection_ready is False
    assert snapshot.release_ready is True
    assert snapshot.review_workload.consensus == 1
    assert snapshot.review_workload.final_observations == 1
    assert snapshot.release_manifest_state == "present"
    assert snapshot.release_package.state == "verified"
    assert snapshot.release_package.package_id is not None
