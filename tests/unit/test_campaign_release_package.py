from __future__ import annotations

import sqlite3
from datetime import timedelta
from pathlib import Path

import pytest
from governance_test_support import (
    ADJUDICATOR_SECRET,
    ADMIN_SECRET,
    APPROVER_SECRET,
    NOW,
    REVIEWER_ONE_SECRET,
    REVIEWER_TWO_SECRET,
    create_authorization,
    make_governance_store,
    prepare_identities,
)

from vulnhunter.governance.models import CampaignLimits
from vulnhunter.governance.release_package import (
    CampaignReleasePackageError,
    CampaignReleasePackageStore,
    build_campaign_release_package,
    create_campaign_release_package,
)
from vulnhunter.governance.service import (
    activate_campaign,
    adjudicate_governed_review,
    approve_campaign,
    assign_reviewers,
    complete_campaign,
    create_campaign,
    link_scan,
    register_application,
    release_dataset,
    scan_snapshot_sha256,
    submit_governed_review,
)
from vulnhunter.mapping.models import MappedPage, MappingResult
from vulnhunter.observations.models import Observation
from vulnhunter.observations.storage import ScanRepository


def _completed_scan(
    database: Path,
    authorization_store,
    authorization_id: str,
    *,
    target_url: str,
    indicator: str,
) -> tuple[ScanRepository, int, int]:
    repository = ScanRepository.from_path(database)
    repository.initialize()
    authorization_store.append_event(
        authorization_id,
        "validated",
        {
            "target_url": target_url,
            "maximum_pages": 20,
            "maximum_depth": 2,
            "maximum_requests": 100,
            "request_delay_seconds": 0.3,
        },
    )
    scan_id = repository.create_scan(target_url)
    authorization_store.append_event(
        authorization_id,
        "scan_started",
        {
            "scan_id": scan_id,
            "scan_database": str(database.resolve()),
            "target_url": target_url,
        },
    )
    observation = Observation.create(
        category="debug_error_exposure",
        severity="high",
        title="Debug detail exposed",
        description="Detailed debug output was visible.",
        url=target_url + "error",
        evidence={"detected_indicators": [indicator]},
    )
    repository.complete_scan(
        scan_id,
        MappingResult(
            target_url=target_url,
            started_at=NOW,
            completed_at=NOW + timedelta(seconds=1),
            pages=(
                MappedPage(
                    url=observation.url,
                    depth=0,
                    status_code=500,
                    response_bytes=100,
                    elapsed_ms=1.0,
                ),
            ),
            observations=(observation,),
            discovered_urls=1,
            rejected_links=0,
        ),
    )
    completed = repository.get_scan(scan_id)
    authorization_store.append_event(
        authorization_id,
        "scan_completed",
        {
            "scan_id": scan_id,
            "scan_database": str(database.resolve()),
            "target_url": target_url,
            "scan_snapshot_sha256": scan_snapshot_sha256(completed),
            "pages_visited": 1,
            "observations": 1,
        },
    )
    observation_id = repository.list_observations(scan_id=scan_id)[0].id
    return repository, scan_id, observation_id


def _released_campaign(tmp_path: Path):
    governance_store = make_governance_store(tmp_path)
    prepare_identities(governance_store)
    authorization_store, first_authorization = create_authorization(
        tmp_path / "authorizations.db",
        target_url="http://127.0.0.1:8000/alpha/",
        family_suffix="alpha",
    )
    _, second_authorization = create_authorization(
        tmp_path / "authorizations.db",
        target_url="http://127.0.0.1:8000/beta/",
        family_suffix="beta",
    )
    campaign = create_campaign(
        governance_store,
        actor_id="admin-a",
        actor_secret=ADMIN_SECRET,
        title="Two-family governed campaign",
        purpose="Preserve exact dual-review and adjudication provenance.",
        owner_id="admin-a",
        limits=CampaignLimits(
            maximum_pages=20,
            maximum_depth=2,
            maximum_requests=100,
            minimum_request_delay_seconds=0.3,
            maximum_scans_per_application=2,
        ),
        minimum_applications=2,
        minimum_application_families=2,
        minimum_reviewed_observations=2,
        now=NOW,
    )
    first_application = register_application(
        governance_store,
        authorization_store,
        actor_id="admin-a",
        actor_secret=ADMIN_SECRET,
        campaign_id=campaign.campaign_id,
        authorization_id=first_authorization.authorization_id,
        application_family="python-django",
        environment="owned-local-alpha",
        now=NOW,
    )
    second_application = register_application(
        governance_store,
        authorization_store,
        actor_id="admin-a",
        actor_secret=ADMIN_SECRET,
        campaign_id=campaign.campaign_id,
        authorization_id=second_authorization.authorization_id,
        application_family="node-express",
        environment="owned-local-beta",
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
    campaign = activate_campaign(
        governance_store,
        authorization_store,
        actor_id="admin-b",
        actor_secret=APPROVER_SECRET,
        campaign_id=campaign.campaign_id,
        now=NOW,
    )

    cases = (
        (
            first_application,
            first_authorization,
            tmp_path / "alpha-scans.db",
            "alpha-traceback",
        ),
        (
            second_application,
            second_authorization,
            tmp_path / "beta-scans.db",
            "beta-stack",
        ),
    )
    repositories: dict[str, ScanRepository] = {}
    observations: list[tuple[Path, int]] = []
    for application, authorization, database, indicator in cases:
        repository, scan_id, observation_id = _completed_scan(
            database,
            authorization_store,
            authorization.authorization_id,
            target_url=authorization.target_url,
            indicator=indicator,
        )
        link_scan(
            governance_store,
            authorization_store,
            repository,
            actor_id="admin-a",
            actor_secret=ADMIN_SECRET,
            campaign_id=campaign.campaign_id,
            application_id=application.application_id,
            scan_database=database,
            scan_id=scan_id,
            now=NOW,
        )
        assign_reviewers(
            governance_store,
            repository,
            actor_id="admin-a",
            actor_secret=ADMIN_SECRET,
            campaign_id=campaign.campaign_id,
            scan_database=database,
            observation_id=observation_id,
            first_reviewer_id="reviewer-a",
            second_reviewer_id="reviewer-b",
            adjudicator_id="lead-c",
            now=NOW,
        )
        repositories[str(database.resolve())] = repository
        observations.append((database, observation_id))

    first_database, first_observation = observations[0]
    for actor_id, secret in (
        ("reviewer-a", REVIEWER_ONE_SECRET),
        ("reviewer-b", REVIEWER_TWO_SECRET),
    ):
        submit_governed_review(
            governance_store,
            repositories[str(first_database.resolve())],
            actor_id=actor_id,
            actor_secret=secret,
            campaign_id=campaign.campaign_id,
            scan_database=first_database,
            observation_id=first_observation,
            outcome="confirmed",
            now=NOW,
        )

    second_database, second_observation = observations[1]
    submit_governed_review(
        governance_store,
        repositories[str(second_database.resolve())],
        actor_id="reviewer-a",
        actor_secret=REVIEWER_ONE_SECRET,
        campaign_id=campaign.campaign_id,
        scan_database=second_database,
        observation_id=second_observation,
        outcome="confirmed",
        now=NOW,
    )
    submit_governed_review(
        governance_store,
        repositories[str(second_database.resolve())],
        actor_id="reviewer-b",
        actor_secret=REVIEWER_TWO_SECRET,
        campaign_id=campaign.campaign_id,
        scan_database=second_database,
        observation_id=second_observation,
        outcome="false_positive",
        now=NOW,
    )
    adjudicate_governed_review(
        governance_store,
        repositories[str(second_database.resolve())],
        actor_id="lead-c",
        actor_secret=ADJUDICATOR_SECRET,
        campaign_id=campaign.campaign_id,
        scan_database=second_database,
        observation_id=second_observation,
        outcome="false_positive",
        rationale="The response is a deliberate synthetic fixture.",
        now=NOW,
    )
    complete_campaign(
        governance_store,
        authorization_store,
        repositories,
        actor_id="admin-b",
        actor_secret=APPROVER_SECRET,
        campaign_id=campaign.campaign_id,
        now=NOW,
    )
    release = release_dataset(
        governance_store,
        authorization_store,
        repositories,
        actor_id="admin-b",
        actor_secret=APPROVER_SECRET,
        campaign_id=campaign.campaign_id,
        now=NOW,
    )
    return governance_store, repositories, campaign.campaign_id, release


def test_release_package_preserves_two_families_reviews_and_adjudication(
    tmp_path: Path,
) -> None:
    governance_store, repositories, campaign_id, release = _released_campaign(tmp_path)
    package_store = CampaignReleasePackageStore(tmp_path / "release-packages")

    package, created = create_campaign_release_package(
        governance_store,
        package_store,
        repositories,
        campaign_id=campaign_id,
    )

    assert created is True
    assert package.release_id == release.release_id
    assert {item.application_family for item in package.applications} == {
        "python-django",
        "node-express",
    }
    assert {item.resolution_state for item in package.reviews} == {
        "consensus",
        "adjudicated",
    }
    adjudicated = next(
        item for item in package.reviews if item.resolution_state == "adjudicated"
    )
    assert adjudicated.assigned_adjudicator_id == "lead-c"
    assert adjudicated.adjudication_attestation_id is not None
    assert adjudicated.effective_label == "false_positive"
    loaded = package_store.load(campaign_id, release.release_id)
    assert loaded == package
    assert package_store.save(package) is False


def test_release_package_fails_closed_when_primary_attestation_is_removed(
    tmp_path: Path,
) -> None:
    governance_store, repositories, campaign_id, _ = _released_campaign(tmp_path)
    with sqlite3.connect(governance_store.path) as connection:
        connection.execute(
            "DELETE FROM governance_attestations WHERE actor_id = ? AND role = ?",
            ("reviewer-b", "primary"),
        )
        connection.commit()

    with pytest.raises(CampaignReleasePackageError, match="exactly two assigned"):
        build_campaign_release_package(
            governance_store,
            repositories,
            campaign_id=campaign_id,
        )


def test_release_package_store_never_overwrites_changed_content(tmp_path: Path) -> None:
    governance_store, repositories, campaign_id, release = _released_campaign(tmp_path)
    package_store = CampaignReleasePackageStore(tmp_path / "release-packages")
    package, _ = create_campaign_release_package(
        governance_store,
        package_store,
        repositories,
        campaign_id=campaign_id,
    )
    path = package_store.path_for(package)
    path.write_text("{}", encoding="utf-8")

    with pytest.raises(CampaignReleasePackageError, match="different immutable content"):
        package_store.save(package)
    assert path.read_text(encoding="utf-8") == "{}"
    with pytest.raises(CampaignReleasePackageError, match="unavailable or invalid"):
        package_store.load(campaign_id, release.release_id)
