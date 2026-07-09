from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

from vulnhunter.authorization import (
    AuthorizationLimits,
    AuthorizationStore,
    issue_authorization,
)
from vulnhunter.governance.models import CampaignLimits
from vulnhunter.governance.service import (
    activate_campaign,
    approve_campaign,
    bootstrap_administrator,
    create_campaign,
    create_identity,
    register_application,
)
from vulnhunter.governance.store import GovernanceStore
from vulnhunter.mapping.models import MappedPage, MappingResult
from vulnhunter.observations.models import Observation
from vulnhunter.observations.storage import ScanRepository

NOW = datetime(2026, 7, 9, 12, tzinfo=UTC)
ADMIN_SECRET = "admin-secret-123"
APPROVER_SECRET = "approver-secret-123"
REVIEWER_ONE_SECRET = "reviewer-one-123"
REVIEWER_TWO_SECRET = "reviewer-two-123"
ADJUDICATOR_SECRET = "adjudicator-123"


def make_governance_store(tmp_path: Path) -> GovernanceStore:
    store = GovernanceStore.from_path(tmp_path / "governance.db")
    store.initialize()
    return store


def add_identity(
    store: GovernanceStore,
    reviewer_id: str,
    secret: str,
    roles: tuple[str, ...],
    *,
    conflict_tags: tuple[str, ...] = (),
):
    return create_identity(
        store,
        actor_id="admin-a",
        actor_secret=ADMIN_SECRET,
        reviewer_id=reviewer_id,
        display_name=reviewer_id,
        secret=secret,
        roles=roles,
        conflict_tags=conflict_tags,
        now=NOW,
    )


def prepare_identities(store: GovernanceStore) -> None:
    bootstrap_administrator(
        store,
        reviewer_id="admin-a",
        display_name="Administrator A",
        secret=ADMIN_SECRET,
        now=NOW,
    )
    add_identity(store, "admin-b", APPROVER_SECRET, ("campaign_admin",))
    add_identity(store, "reviewer-a", REVIEWER_ONE_SECRET, ("reviewer",))
    add_identity(store, "reviewer-b", REVIEWER_TWO_SECRET, ("reviewer",))
    add_identity(store, "lead-c", ADJUDICATOR_SECRET, ("adjudicator",))


def create_authorization(
    path: Path,
    *,
    target_url: str = "http://127.0.0.1:8000/app/",
    family_suffix: str = "one",
) -> tuple[AuthorizationStore, object]:
    store = AuthorizationStore.from_path(path)
    store.initialize()
    target = SimpleNamespace(
        normalized_url=target_url,
        scheme="http",
        hostname="127.0.0.1",
        port=8000,
        path="/app/",
        resolved_addresses=("127.0.0.1",),
    )
    record = issue_authorization(
        store,
        target,
        owner=f"Local owner {family_suffix}",
        approved_by="Supervisor",
        purpose="Governed passive collection",
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


def create_active_campaign(
    store: GovernanceStore,
    authorization_store: AuthorizationStore,
    authorization_id: str,
    *,
    minimum_observations: int = 1,
    conflict_tags: tuple[str, ...] = (),
):
    campaign = create_campaign(
        store,
        actor_id="admin-a",
        actor_secret=ADMIN_SECRET,
        title="Governed collection",
        purpose="Collect independently reviewed local evidence",
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
        minimum_reviewed_observations=minimum_observations,
        now=NOW,
    )
    application = register_application(
        store,
        authorization_store,
        actor_id="admin-a",
        actor_secret=ADMIN_SECRET,
        campaign_id=campaign.campaign_id,
        authorization_id=authorization_id,
        application_family="demo-family",
        environment="local-test",
        conflict_tags=conflict_tags,
        now=NOW,
    )
    approve_campaign(
        store,
        authorization_store,
        actor_id="admin-b",
        actor_secret=APPROVER_SECRET,
        campaign_id=campaign.campaign_id,
        now=NOW,
    )
    campaign = activate_campaign(
        store,
        authorization_store,
        actor_id="admin-b",
        actor_secret=APPROVER_SECRET,
        campaign_id=campaign.campaign_id,
        now=NOW,
    )
    return campaign, application


def create_completed_scan(
    database: Path,
    authorization_store: AuthorizationStore,
    authorization_id: str,
    *,
    outcome_name: str = "traceback",
) -> tuple[ScanRepository, int, int]:
    repository = ScanRepository.from_path(database)
    repository.initialize()
    target_url = "http://127.0.0.1:8000/app/"
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
            "scan_database": str(database.expanduser().resolve()),
            "target_url": target_url,
        },
    )
    observation = Observation.create(
        category="debug_error_exposure",
        severity="high",
        title="Debug traceback exposed",
        description="A detailed traceback was visible.",
        url=target_url + "error",
        evidence={"detected_indicators": [outcome_name]},
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
    authorization_store.append_event(
        authorization_id,
        "scan_completed",
        {"scan_id": scan_id, "pages_visited": 1, "observations": 1},
    )
    observation_id = repository.list_observations(scan_id=scan_id)[0].id
    return repository, scan_id, observation_id
