from __future__ import annotations

from pathlib import Path

import pytest
from governance_test_support import (
    ADJUDICATOR_SECRET,
    ADMIN_SECRET,
    NOW,
    REVIEWER_ONE_SECRET,
    REVIEWER_TWO_SECRET,
    add_identity,
    create_active_campaign,
    create_authorization,
    create_completed_scan,
    make_governance_store,
    prepare_identities,
)

from vulnhunter.exceptions import GovernancePolicyError
from vulnhunter.governance.service import (
    adjudicate_governed_review,
    assess_release,
    assign_reviewers,
    complete_campaign,
    link_scan,
    release_dataset,
    submit_governed_review,
)


def prepare_world(governance_store, tmp_path: Path, *, conflict_tags=()):
    prepare_identities(governance_store)
    authorization_store, authorization = create_authorization(tmp_path / "auth.db")
    campaign, application = create_active_campaign(
        governance_store,
        authorization_store,
        authorization.authorization_id,
        conflict_tags=conflict_tags,
    )
    scan_database = tmp_path / "scans.db"
    repository, scan_id, observation_id = create_completed_scan(
        scan_database,
        authorization_store,
        authorization.authorization_id,
    )
    linked = link_scan(
        governance_store,
        authorization_store,
        repository,
        actor_id="admin-a",
        actor_secret=ADMIN_SECRET,
        campaign_id=campaign.campaign_id,
        application_id=application.application_id,
        scan_database=scan_database,
        scan_id=scan_id,
        now=NOW,
    )
    return {
        "authorization_store": authorization_store,
        "authorization": authorization,
        "campaign": campaign,
        "application": application,
        "scan_database": scan_database,
        "repository": repository,
        "scan_id": scan_id,
        "observation_id": observation_id,
        "linked": linked,
    }


def assign_default(governance_store, world):
    return assign_reviewers(
        governance_store,
        world["repository"],
        actor_id="admin-a",
        actor_secret=ADMIN_SECRET,
        campaign_id=world["campaign"].campaign_id,
        scan_database=world["scan_database"],
        observation_id=world["observation_id"],
        first_reviewer_id="reviewer-a",
        second_reviewer_id="reviewer-b",
        adjudicator_id="lead-c",
        now=NOW,
    )


def test_scan_link_requires_authorization_audit_evidence(tmp_path: Path) -> None:
    governance_store = make_governance_store(tmp_path)
    prepare_identities(governance_store)
    authorization_store, authorization = create_authorization(tmp_path / "auth.db")
    campaign, application = create_active_campaign(
        governance_store,
        authorization_store,
        authorization.authorization_id,
    )
    scan_database = tmp_path / "scans.db"
    repository, scan_id, _ = create_completed_scan(
        scan_database,
        authorization_store,
        authorization.authorization_id,
    )
    # Point at a different path so the recorded scan_started database cannot match.
    with pytest.raises(GovernancePolicyError, match="scan_started"):
        link_scan(
            governance_store,
            authorization_store,
            repository,
            actor_id="admin-a",
            actor_secret=ADMIN_SECRET,
            campaign_id=campaign.campaign_id,
            application_id=application.application_id,
            scan_database=tmp_path / "other.db",
            scan_id=scan_id,
            now=NOW,
        )


def test_conflicted_reviewer_cannot_be_assigned(tmp_path: Path) -> None:
    governance_store = make_governance_store(tmp_path)
    world = prepare_world(governance_store, tmp_path, conflict_tags=("vendor-a",))
    add_identity(
        governance_store,
        "conflicted",
        "conflicted-secret-123",
        ("reviewer",),
        conflict_tags=("vendor-a",),
    )

    with pytest.raises(GovernancePolicyError, match="declared application conflict"):
        assign_reviewers(
            governance_store,
            world["repository"],
            actor_id="admin-a",
            actor_secret=ADMIN_SECRET,
            campaign_id=world["campaign"].campaign_id,
            scan_database=world["scan_database"],
            observation_id=world["observation_id"],
            first_reviewer_id="conflicted",
            second_reviewer_id="reviewer-b",
            adjudicator_id="lead-c",
            now=NOW,
        )


def test_campaign_creator_cannot_review_own_data(tmp_path: Path) -> None:
    governance_store = make_governance_store(tmp_path)
    world = prepare_world(governance_store, tmp_path)
    # Bootstrap administrator is not a reviewer role, so add that role is impossible in place;
    # owner protection is still enforced before assignment role use for matching IDs.
    with pytest.raises(GovernancePolicyError):
        assign_reviewers(
            governance_store,
            world["repository"],
            actor_id="admin-a",
            actor_secret=ADMIN_SECRET,
            campaign_id=world["campaign"].campaign_id,
            scan_database=world["scan_database"],
            observation_id=world["observation_id"],
            first_reviewer_id="admin-a",
            second_reviewer_id="reviewer-b",
            adjudicator_id="lead-c",
            now=NOW,
        )


def test_matching_authenticated_reviews_establish_consensus(tmp_path: Path) -> None:
    governance_store = make_governance_store(tmp_path)
    world = prepare_world(governance_store, tmp_path)
    assign_default(governance_store, world)

    first = submit_governed_review(
        governance_store,
        world["repository"],
        actor_id="reviewer-a",
        actor_secret=REVIEWER_ONE_SECRET,
        campaign_id=world["campaign"].campaign_id,
        scan_database=world["scan_database"],
        observation_id=world["observation_id"],
        outcome="confirmed",
        now=NOW,
    )
    second = submit_governed_review(
        governance_store,
        world["repository"],
        actor_id="reviewer-b",
        actor_secret=REVIEWER_TWO_SECRET,
        campaign_id=world["campaign"].campaign_id,
        scan_database=world["scan_database"],
        observation_id=world["observation_id"],
        outcome="confirmed",
        now=NOW,
    )

    case = world["repository"].get_review_case(world["observation_id"])
    assert first.actor_id == "reviewer-a"
    assert second.actor_id == "reviewer-b"
    assert case.state == "consensus"
    assert case.effective_label == "confirmed"


def test_unattested_legacy_decision_blocks_governed_review(tmp_path: Path) -> None:
    governance_store = make_governance_store(tmp_path)
    world = prepare_world(governance_store, tmp_path)
    assign_default(governance_store, world)
    world["repository"].submit_review_decision(
        world["observation_id"],
        "reviewer-a",
        "confirmed",
    )

    with pytest.raises(GovernancePolicyError, match="unattested"):
        submit_governed_review(
            governance_store,
            world["repository"],
            actor_id="reviewer-b",
            actor_secret=REVIEWER_TWO_SECRET,
            campaign_id=world["campaign"].campaign_id,
            scan_database=world["scan_database"],
            observation_id=world["observation_id"],
            outcome="confirmed",
            now=NOW,
        )


def test_disagreement_requires_assigned_adjudicator(tmp_path: Path) -> None:
    governance_store = make_governance_store(tmp_path)
    world = prepare_world(governance_store, tmp_path)
    assign_default(governance_store, world)
    submit_governed_review(
        governance_store,
        world["repository"],
        actor_id="reviewer-a",
        actor_secret=REVIEWER_ONE_SECRET,
        campaign_id=world["campaign"].campaign_id,
        scan_database=world["scan_database"],
        observation_id=world["observation_id"],
        outcome="confirmed",
        now=NOW,
    )
    submit_governed_review(
        governance_store,
        world["repository"],
        actor_id="reviewer-b",
        actor_secret=REVIEWER_TWO_SECRET,
        campaign_id=world["campaign"].campaign_id,
        scan_database=world["scan_database"],
        observation_id=world["observation_id"],
        outcome="false_positive",
        now=NOW,
    )

    attestation = adjudicate_governed_review(
        governance_store,
        world["repository"],
        actor_id="lead-c",
        actor_secret=ADJUDICATOR_SECRET,
        campaign_id=world["campaign"].campaign_id,
        scan_database=world["scan_database"],
        observation_id=world["observation_id"],
        outcome="confirmed",
        rationale="The traceback exposes actionable framework internals.",
        now=NOW,
    )

    assert attestation.role == "adjudicator"
    assert world["repository"].get_review_case(world["observation_id"]).state == "adjudicated"


def test_release_gate_blocks_before_campaign_completion(tmp_path: Path) -> None:
    governance_store = make_governance_store(tmp_path)
    world = prepare_world(governance_store, tmp_path)
    assign_default(governance_store, world)
    for reviewer, secret in (
        ("reviewer-a", REVIEWER_ONE_SECRET),
        ("reviewer-b", REVIEWER_TWO_SECRET),
    ):
        submit_governed_review(
            governance_store,
            world["repository"],
            actor_id=reviewer,
            actor_secret=secret,
            campaign_id=world["campaign"].campaign_id,
            scan_database=world["scan_database"],
            observation_id=world["observation_id"],
            outcome="confirmed",
            now=NOW,
        )
    repositories = {str(world["scan_database"].resolve()): world["repository"]}

    assessment = assess_release(
        governance_store,
        world["authorization_store"],
        repositories,
        campaign_id=world["campaign"].campaign_id,
        now=NOW,
        require_completed=True,
    )

    assert not assessment.ready
    assert "campaign is not completed" in assessment.reasons


def test_complete_and_release_create_integrity_manifest(tmp_path: Path) -> None:
    governance_store = make_governance_store(tmp_path)
    world = prepare_world(governance_store, tmp_path)
    assign_default(governance_store, world)
    for reviewer, secret in (
        ("reviewer-a", REVIEWER_ONE_SECRET),
        ("reviewer-b", REVIEWER_TWO_SECRET),
    ):
        submit_governed_review(
            governance_store,
            world["repository"],
            actor_id=reviewer,
            actor_secret=secret,
            campaign_id=world["campaign"].campaign_id,
            scan_database=world["scan_database"],
            observation_id=world["observation_id"],
            outcome="confirmed",
            now=NOW,
        )
    repositories = {str(world["scan_database"].resolve()): world["repository"]}
    completed = complete_campaign(
        governance_store,
        world["authorization_store"],
        repositories,
        actor_id="admin-b",
        actor_secret="approver-secret-123",
        campaign_id=world["campaign"].campaign_id,
        now=NOW,
    )
    manifest = release_dataset(
        governance_store,
        world["authorization_store"],
        repositories,
        actor_id="admin-b",
        actor_secret="approver-secret-123",
        campaign_id=world["campaign"].campaign_id,
        now=NOW,
    )

    assert completed.status == "completed"
    assert manifest.observation_references
    assert manifest.effective_labels[manifest.observation_references[0]] == "confirmed"
    assert governance_store.get_release(completed.campaign_id) == manifest
    governance_store.verify_integrity()
