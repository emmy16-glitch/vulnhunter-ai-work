from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from governance_test_support import (
    ADJUDICATOR_SECRET,
    ADMIN_SECRET,
    NOW,
    REVIEWER_ONE_SECRET,
    REVIEWER_TWO_SECRET,
    create_completed_scan,
    make_governance_store,
)
from test_governance_workflow import assign_default, prepare_world

from vulnhunter.authorization import AuthorizationStore
from vulnhunter.governance.readiness import assess_pilot_readiness
from vulnhunter.governance.service import (
    assign_reviewers,
    change_identity_status,
    complete_campaign,
    link_scan,
    release_dataset,
    submit_governed_review,
)
from vulnhunter.observations.storage import ScanRepository


def _repository_map(scan_database: Path, repository: ScanRepository) -> dict[str, ScanRepository]:
    return {str(scan_database.expanduser().resolve()): repository}


def _attest_consensus(governance_store, world, observation_id: int | None = None) -> None:
    observation = observation_id or world["observation_id"]
    submit_governed_review(
        governance_store,
        world["repository"],
        actor_id="reviewer-a",
        actor_secret=REVIEWER_ONE_SECRET,
        campaign_id=world["campaign"].campaign_id,
        scan_database=world["scan_database"],
        observation_id=observation,
        outcome="confirmed",
        note="confirmed by reviewer a",
        now=NOW,
    )
    submit_governed_review(
        governance_store,
        world["repository"],
        actor_id="reviewer-b",
        actor_secret=REVIEWER_TWO_SECRET,
        campaign_id=world["campaign"].campaign_id,
        scan_database=world["scan_database"],
        observation_id=observation,
        outcome="confirmed",
        note="confirmed by reviewer b",
        now=NOW,
    )


def _complete_and_release(governance_store, world) -> None:
    repositories = _repository_map(world["scan_database"], world["repository"])
    complete_campaign(
        governance_store,
        world["authorization_store"],
        repositories,
        actor_id="admin-a",
        actor_secret=ADMIN_SECRET,
        campaign_id=world["campaign"].campaign_id,
        now=NOW,
    )
    release_dataset(
        governance_store,
        world["authorization_store"],
        repositories,
        actor_id="admin-a",
        actor_secret=ADMIN_SECRET,
        campaign_id=world["campaign"].campaign_id,
        now=NOW,
    )


def test_readiness_succeeds_for_complete_synthetic_campaign(tmp_path: Path) -> None:
    governance_store = make_governance_store(tmp_path)
    world = prepare_world(governance_store, tmp_path)
    assign_default(governance_store, world)
    _attest_consensus(governance_store, world)
    _complete_and_release(governance_store, world)

    report = assess_pilot_readiness(
        governance_store,
        world["authorization_store"],
        _repository_map(world["scan_database"], world["repository"]),
        campaign_id=world["campaign"].campaign_id,
        now=NOW,
    )

    assert report.pilot_ready is True
    assert report.hard_release_blockers == ()
    assert report.informational_metrics["release_manifest_present"] is True
    assert report.informational_metrics["application_families"] == {"demo-family": 1}
    assert report.model_training_ready is False
    assert report.model_training_blockers


def test_readiness_fails_for_missing_authorization(tmp_path: Path) -> None:
    governance_store = make_governance_store(tmp_path)
    world = prepare_world(governance_store, tmp_path)
    assign_default(governance_store, world)
    _attest_consensus(governance_store, world)

    empty_authorizations = AuthorizationStore.from_path(tmp_path / "empty-auth.db")
    empty_authorizations.initialize()
    report = assess_pilot_readiness(
        governance_store,
        empty_authorizations,
        _repository_map(world["scan_database"], world["repository"]),
        campaign_id=world["campaign"].campaign_id,
        now=NOW,
    )

    assert report.pilot_ready is False
    assert any("authorization" in reason for reason in report.hard_release_blockers)


def test_readiness_fails_for_scan_provenance_mismatch(tmp_path: Path) -> None:
    governance_store = make_governance_store(tmp_path)
    world = prepare_world(governance_store, tmp_path)
    assign_default(governance_store, world)
    _attest_consensus(governance_store, world)
    _complete_and_release(governance_store, world)

    with sqlite3.connect(world["scan_database"]) as connection:
        connection.execute("UPDATE scans SET pages_visited = pages_visited + 1")

    report = assess_pilot_readiness(
        governance_store,
        world["authorization_store"],
        _repository_map(world["scan_database"], world["repository"]),
        campaign_id=world["campaign"].campaign_id,
        now=NOW,
    )

    assert report.pilot_ready is False
    assert any("scan" in reason and "changed" in reason for reason in report.hard_release_blockers)


def test_readiness_fails_for_incomplete_review(tmp_path: Path) -> None:
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
        note="first review only",
        now=NOW,
    )

    report = assess_pilot_readiness(
        governance_store,
        world["authorization_store"],
        _repository_map(world["scan_database"], world["repository"]),
        campaign_id=world["campaign"].campaign_id,
        now=NOW,
    )

    assert report.pilot_ready is False
    assert any("pending_second_review" in reason for reason in report.hard_release_blockers)


def test_readiness_fails_for_unresolved_disagreement(tmp_path: Path) -> None:
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
        note="confirmed",
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
        note="disputed",
        now=NOW,
    )

    report = assess_pilot_readiness(
        governance_store,
        world["authorization_store"],
        _repository_map(world["scan_database"], world["repository"]),
        campaign_id=world["campaign"].campaign_id,
        now=NOW,
    )

    assert report.pilot_ready is False
    assert any("disputed" in reason for reason in report.hard_release_blockers)


def test_readiness_fails_for_revoked_reviewer_evidence(tmp_path: Path) -> None:
    governance_store = make_governance_store(tmp_path)
    world = prepare_world(governance_store, tmp_path)
    assign_default(governance_store, world)
    _attest_consensus(governance_store, world)
    _complete_and_release(governance_store, world)

    change_identity_status(
        governance_store,
        actor_id="admin-a",
        actor_secret=ADMIN_SECRET,
        reviewer_id="reviewer-a",
        status="revoked",
        reason="synthetic compromise drill",
        now=NOW,
    )
    report = assess_pilot_readiness(
        governance_store,
        world["authorization_store"],
        _repository_map(world["scan_database"], world["repository"]),
        campaign_id=world["campaign"].campaign_id,
        now=NOW,
    )

    assert report.pilot_ready is False
    assert any("reviewer-a" in reason for reason in report.hard_release_blockers)


def test_readiness_fails_for_missing_release_manifest(tmp_path: Path) -> None:
    governance_store = make_governance_store(tmp_path)
    world = prepare_world(governance_store, tmp_path)
    assign_default(governance_store, world)
    _attest_consensus(governance_store, world)

    report = assess_pilot_readiness(
        governance_store,
        world["authorization_store"],
        _repository_map(world["scan_database"], world["repository"]),
        campaign_id=world["campaign"].campaign_id,
        now=NOW,
    )

    assert report.pilot_ready is False
    assert "dataset release manifest is missing" in report.hard_release_blockers


def test_readiness_fails_for_tampered_release_manifest(tmp_path: Path) -> None:
    governance_store = make_governance_store(tmp_path)
    world = prepare_world(governance_store, tmp_path)
    assign_default(governance_store, world)
    _attest_consensus(governance_store, world)
    _complete_and_release(governance_store, world)

    with sqlite3.connect(tmp_path / "governance.db") as connection:
        record = json.loads(
            connection.execute("SELECT record_json FROM governance_releases").fetchone()[0]
        )
        record["effective_labels"][next(iter(record["effective_labels"]))] = "false_positive"
        connection.execute(
            "UPDATE governance_releases SET record_json = ?",
            (json.dumps(record, sort_keys=True),),
        )

    report = assess_pilot_readiness(
        governance_store,
        world["authorization_store"],
        _repository_map(world["scan_database"], world["repository"]),
        campaign_id=world["campaign"].campaign_id,
        now=NOW,
    )

    assert report.pilot_ready is False
    assert any(
        "release" in reason and "integrity" in reason for reason in report.hard_release_blockers
    )


def test_duplicate_leakage_warnings_and_deterministic_fingerprint(tmp_path: Path) -> None:
    governance_store = make_governance_store(tmp_path)
    world = prepare_world(governance_store, tmp_path)
    assign_default(governance_store, world)
    _attest_consensus(governance_store, world)

    repository, second_scan_id, second_observation_id = create_completed_scan(
        world["scan_database"],
        world["authorization_store"],
        world["authorization"].authorization_id,
    )
    world["repository"] = repository
    link_scan(
        governance_store,
        world["authorization_store"],
        repository,
        actor_id="admin-a",
        actor_secret=ADMIN_SECRET,
        campaign_id=world["campaign"].campaign_id,
        application_id=world["application"].application_id,
        scan_database=world["scan_database"],
        scan_id=second_scan_id,
        now=NOW,
    )
    assign_reviewers(
        governance_store,
        repository,
        actor_id="admin-a",
        actor_secret=ADMIN_SECRET,
        campaign_id=world["campaign"].campaign_id,
        scan_database=world["scan_database"],
        observation_id=second_observation_id,
        first_reviewer_id="reviewer-a",
        second_reviewer_id="reviewer-b",
        adjudicator_id="lead-c",
        now=NOW,
    )
    _attest_consensus(governance_store, world, second_observation_id)
    _complete_and_release(governance_store, world)

    report = assess_pilot_readiness(
        governance_store,
        world["authorization_store"],
        _repository_map(world["scan_database"], repository),
        campaign_id=world["campaign"].campaign_id,
        now=NOW,
    )
    repeated = assess_pilot_readiness(
        governance_store,
        world["authorization_store"],
        _repository_map(world["scan_database"], repository),
        campaign_id=world["campaign"].campaign_id,
        now=NOW,
    )

    assert report.pilot_ready is True
    assert report.report_sha256 == repeated.report_sha256
    assert report.informational_metrics["duplicate_fingerprint_count"] == 1
    assert report.informational_metrics["duplicate_evidence_count"] == 1
    assert any("duplicate" in warning.lower() for warning in report.warnings)
    assert any("Duplicate" in reason for reason in report.model_training_blockers)


def test_adjudicated_disagreement_counts_as_complete(tmp_path: Path) -> None:
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
        note="confirmed",
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
        note="disputed",
        now=NOW,
    )
    from vulnhunter.governance.service import adjudicate_governed_review

    adjudicate_governed_review(
        governance_store,
        world["repository"],
        actor_id="lead-c",
        actor_secret=ADJUDICATOR_SECRET,
        campaign_id=world["campaign"].campaign_id,
        scan_database=world["scan_database"],
        observation_id=world["observation_id"],
        outcome="confirmed",
        rationale="synthetic adjudication",
        now=NOW,
    )
    _complete_and_release(governance_store, world)

    report = assess_pilot_readiness(
        governance_store,
        world["authorization_store"],
        _repository_map(world["scan_database"], world["repository"]),
        campaign_id=world["campaign"].campaign_id,
        now=NOW,
    )

    assert report.pilot_ready is True
    assert report.informational_metrics["disagreement_count"] == 1
    assert report.informational_metrics["adjudicated_count"] == 1


def test_readiness_reports_application_family_diversity(tmp_path: Path) -> None:
    governance_store = make_governance_store(tmp_path)
    world = prepare_world(governance_store, tmp_path)

    report = assess_pilot_readiness(
        governance_store,
        world["authorization_store"],
        _repository_map(world["scan_database"], world["repository"]),
        campaign_id=world["campaign"].campaign_id,
        now=NOW,
    )

    assert report.informational_metrics["application_family_count"] == 1
    assert report.informational_metrics["application_families"] == {"demo-family": 1}
