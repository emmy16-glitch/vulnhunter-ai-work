"""Independent second-review, dispute, and adjudication tests."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from vulnhunter.mapping.models import MappedPage, MappingResult
from vulnhunter.observations.models import Observation
from vulnhunter.observations.storage import ScanRepository


def create_observation(repository: ScanRepository) -> int:
    observation = Observation.create(
        category="debug_error_exposure",
        severity="high",
        title="Debug traceback exposed",
        description="A detailed traceback was visible.",
        url="http://127.0.0.1:8000/error",
        evidence={"status_code": 500, "detected_indicators": ["traceback"]},
    )
    now = datetime.now(UTC)
    scan_id = repository.create_scan("http://127.0.0.1:8000/")
    repository.complete_scan(
        scan_id,
        MappingResult(
            target_url="http://127.0.0.1:8000/",
            started_at=now,
            completed_at=now,
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
    return repository.list_observations(scan_id=scan_id)[0].id


def make_repository(tmp_path: Path) -> ScanRepository:
    repository = ScanRepository.from_path(tmp_path / "reviews.db")
    repository.initialize()
    return repository


def test_first_decision_requires_distinct_second_reviewer(tmp_path: Path) -> None:
    repository = make_repository(tmp_path)
    observation_id = create_observation(repository)

    case = repository.submit_review_decision(
        observation_id,
        "analyst-a",
        "confirmed",
        note="Traceback contains framework internals.",
    )

    assert case.state == "pending_second_review"
    assert case.effective_label == "needs_review"
    assert case.decisions[0].reviewer_id == "analyst-a"
    assert repository.list_training_observations() == ()


def test_same_reviewer_cannot_submit_twice(tmp_path: Path) -> None:
    repository = make_repository(tmp_path)
    observation_id = create_observation(repository)
    repository.submit_review_decision(observation_id, "analyst-a", "confirmed")

    with pytest.raises(ValueError, match="only one immutable"):
        repository.submit_review_decision(
            observation_id,
            "ANALYST-A",
            "false_positive",
        )


def test_matching_independent_decisions_establish_consensus(tmp_path: Path) -> None:
    repository = make_repository(tmp_path)
    observation_id = create_observation(repository)
    repository.submit_review_decision(observation_id, "analyst-a", "confirmed")

    case = repository.submit_review_decision(
        observation_id,
        "analyst-b",
        "confirmed",
    )

    assert case.state == "consensus"
    assert case.effective_label == "confirmed"
    assert len(repository.list_training_observations()) == 1


def test_disagreement_is_excluded_until_adjudicated(tmp_path: Path) -> None:
    repository = make_repository(tmp_path)
    observation_id = create_observation(repository)
    repository.submit_review_decision(observation_id, "analyst-a", "confirmed")
    case = repository.submit_review_decision(
        observation_id,
        "analyst-b",
        "false_positive",
    )

    assert case.state == "disputed"
    assert case.effective_label == "needs_review"
    assert repository.list_training_observations() == ()
    assert repository.list_disputed_review_cases()[0].observation.id == observation_id


def test_distinct_adjudicator_resolves_disagreement(tmp_path: Path) -> None:
    repository = make_repository(tmp_path)
    observation_id = create_observation(repository)
    repository.submit_review_decision(observation_id, "analyst-a", "confirmed")
    repository.submit_review_decision(
        observation_id,
        "analyst-b",
        "false_positive",
    )

    case = repository.adjudicate_review(
        observation_id,
        "lead-c",
        "confirmed",
        rationale="The exposed traceback contains actionable internal details.",
    )

    assert case.state == "adjudicated"
    assert case.effective_label == "confirmed"
    assert case.adjudication is not None
    assert case.adjudication.adjudicator_id == "lead-c"
    assert len(repository.list_training_observations()) == 1
    assert repository.list_disputed_review_cases() == ()


def test_primary_reviewer_cannot_adjudicate_own_dispute(tmp_path: Path) -> None:
    repository = make_repository(tmp_path)
    observation_id = create_observation(repository)
    repository.submit_review_decision(observation_id, "analyst-a", "confirmed")
    repository.submit_review_decision(
        observation_id,
        "analyst-b",
        "false_positive",
    )

    with pytest.raises(ValueError, match="distinct from both"):
        repository.adjudicate_review(
            observation_id,
            "analyst-a",
            "confirmed",
            rationale="Attempted self-adjudication.",
        )


def test_second_review_queue_excludes_first_reviewer(tmp_path: Path) -> None:
    repository = make_repository(tmp_path)
    observation_id = create_observation(repository)
    repository.submit_review_decision(observation_id, "analyst-a", "confirmed")

    assert repository.list_second_review_queue("analyst-a") == ()
    queue = repository.list_second_review_queue("analyst-b")
    assert queue[0].observation.id == observation_id


def test_legacy_single_review_cannot_overwrite_governed_case(tmp_path: Path) -> None:
    repository = make_repository(tmp_path)
    observation_id = create_observation(repository)
    repository.submit_review_decision(observation_id, "analyst-a", "confirmed")

    with pytest.raises(ValueError, match="governed by independent review"):
        repository.label_observation(observation_id, "false_positive")
