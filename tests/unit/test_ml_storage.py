"""Storage integration tests for ML-labelled observations."""

from datetime import UTC, datetime
from pathlib import Path

from vulnhunter.mapping.models import MappedPage, MappingResult
from vulnhunter.observations.models import Observation
from vulnhunter.observations.storage import ScanRepository


def test_repository_returns_stable_training_rows_and_single_observation(
    tmp_path: Path,
) -> None:
    repository = ScanRepository.from_path(tmp_path / "training.db")
    repository.initialize()
    scan_id = repository.create_scan("http://127.0.0.1:8000/")
    observation_one = Observation.create(
        category="debug_error_exposure",
        severity="high",
        title="Debug page exposed",
        description="Detailed exception information was visible.",
        url="http://127.0.0.1:8000/error",
        evidence={"status_code": 500},
    )
    observation_two = Observation.create(
        category="technology_disclosure",
        severity="info",
        title="Server banner visible",
        description="Informational server header was visible.",
        url="http://127.0.0.1:8000/",
        evidence={"headers": {"server": "lab"}},
    )
    result = MappingResult(
        target_url="http://127.0.0.1:8000/",
        started_at=datetime.now(UTC),
        completed_at=datetime.now(UTC),
        pages=(
            MappedPage(
                url="http://127.0.0.1:8000/",
                depth=0,
                status_code=200,
                response_bytes=10,
                elapsed_ms=1.0,
            ),
            MappedPage(
                url="http://127.0.0.1:8000/error",
                depth=1,
                status_code=500,
                response_bytes=10,
                elapsed_ms=1.0,
            ),
        ),
        observations=(observation_one, observation_two),
        discovered_urls=2,
        rejected_links=0,
    )
    repository.complete_scan(scan_id, result)
    rows = repository.list_observations(limit=10)
    by_category = {row.category: row for row in rows}
    repository.label_observation(by_category["debug_error_exposure"].id, "confirmed")
    repository.label_observation(by_category["technology_disclosure"].id, "false_positive")

    training_rows = repository.list_training_observations()

    assert [row.id for row in training_rows] == sorted(row.id for row in training_rows)
    assert {row.review_label for row in training_rows} == {
        "confirmed",
        "false_positive",
    }
    assert repository.get_observation(training_rows[0].id) == training_rows[0]
