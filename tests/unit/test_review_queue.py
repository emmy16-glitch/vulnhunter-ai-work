"""Review queue ordering, duplicate context, and CLI evidence tests."""

from datetime import UTC, datetime
from pathlib import Path

from typer.testing import CliRunner

from vulnhunter.cli import app
from vulnhunter.mapping.models import MappedPage, MappingResult
from vulnhunter.observations.models import Observation
from vulnhunter.observations.storage import ScanRepository

runner = CliRunner()


def persist_scan(
    repository: ScanRepository,
    *,
    target: str,
    observations: tuple[Observation, ...],
) -> None:
    scan_id = repository.create_scan(target)
    pages = tuple(
        MappedPage(
            url=observation.url,
            depth=0,
            status_code=500 if observation.severity == "high" else 200,
            response_bytes=100,
            elapsed_ms=1.0,
        )
        for observation in observations
    )
    repository.complete_scan(
        scan_id,
        MappingResult(
            target_url=target,
            started_at=datetime.now(UTC),
            completed_at=datetime.now(UTC),
            pages=pages,
            observations=observations,
            discovered_urls=len(pages),
            rejected_links=0,
        ),
    )


def test_review_queue_prioritises_severity_and_counts_repeated_fingerprints(
    tmp_path: Path,
) -> None:
    database = tmp_path / "queue.db"
    repository = ScanRepository.from_path(database)
    repository.initialize()
    repeated = Observation.create(
        category="debug_error_exposure",
        severity="high",
        title="Debug traceback exposed",
        description="A detailed traceback was visible.",
        url="http://127.0.0.1:8000/error",
        evidence={"status_code": 500, "detected_indicators": ["traceback"]},
    )
    low = Observation.create(
        category="technology_disclosure",
        severity="info",
        title="Server header visible",
        description="An informational server header was visible.",
        url="http://127.0.0.1:8000/",
        evidence={"headers": {"server": "lab"}},
    )
    persist_scan(
        repository,
        target="http://127.0.0.1:8000/",
        observations=(low, repeated),
    )
    persist_scan(
        repository,
        target="http://127.0.0.1:8000/",
        observations=(repeated,),
    )

    queue = repository.list_review_queue(limit=10)
    counts = repository.fingerprint_occurrence_counts(tuple(item.fingerprint for item in queue))

    assert queue[0].severity == "high"
    assert counts[repeated.fingerprint] == 2

    cli_result = runner.invoke(
        app,
        ["findings", "queue", "--database", str(database), "--limit", "10"],
    )
    assert cli_result.exit_code == 0, cli_result.output
    assert "repeated_across_scans=2" in cli_result.output


def test_findings_show_displays_redacted_structured_evidence(tmp_path: Path) -> None:
    database = tmp_path / "show.db"
    repository = ScanRepository.from_path(database)
    repository.initialize()
    observation = Observation.create(
        category="missing_security_headers",
        severity="medium",
        title="Security headers missing",
        description="Expected defensive headers were absent.",
        url="http://127.0.0.1:8000/",
        evidence={"missing_headers": ["content-security-policy"]},
    )
    persist_scan(
        repository,
        target="http://127.0.0.1:8000/",
        observations=(observation,),
    )
    observation_id = repository.list_observations(limit=1)[0].id

    result = runner.invoke(
        app,
        ["findings", "show", str(observation_id), "--database", str(database)],
    )

    assert result.exit_code == 0, result.output
    assert "Evidence:" in result.output
    assert "content-security-policy" in result.output
