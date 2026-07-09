"""CLI tests for two-reviewer consensus and adjudication."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from typer.testing import CliRunner

from vulnhunter.cli import app
from vulnhunter.mapping.models import MappedPage, MappingResult
from vulnhunter.observations.models import Observation
from vulnhunter.observations.storage import ScanRepository

runner = CliRunner()


def create_database(tmp_path: Path) -> tuple[Path, int]:
    database = tmp_path / "review-cli.db"
    repository = ScanRepository.from_path(database)
    repository.initialize()
    observation = Observation.create(
        category="missing_security_headers",
        severity="medium",
        title="CSP missing",
        description="Content-Security-Policy was absent.",
        url="http://127.0.0.1:8000/",
        evidence={"missing_headers": ["content-security-policy"]},
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
                    status_code=200,
                    response_bytes=50,
                    elapsed_ms=1.0,
                ),
            ),
            observations=(observation,),
            discovered_urls=1,
            rejected_links=0,
        ),
    )
    return database, repository.list_observations(scan_id=scan_id)[0].id


def test_cli_records_two_reviewer_consensus(tmp_path: Path) -> None:
    database, observation_id = create_database(tmp_path)

    first = runner.invoke(
        app,
        [
            "findings",
            "review",
            str(observation_id),
            "--reviewer",
            "analyst-a",
            "--label",
            "confirmed",
            "--database",
            str(database),
        ],
    )
    second = runner.invoke(
        app,
        [
            "findings",
            "review",
            str(observation_id),
            "--reviewer",
            "analyst-b",
            "--label",
            "confirmed",
            "--database",
            str(database),
        ],
    )

    assert first.exit_code == 0, first.output
    assert "pending_second_review" in first.output
    assert second.exit_code == 0, second.output
    assert "State: consensus" in second.output
    assert "Effective label: confirmed" in second.output


def test_cli_dispute_and_adjudication(tmp_path: Path) -> None:
    database, observation_id = create_database(tmp_path)
    for reviewer, label in (
        ("analyst-a", "confirmed"),
        ("analyst-b", "false_positive"),
    ):
        result = runner.invoke(
            app,
            [
                "findings",
                "review",
                str(observation_id),
                "--reviewer",
                reviewer,
                "--label",
                label,
                "--database",
                str(database),
            ],
        )
        assert result.exit_code == 0, result.output

    disputes = runner.invoke(
        app,
        ["findings", "disputes", "--database", str(database)],
    )
    adjudication = runner.invoke(
        app,
        [
            "findings",
            "adjudicate",
            str(observation_id),
            "--adjudicator",
            "lead-c",
            "--label",
            "false_positive",
            "--rationale",
            "The missing header is expected for this isolated static page.",
            "--database",
            str(database),
        ],
    )

    assert disputes.exit_code == 0, disputes.output
    assert "analyst-a=confirmed" in disputes.output
    assert "analyst-b=false_positive" in disputes.output
    assert adjudication.exit_code == 0, adjudication.output
    assert "State: adjudicated" in adjudication.output
    assert "Effective label: false_positive" in adjudication.output


def test_cli_second_review_queue_is_reviewer_specific(tmp_path: Path) -> None:
    database, observation_id = create_database(tmp_path)
    first = runner.invoke(
        app,
        [
            "findings",
            "review",
            str(observation_id),
            "--reviewer",
            "analyst-a",
            "--label",
            "confirmed",
            "--database",
            str(database),
        ],
    )
    assert first.exit_code == 0, first.output

    own_queue = runner.invoke(
        app,
        [
            "findings",
            "second-review-queue",
            "--reviewer",
            "analyst-a",
            "--database",
            str(database),
        ],
    )
    other_queue = runner.invoke(
        app,
        [
            "findings",
            "second-review-queue",
            "--reviewer",
            "analyst-b",
            "--database",
            str(database),
        ],
    )

    assert "queue is empty" in own_queue.output
    assert f"#{observation_id}" in other_queue.output


def test_cli_rejects_legacy_single_review_command(tmp_path: Path) -> None:
    database, observation_id = create_database(tmp_path)

    result = runner.invoke(
        app,
        [
            "findings",
            "label",
            str(observation_id),
            "confirmed",
            "--database",
            str(database),
        ],
    )

    assert result.exit_code == 2
    assert "Direct single-review labelling is disabled" in result.output
