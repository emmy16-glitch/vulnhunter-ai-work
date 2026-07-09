"""CLI tests for dataset export, training, inspection, and prediction."""

from datetime import UTC, datetime
from pathlib import Path

from typer.testing import CliRunner

from vulnhunter.cli import app
from vulnhunter.mapping.models import MappedPage, MappingResult
from vulnhunter.observations.models import Observation
from vulnhunter.observations.storage import ScanRepository

runner = CliRunner()


def prepare_database(path: Path) -> int:
    repository = ScanRepository.from_path(path)
    repository.initialize()
    scan_id = repository.create_scan("http://127.0.0.1:8000/")
    observations = []
    pages = []

    for index in range(21):
        confirmed = index < 10 or index == 20
        url = f"http://127.0.0.1:8000/page/{index}"
        pages.append(
            MappedPage(
                url=url,
                depth=1,
                status_code=500 if confirmed else 200,
                response_bytes=100,
                elapsed_ms=1.0,
            )
        )
        observations.append(
            Observation.create(
                category=("debug_error_exposure" if confirmed else "technology_disclosure"),
                severity=("high" if confirmed else "info"),
                title=("Stack trace exposed" if confirmed else "Informational server banner"),
                description=(
                    "Detailed exception traceback was visible."
                    if confirmed
                    else "Low-risk generic implementation header."
                ),
                url=url,
                evidence=(
                    {"status_code": 500, "detected_indicators": ["traceback"]}
                    if confirmed
                    else {"headers": {"server": "lab"}}
                ),
            )
        )

    repository.complete_scan(
        scan_id,
        MappingResult(
            target_url="http://127.0.0.1:8000/",
            started_at=datetime.now(UTC),
            completed_at=datetime.now(UTC),
            pages=tuple(pages),
            observations=tuple(observations),
            discovered_urls=21,
            rejected_links=0,
        ),
    )
    rows = repository.list_observations(limit=100)
    by_url = {row.url: row for row in rows}

    for index in range(20):
        row = by_url[f"http://127.0.0.1:8000/page/{index}"]
        repository.label_observation(
            row.id,
            "confirmed" if index < 10 else "false_positive",
        )

    return by_url["http://127.0.0.1:8000/page/20"].id


def test_ml_cli_end_to_end(tmp_path: Path) -> None:
    database = tmp_path / "vulnhunter.db"
    dataset_path = tmp_path / "training.jsonl"
    model_path = tmp_path / "baseline.json"
    prediction_id = prepare_database(database)

    export_result = runner.invoke(
        app,
        ["ml", "export", "--database", str(database), "--output", str(dataset_path)],
    )
    assert export_result.exit_code == 0, export_result.output
    assert "Exported 20 reviewed observations" in export_result.output

    train_result = runner.invoke(
        app,
        [
            "ml",
            "train",
            "--database",
            str(database),
            "--model",
            str(model_path),
        ],
    )
    assert train_result.exit_code == 0, train_result.output
    assert "Baseline model trained" in train_result.output
    assert "Human review remains authoritative" in train_result.output

    info_result = runner.invoke(app, ["ml", "info", "--model", str(model_path)])
    assert info_result.exit_code == 0, info_result.output
    assert "Model type: multinomial_naive_bayes" in info_result.output

    prediction_result = runner.invoke(
        app,
        [
            "ml",
            "predict",
            str(prediction_id),
            "--database",
            str(database),
            "--model",
            str(model_path),
        ],
    )
    assert prediction_result.exit_code == 0, prediction_result.output
    assert "Current human label: unreviewed" in prediction_result.output
    assert "Model prediction: confirmed" in prediction_result.output
    assert "stored human label was not changed" in prediction_result.output
