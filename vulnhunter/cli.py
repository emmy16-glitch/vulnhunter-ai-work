"""Command-line interface for VulnHunter AI."""

from __future__ import annotations

import asyncio
import os
import platform
import sys
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from vulnhunter import __version__
from vulnhunter.exceptions import (
    MachineLearningError,
    ScopeValidationError,
    VulnHunterError,
)
from vulnhunter.mapping import MapperPolicy, SiteMapper
from vulnhunter.ml import (
    build_dataset,
    export_jsonl,
    load_model,
    predict,
    save_model,
    to_model_input,
    train_baseline,
)
from vulnhunter.observations.models import ReviewOutcome
from vulnhunter.observations.storage import ScanRepository
from vulnhunter.scanner import HttpClientPolicy, SafeHttpClient
from vulnhunter.scope import ApprovedTarget, validate_target

app = typer.Typer(
    name="vulnhunter",
    help="Authorised laboratory-only vulnerability testing research platform.",
    no_args_is_help=True,
)

scope_app = typer.Typer(
    help="Validate and manage authorised laboratory targets.",
    no_args_is_help=True,
)
scan_app = typer.Typer(
    help="Run and inspect bounded passive mapping scans.",
    no_args_is_help=True,
)
findings_app = typer.Typer(
    help="List and apply human-review labels to observations.",
    no_args_is_help=True,
)
ml_app = typer.Typer(
    help="Export reviewed data and run the local baseline ML pipeline.",
    no_args_is_help=True,
)

app.add_typer(scope_app, name="scope")
app.add_typer(scan_app, name="scan")
app.add_typer(findings_app, name="findings")
app.add_typer(ml_app, name="ml")

DatabaseOption = Annotated[
    Path,
    typer.Option(
        "--database",
        "-d",
        help="SQLite database file used for local scan records.",
    ),
]


@app.command()
def version() -> None:
    """Display the installed VulnHunter version."""
    typer.echo(f"VulnHunter AI {__version__}")


@app.command()
def doctor() -> None:
    """Check the local VulnHunter development environment."""
    virtual_environment = os.environ.get("VIRTUAL_ENV")

    typer.echo("VulnHunter environment check")
    typer.echo("----------------------------")
    typer.echo(f"Version: {__version__}")
    typer.echo(f"Python: {platform.python_version()}")
    typer.echo(f"Python executable: {sys.executable}")
    typer.echo(f"Project directory: {Path.cwd()}")
    typer.echo(
        f"Virtual environment: {virtual_environment}"
        if virtual_environment
        else "Virtual environment: not active"
    )


@scope_app.command("check")
def scope_check(url: str) -> None:
    """Check whether a URL is permitted for laboratory testing."""
    try:
        target = validate_target(url)
    except ScopeValidationError as exc:
        typer.secho(
            f"Rejected: {exc}",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=2) from exc

    typer.secho(
        "Approved laboratory target",
        fg=typer.colors.GREEN,
    )
    typer.echo(f"Normalized URL: {target.normalized_url}")
    typer.echo(f"Scheme: {target.scheme}")
    typer.echo(f"Hostname: {target.hostname}")
    typer.echo(f"Port: {target.port}")
    typer.echo(f"Path boundary: {target.path}")
    typer.echo("Approved addresses: " + ", ".join(target.resolved_addresses))


def _repository(database: Path) -> ScanRepository:
    repository = ScanRepository.from_path(database)
    repository.initialize()
    return repository


async def _execute_scan(
    target: ApprovedTarget,
    *,
    maximum_pages: int,
    maximum_depth: int,
    maximum_requests: int,
    request_delay_seconds: float,
):
    mapper_policy = MapperPolicy(
        maximum_pages=maximum_pages,
        maximum_depth=maximum_depth,
    )
    http_policy = HttpClientPolicy(
        maximum_requests=maximum_requests,
        minimum_request_delay_seconds=request_delay_seconds,
    )

    async with SafeHttpClient(target, policy=http_policy) as client:
        mapper = SiteMapper(target, client, policy=mapper_policy)
        return target, await mapper.map()


@scan_app.command("run")
def scan_run(
    url: str,
    database: DatabaseOption = Path("vulnhunter.db"),
    maximum_pages: Annotated[
        int,
        typer.Option("--max-pages", min=1, max=500),
    ] = 20,
    maximum_depth: Annotated[
        int,
        typer.Option("--max-depth", min=0, max=10),
    ] = 2,
    maximum_requests: Annotated[
        int,
        typer.Option("--max-requests", min=1, max=10_000),
    ] = 100,
    request_delay_seconds: Annotated[
        float,
        typer.Option("--delay", min=0, max=10),
    ] = 0.2,
) -> None:
    """Map one approved target and persist passive observations."""
    try:
        target = validate_target(url)
    except ScopeValidationError as exc:
        typer.secho(f"Rejected: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc

    repository = _repository(database)
    scan_id = repository.create_scan(target.normalized_url)
    typer.echo(f"Started scan {scan_id}: {target.normalized_url}")

    try:
        _, result = asyncio.run(
            _execute_scan(
                target,
                maximum_pages=maximum_pages,
                maximum_depth=maximum_depth,
                maximum_requests=maximum_requests,
                request_delay_seconds=request_delay_seconds,
            )
        )
        repository.complete_scan(scan_id, result)
    except KeyboardInterrupt as exc:
        repository.fail_scan(scan_id, "Cancelled by operator.")
        typer.secho("Scan cancelled by operator.", fg=typer.colors.YELLOW, err=True)
        raise typer.Exit(code=130) from exc
    except (VulnHunterError, ValidationError, ValueError) as exc:
        repository.fail_scan(scan_id, str(exc))
        typer.secho(f"Scan failed safely: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc
    except Exception as exc:
        repository.fail_scan(scan_id, str(exc))
        raise

    typer.secho("Scan completed", fg=typer.colors.GREEN)
    typer.echo(f"Pages visited: {len(result.pages)}")
    typer.echo(f"Unique in-scope URLs discovered: {result.discovered_urls}")
    typer.echo(f"Rejected out-of-scope links: {result.rejected_links}")
    typer.echo(f"Passive observations: {len(result.observations)}")
    typer.echo(f"Database: {database.expanduser().resolve()}")


@scan_app.command("list")
def scan_list(
    database: DatabaseOption = Path("vulnhunter.db"),
    limit: Annotated[int, typer.Option("--limit", min=1, max=500)] = 50,
) -> None:
    """List recent persisted scans."""
    scans = _repository(database).list_scans(limit=limit)

    if not scans:
        typer.echo("No scans found.")
        return

    for scan in scans:
        typer.echo(
            f"#{scan.id} {scan.status.upper()} pages={scan.pages_visited} "
            f"observations={scan.observations_count} target={scan.target_url}"
        )


@findings_app.command("list")
def findings_list(
    database: DatabaseOption = Path("vulnhunter.db"),
    scan_id: Annotated[int | None, typer.Option("--scan-id", min=1)] = None,
    label: Annotated[str | None, typer.Option("--label")] = None,
    limit: Annotated[int, typer.Option("--limit", min=1, max=1_000)] = 100,
) -> None:
    """List passive observations awaiting or carrying human review."""
    repository = _repository(database)

    try:
        observations = repository.list_observations(
            scan_id=scan_id,
            review_label=label,
            limit=limit,
        )
    except (ValidationError, ValueError) as exc:
        typer.secho(f"Invalid filter: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc

    if not observations:
        typer.echo("No observations found.")
        return

    for observation in observations:
        typer.echo(
            f"#{observation.id} [{observation.severity.upper()}] "
            f"{observation.review_label} — {observation.title}"
        )
        typer.echo(f"  URL: {observation.url}")


@findings_app.command("label")
def findings_label(
    observation_id: int,
    label: ReviewOutcome,
    database: DatabaseOption = Path("vulnhunter.db"),
    note: Annotated[str | None, typer.Option("--note")] = None,
) -> None:
    """Apply a human review outcome to one persisted observation."""
    repository = _repository(database)

    try:
        observation = repository.label_observation(
            observation_id,
            label,
            note=note,
        )
    except (ValidationError, ValueError) as exc:
        typer.secho(f"Unable to label observation: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc

    typer.secho(
        f"Observation {observation.id} labelled {observation.review_label}.",
        fg=typer.colors.GREEN,
    )


@ml_app.command("export")
def ml_export(
    database: DatabaseOption = Path("vulnhunter.db"),
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Destination JSONL dataset file."),
    ] = Path("artifacts/training-data.jsonl"),
) -> None:
    """Export confirmed and false-positive human labels as JSON Lines."""
    repository = _repository(database)
    dataset = build_dataset(repository.list_training_observations())

    if not dataset:
        typer.secho(
            "No confirmed or false-positive observations are available for export.",
            fg=typer.colors.YELLOW,
            err=True,
        )
        raise typer.Exit(code=2)

    try:
        count = export_jsonl(dataset, output)
    except OSError as exc:
        typer.secho(f"Dataset export failed safely: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc

    typer.secho(f"Exported {count} reviewed observations.", fg=typer.colors.GREEN)
    typer.echo(f"Dataset: {output.expanduser().resolve()}")


@ml_app.command("train")
def ml_train(
    database: DatabaseOption = Path("vulnhunter.db"),
    model_path: Annotated[
        Path,
        typer.Option("--model", "-m", help="Destination model JSON artifact."),
    ] = Path("artifacts/vulnhunter-baseline.json"),
    minimum_samples: Annotated[
        int,
        typer.Option("--minimum-samples", min=4, max=100_000),
    ] = 20,
    minimum_per_class: Annotated[
        int,
        typer.Option("--minimum-per-class", min=2, max=50_000),
    ] = 5,
    test_fraction: Annotated[
        float,
        typer.Option("--test-fraction", min=0.05, max=0.45),
    ] = 0.2,
    random_seed: Annotated[int, typer.Option("--seed")] = 42,
    maximum_tokens: Annotated[
        int,
        typer.Option("--maximum-tokens", min=0, max=2_000),
    ] = 128,
) -> None:
    """Train a reviewed-data baseline without changing any human labels."""
    repository = _repository(database)
    dataset = build_dataset(repository.list_training_observations())

    try:
        artifact = train_baseline(
            dataset,
            minimum_samples=minimum_samples,
            minimum_per_class=minimum_per_class,
            test_fraction=test_fraction,
            random_seed=random_seed,
            maximum_tokens=maximum_tokens,
        )
        save_model(artifact, model_path)
    except (MachineLearningError, ValidationError, ValueError, OSError) as exc:
        typer.secho(f"Training stopped safely: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc

    metrics = artifact.evaluation
    typer.secho("Baseline model trained", fg=typer.colors.GREEN)
    typer.echo(f"Training samples: {artifact.training_samples}")
    typer.echo(f"Holdout samples: {artifact.holdout_samples}")
    typer.echo(f"Accuracy: {metrics.accuracy:.3f}")
    typer.echo(f"Precision: {metrics.precision:.3f}")
    typer.echo(f"Recall: {metrics.recall:.3f}")
    typer.echo(f"F1 score: {metrics.f1_score:.3f}")
    typer.echo(f"Model: {model_path.expanduser().resolve()}")
    typer.echo("Human review remains authoritative; predictions never change labels.")


@ml_app.command("info")
def ml_info(
    model_path: Annotated[
        Path,
        typer.Option("--model", "-m", help="Model JSON artifact to inspect."),
    ] = Path("artifacts/vulnhunter-baseline.json"),
) -> None:
    """Display model provenance and holdout evaluation metrics."""
    try:
        artifact = load_model(model_path)
    except MachineLearningError as exc:
        typer.secho(f"Unable to load model: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc

    metrics = artifact.evaluation
    typer.echo(f"Model type: {artifact.model_type}")
    typer.echo(f"Artifact version: {artifact.artifact_version}")
    typer.echo(f"Created: {artifact.created_at.isoformat()}")
    typer.echo(f"Application version: {artifact.application_version}")
    typer.echo(f"Dataset SHA-256: {artifact.dataset_sha256}")
    typer.echo(f"Training samples: {artifact.training_samples}")
    typer.echo(f"Holdout samples: {artifact.holdout_samples}")
    typer.echo(f"Features: {len(artifact.feature_schema.feature_names)}")
    typer.echo(f"Accuracy: {metrics.accuracy:.3f}")
    typer.echo(f"Precision: {metrics.precision:.3f}")
    typer.echo(f"Recall: {metrics.recall:.3f}")
    typer.echo(f"F1 score: {metrics.f1_score:.3f}")


@ml_app.command("predict")
def ml_predict(
    observation_id: Annotated[int, typer.Argument(min=1)],
    database: DatabaseOption = Path("vulnhunter.db"),
    model_path: Annotated[
        Path,
        typer.Option("--model", "-m", help="Model JSON artifact to use."),
    ] = Path("artifacts/vulnhunter-baseline.json"),
) -> None:
    """Predict one stored observation without altering its review label."""
    repository = _repository(database)

    try:
        observation = repository.get_observation(observation_id)
        artifact = load_model(model_path)
        result = predict(to_model_input(observation), artifact)
    except (MachineLearningError, ValidationError, ValueError) as exc:
        typer.secho(f"Prediction stopped safely: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc

    typer.echo(f"Observation: {observation.id}")
    typer.echo(f"Current human label: {observation.review_label}")
    typer.echo(f"Model prediction: {result.label}")
    typer.echo(f"Confidence: {result.confidence:.3f}")
    typer.echo(
        "Class probabilities: "
        f"confirmed={result.probabilities['confirmed']:.3f}, "
        f"false_positive={result.probabilities['false_positive']:.3f}"
    )
    typer.echo("Decision support only; the stored human label was not changed.")


if __name__ == "__main__":
    app()
