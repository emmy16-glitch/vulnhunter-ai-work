"""Command-line interface for VulnHunter AI."""

from __future__ import annotations

import asyncio
import json
import os
import platform
import sys
from collections import Counter
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from vulnhunter import __version__
from vulnhunter.authorization.cli import (
    app as authorization_app,
)
from vulnhunter.authorization.cli import (
    open_authorization_store,
)
from vulnhunter.authorization.service import validate_scan_authorization
from vulnhunter.benchmark import (
    apply_scenario_review,
    benchmark_status,
    load_manifest,
    manifest_sha256,
    pending_by_scenario,
    run_benchmark_suite,
    validate_manifest_database,
)
from vulnhunter.exceptions import (
    AuthorizationError,
    BenchmarkError,
    BenchmarkManifestError,
    MachineLearningError,
    ScopeValidationError,
    VulnHunterError,
)
from vulnhunter.governance.cli import app as governance_app
from vulnhunter.governance.service import scan_snapshot_sha256
from vulnhunter.mapping import MapperPolicy, SiteMapper
from vulnhunter.ml import (
    BenchmarkProvenance,
    assess_dataset_quality,
    build_dataset,
    diagnose_holdout,
    export_jsonl,
    load_model,
    predict,
    save_model,
    to_model_input,
    train_baseline,
    train_tuned,
)
from vulnhunter.observations.storage import ScanRepository
from vulnhunter.orchestration.cli import app as orchestration_app
from vulnhunter.research.cli import app as research_app
from vulnhunter.review import IndependentReviewOutcome, ReviewCaseSummary
from vulnhunter.scanner import HttpClientPolicy, SafeHttpClient
from vulnhunter.scope import ApprovedTarget, validate_target
from vulnhunter.unattended.cli import app as unattended_app

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
    help="Inspect findings and run independent human review workflows.",
    no_args_is_help=True,
)
ml_app = typer.Typer(
    help="Export reviewed data and run the local baseline ML pipeline.",
    no_args_is_help=True,
)
benchmark_app = typer.Typer(
    help="Generate and review controlled loopback benchmark observations.",
    no_args_is_help=True,
)

app.add_typer(authorization_app, name="authorize")
app.add_typer(governance_app, name="governance")
app.add_typer(scope_app, name="scope")
app.add_typer(scan_app, name="scan")
app.add_typer(findings_app, name="findings")
app.add_typer(ml_app, name="ml")
app.add_typer(benchmark_app, name="benchmark")
app.add_typer(orchestration_app, name="loop")
app.add_typer(research_app, name="research")
app.add_typer(unattended_app, name="unattended")

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
    authorization_id: Annotated[
        str,
        typer.Option(
            "--authorization",
            help="Active authorization ID required before any network request.",
        ),
    ],
    authorization_database: Annotated[
        Path,
        typer.Option(
            "--authorization-database",
            help="SQLite authorization registry used to validate this scan.",
        ),
    ] = Path("authorizations.db"),
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
        authorization_store = open_authorization_store(authorization_database)
        validate_scan_authorization(
            authorization_store,
            authorization_id,
            target,
            maximum_pages=maximum_pages,
            maximum_depth=maximum_depth,
            maximum_requests=maximum_requests,
            request_delay_seconds=request_delay_seconds,
        )
    except (
        AuthorizationError,
        ScopeValidationError,
        ValidationError,
        ValueError,
    ) as exc:
        typer.secho(f"Scan authorization rejected: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc

    repository = _repository(database)
    scan_id = repository.create_scan(target.normalized_url)
    authorization_store.append_event(
        authorization_id,
        "scan_started",
        {
            "scan_id": scan_id,
            "scan_database": str(database.expanduser().resolve()),
            "target_url": target.normalized_url,
        },
    )
    typer.echo(f"Authorization accepted: {authorization_id}")
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
        completed_scan = repository.get_scan(scan_id)
        authorization_store.append_event(
            authorization_id,
            "scan_completed",
            {
                "scan_id": scan_id,
                "scan_database": str(database.expanduser().resolve()),
                "target_url": target.normalized_url,
                "scan_snapshot_sha256": scan_snapshot_sha256(completed_scan),
                "pages_visited": len(result.pages),
                "observations": len(result.observations),
            },
        )
    except KeyboardInterrupt as exc:
        repository.fail_scan(scan_id, "Cancelled by operator.")
        authorization_store.append_event(
            authorization_id,
            "scan_failed",
            {"scan_id": scan_id, "reason": "Cancelled by operator."},
        )
        typer.secho("Scan cancelled by operator.", fg=typer.colors.YELLOW, err=True)
        raise typer.Exit(code=130) from exc
    except (VulnHunterError, ValidationError, ValueError) as exc:
        repository.fail_scan(scan_id, str(exc))
        authorization_store.append_event(
            authorization_id,
            "scan_failed",
            {"scan_id": scan_id, "reason": str(exc)},
        )
        typer.secho(f"Scan failed safely: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc
    except Exception as exc:
        repository.fail_scan(scan_id, str(exc))
        authorization_store.append_event(
            authorization_id,
            "scan_failed",
            {"scan_id": scan_id, "reason": "Unexpected internal failure."},
        )
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


@findings_app.command("queue")
def findings_queue(
    database: DatabaseOption = Path("vulnhunter.db"),
    limit: Annotated[int, typer.Option("--limit", min=1, max=500)] = 50,
) -> None:
    """Show the highest-priority observations awaiting human review."""
    repository = _repository(database)
    observations = repository.list_review_queue(limit=limit)

    if not observations:
        typer.echo("Review queue is empty.")
        return

    counts = repository.fingerprint_occurrence_counts(
        tuple(observation.fingerprint for observation in observations)
    )

    for observation in observations:
        occurrences = counts.get(observation.fingerprint, 1)
        typer.echo(
            f"#{observation.id} [{observation.severity.upper()}] "
            f"{observation.review_label} — {observation.title}"
        )
        typer.echo(
            f"  scan={observation.scan_id} repeated_across_scans={occurrences} "
            f"category={observation.category}"
        )
        typer.echo(f"  URL: {observation.url}")


@findings_app.command("show")
def findings_show(
    observation_id: Annotated[int, typer.Argument(min=1)],
    database: DatabaseOption = Path("vulnhunter.db"),
) -> None:
    """Display complete redacted evidence for one observation."""
    try:
        review_case = _repository(database).get_review_case(observation_id)
    except ValueError as exc:
        typer.secho(f"Unable to load observation: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc

    observation = review_case.observation
    typer.echo(f"Observation: {observation.id}")
    typer.echo(f"Scan: {observation.scan_id}")
    typer.echo(f"Category: {observation.category}")
    typer.echo(f"Severity: {observation.severity}")
    typer.echo(f"Review label: {observation.review_label}")
    typer.echo(f"Review state: {review_case.state}")
    typer.echo(f"Primary decisions: {len(review_case.decisions)}")
    typer.echo(f"Title: {observation.title}")
    typer.echo(f"URL: {observation.url}")
    typer.echo(f"Description: {observation.description}")
    typer.echo("Evidence:")
    typer.echo(json.dumps(observation.evidence, indent=2, sort_keys=True, default=str))
    if observation.review_note:
        typer.echo(f"Review note: {observation.review_note}")


@findings_app.command("label")
def findings_label(
    observation_id: int,
    label: str,
    database: DatabaseOption = Path("vulnhunter.db"),
    note: Annotated[str | None, typer.Option("--note")] = None,
) -> None:
    """Reject legacy single-review labelling for manual findings."""
    del observation_id, label, database, note
    typer.secho(
        "Direct single-review labelling is disabled for manual findings. "
        "Use 'vulnhunter findings review' with two distinct reviewers, and "
        "'vulnhunter findings adjudicate' when they disagree.",
        fg=typer.colors.RED,
        err=True,
    )
    raise typer.Exit(code=2)


def _display_review_case(case: ReviewCaseSummary) -> None:
    """Render one review case without exposing unredacted source data."""
    typer.echo(f"Observation: {case.observation.id}")
    typer.echo(f"State: {case.state}")
    typer.echo(f"Effective label: {case.effective_label}")
    typer.echo(f"Primary decisions: {len(case.decisions)}")
    for decision in case.decisions:
        typer.echo(
            f"  #{decision.id} reviewer={decision.reviewer_id} "
            f"outcome={decision.outcome} at={decision.created_at.isoformat()}"
        )
        if decision.note:
            typer.echo(f"    Note: {decision.note}")
    if case.adjudication is not None:
        typer.echo(
            f"Adjudication: adjudicator={case.adjudication.adjudicator_id} "
            f"outcome={case.adjudication.outcome} "
            f"at={case.adjudication.created_at.isoformat()}"
        )
        typer.echo(f"  Rationale: {case.adjudication.rationale}")


@findings_app.command("review")
def findings_review(
    observation_id: Annotated[int, typer.Argument(min=1)],
    reviewer: Annotated[
        str,
        typer.Option(
            "--reviewer",
            help="Stable pseudonymous reviewer ID; do not use an email address.",
        ),
    ],
    label: Annotated[
        IndependentReviewOutcome,
        typer.Option("--label", help="Independent primary-review outcome."),
    ],
    database: DatabaseOption = Path("vulnhunter.db"),
    note: Annotated[str | None, typer.Option("--note")] = None,
) -> None:
    """Submit one immutable primary decision by an independent reviewer."""
    try:
        case = _repository(database).submit_review_decision(
            observation_id,
            reviewer,
            label,
            note=note,
        )
    except (ValidationError, ValueError) as exc:
        typer.secho(
            f"Review decision rejected safely: {exc}",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=2) from exc

    typer.secho("Review decision recorded", fg=typer.colors.GREEN)
    _display_review_case(case)
    if case.state == "pending_second_review":
        typer.echo("A distinct second reviewer is required before training eligibility.")
    elif case.state == "disputed":
        typer.echo("The disagreement requires an independent adjudicator.")


@findings_app.command("review-status")
def findings_review_status(
    observation_id: Annotated[int, typer.Argument(min=1)],
    database: DatabaseOption = Path("vulnhunter.db"),
) -> None:
    """Display all redacted decisions and the effective review state."""
    try:
        case = _repository(database).get_review_case(observation_id)
    except ValueError as exc:
        typer.secho(
            f"Unable to load review case: {exc}",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=2) from exc

    _display_review_case(case)


@findings_app.command("second-review-queue")
def findings_second_review_queue(
    reviewer: Annotated[
        str,
        typer.Option(
            "--reviewer",
            help="Reviewer requesting cases they have not already decided.",
        ),
    ],
    database: DatabaseOption = Path("vulnhunter.db"),
    limit: Annotated[int, typer.Option("--limit", min=1, max=500)] = 50,
) -> None:
    """List cases awaiting a distinct second primary reviewer."""
    try:
        cases = _repository(database).list_second_review_queue(
            reviewer,
            limit=limit,
        )
    except ValueError as exc:
        typer.secho(
            f"Unable to load second-review queue: {exc}",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=2) from exc

    if not cases:
        typer.echo("Second-review queue is empty for this reviewer.")
        return

    for case in cases:
        observation = case.observation
        first = case.decisions[0]
        typer.echo(
            f"#{observation.id} [{observation.severity.upper()}] "
            f"first_reviewer={first.reviewer_id} "
            f"first_outcome={first.outcome} — {observation.title}"
        )
        typer.echo(f"  URL: {observation.url}")


@findings_app.command("disputes")
def findings_disputes(
    database: DatabaseOption = Path("vulnhunter.db"),
    limit: Annotated[int, typer.Option("--limit", min=1, max=500)] = 50,
) -> None:
    """List unresolved disagreements requiring adjudication."""
    cases = _repository(database).list_disputed_review_cases(limit=limit)
    if not cases:
        typer.echo("No unresolved review disputes.")
        return

    for case in cases:
        decisions = ", ".join(f"{item.reviewer_id}={item.outcome}" for item in case.decisions)
        typer.echo(
            f"#{case.observation.id} [{case.observation.severity.upper()}] "
            f"{decisions} — {case.observation.title}"
        )


@findings_app.command("adjudicate")
def findings_adjudicate(
    observation_id: Annotated[int, typer.Argument(min=1)],
    adjudicator: Annotated[
        str,
        typer.Option(
            "--adjudicator",
            help="Pseudonymous ID distinct from both primary reviewers.",
        ),
    ],
    label: Annotated[
        IndependentReviewOutcome,
        typer.Option("--label", help="Final adjudicated outcome."),
    ],
    rationale: Annotated[
        str,
        typer.Option("--rationale", help="Required redacted adjudication rationale."),
    ],
    database: DatabaseOption = Path("vulnhunter.db"),
) -> None:
    """Resolve one primary-review disagreement with a third person."""
    try:
        case = _repository(database).adjudicate_review(
            observation_id,
            adjudicator,
            label,
            rationale=rationale,
        )
    except (ValidationError, ValueError) as exc:
        typer.secho(
            f"Adjudication rejected safely: {exc}",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=2) from exc

    typer.secho("Review dispute adjudicated", fg=typer.colors.GREEN)
    _display_review_case(case)


@ml_app.command("readiness")
def ml_readiness(
    database: DatabaseOption = Path("vulnhunter.db"),
    minimum_samples: Annotated[
        int,
        typer.Option("--minimum-samples", min=4, max=100_000),
    ] = 20,
    minimum_per_class: Annotated[
        int,
        typer.Option("--minimum-per-class", min=2, max=50_000),
    ] = 5,
    minimum_scans: Annotated[
        int,
        typer.Option("--minimum-scans", min=2, max=10_000),
    ] = 4,
    minimum_scans_per_class: Annotated[
        int,
        typer.Option("--minimum-scans-per-class", min=2, max=10_000),
    ] = 2,
    test_fraction: Annotated[
        float,
        typer.Option("--test-fraction", min=0.05, max=0.45),
    ] = 0.2,
    random_seed: Annotated[int, typer.Option("--seed")] = 42,
) -> None:
    """Report duplicate, conflict, class, and scan-split readiness."""
    repository = _repository(database)
    dataset = build_dataset(repository.list_training_observations())
    prepared = assess_dataset_quality(
        dataset,
        minimum_samples=minimum_samples,
        minimum_per_class=minimum_per_class,
        minimum_scans=minimum_scans,
        minimum_scans_per_class=minimum_scans_per_class,
        test_fraction=test_fraction,
        random_seed=random_seed,
    )
    report = prepared.report

    typer.echo(f"Reviewed source samples: {report.source_samples}")
    typer.echo(f"Unique usable samples: {report.unique_samples}")
    typer.echo(f"Repeated samples excluded: {report.duplicate_samples}")
    typer.echo(f"Distinct scans: {report.distinct_scans}")
    typer.echo(
        "Class counts: "
        f"confirmed={report.class_counts['confirmed']}, "
        f"false_positive={report.class_counts['false_positive']}"
    )
    typer.echo(
        "Scans per class: "
        f"confirmed={report.scans_per_class['confirmed']}, "
        f"false_positive={report.scans_per_class['false_positive']}"
    )

    for warning in report.warnings:
        typer.secho(f"Warning: {warning}", fg=typer.colors.YELLOW)

    if report.ready:
        typer.secho("Training readiness: READY", fg=typer.colors.GREEN)
    else:
        typer.secho("Training readiness: NOT READY", fg=typer.colors.YELLOW)
        for reason in report.blocking_reasons:
            typer.echo(f"  - {reason}")


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
    minimum_scans: Annotated[
        int,
        typer.Option("--minimum-scans", min=2, max=10_000),
    ] = 4,
    minimum_scans_per_class: Annotated[
        int,
        typer.Option("--minimum-scans-per-class", min=2, max=10_000),
    ] = 2,
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
            minimum_scans=minimum_scans,
            minimum_scans_per_class=minimum_scans_per_class,
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
    typer.echo(f"Split strategy: {artifact.split_strategy}")
    typer.echo(f"Training scans: {len(artifact.training_scan_ids)}")
    typer.echo(f"Holdout scans: {len(artifact.holdout_scan_ids)}")
    typer.echo(f"Repeated samples excluded: {artifact.duplicate_samples_removed}")
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
    typer.echo(f"Training context: {artifact.training_context}")
    typer.echo(f"Created: {artifact.created_at.isoformat()}")
    typer.echo(f"Application version: {artifact.application_version}")
    typer.echo(f"Dataset SHA-256: {artifact.dataset_sha256}")
    typer.echo(f"Training samples: {artifact.training_samples}")
    typer.echo(f"Holdout samples: {artifact.holdout_samples}")
    typer.echo(f"Source samples: {artifact.source_samples}")
    typer.echo(f"Deduplicated samples: {artifact.deduplicated_samples}")
    typer.echo(f"Repeated samples excluded: {artifact.duplicate_samples_removed}")
    typer.echo(f"Split strategy: {artifact.split_strategy}")
    typer.echo(f"Training scan IDs: {', '.join(map(str, artifact.training_scan_ids))}")
    typer.echo(f"Holdout scan IDs: {', '.join(map(str, artifact.holdout_scan_ids))}")
    if artifact.training_context == "controlled_benchmark":
        typer.echo(f"Benchmark run ID: {artifact.benchmark_run_id}")
        typer.echo(f"Benchmark catalog version: {artifact.benchmark_catalog_version}")
        typer.echo(f"Benchmark manifest SHA-256: {artifact.benchmark_manifest_sha256}")
    typer.echo(f"Features: {len(artifact.feature_schema.feature_names)}")
    typer.echo(f"Decision threshold: {artifact.decision_threshold:.3f}")
    if artifact.tuning is not None:
        tuning = artifact.tuning
        typer.echo(f"Cross-validation folds: {tuning.fold_count}")
        typer.echo(f"Candidates evaluated: {tuning.candidate_count}")
        typer.echo(f"Selected algorithm: {tuning.selected_model_type}")
        typer.echo(f"Selected alpha: {tuning.selected_alpha:g}")
        typer.echo(f"Selected threshold: {tuning.selected_threshold:.3f}")
        typer.echo(f"Training-only CV F1: {tuning.cross_validation.f1_score:.3f}")
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


@benchmark_app.command("run")
def benchmark_run(
    database: DatabaseOption = Path("artifacts/benchmark.db"),
    manifest_path: Annotated[
        Path,
        typer.Option(
            "--manifest",
            help="Destination integrity-protected benchmark manifest.",
        ),
    ] = Path("artifacts/benchmark-manifest.json"),
) -> None:
    """Run the fixed benchmark catalog as isolated loopback-only scans."""
    try:
        manifest = asyncio.run(run_benchmark_suite(database, manifest_path))
    except (
        BenchmarkError,
        VulnHunterError,
        ValidationError,
        ValueError,
        OSError,
    ) as exc:
        typer.secho(f"Benchmark stopped safely: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc

    typer.secho("Controlled benchmark completed", fg=typer.colors.GREEN)
    typer.echo(f"Run ID: {manifest.run_id}")
    typer.echo(f"Independent scans: {len(manifest.scenarios)}")
    typer.echo(f"Review expectations: {len(manifest.expectations)}")
    typer.echo(f"Database: {database.expanduser().resolve()}")
    typer.echo(f"Manifest: {manifest_path.expanduser().resolve()}")
    typer.secho(
        "Benchmark observations are synthetic and remain unlabelled until explicit human review.",
        fg=typer.colors.YELLOW,
    )


@benchmark_app.command("status")
def benchmark_status_command(
    database: DatabaseOption = Path("artifacts/benchmark.db"),
    manifest_path: Annotated[
        Path,
        typer.Option("--manifest", help="Benchmark manifest to inspect."),
    ] = Path("artifacts/benchmark-manifest.json"),
) -> None:
    """Show benchmark review progress and manifest consistency."""
    repository = _repository(database)
    try:
        manifest = load_manifest(manifest_path)
        status = benchmark_status(manifest, database, repository)
    except (BenchmarkManifestError, ValidationError, ValueError, OSError) as exc:
        typer.secho(f"Benchmark status failed safely: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc

    typer.echo(f"Run ID: {manifest.run_id}")
    typer.echo(f"Catalog version: {manifest.catalog_version}")
    typer.echo(f"Scenarios: {len(manifest.scenarios)}")
    typer.echo(f"Total expectations: {status.total_expectations}")
    typer.echo(f"Pending review: {status.pending}")
    typer.echo(f"Confirmed: {status.confirmed}")
    typer.echo(f"False positive: {status.false_positive}")
    typer.echo(f"Needs review: {status.needs_review}")
    typer.echo(f"Human decisions differing from suggestion: {status.mismatched}")
    typer.echo(f"Review complete: {'yes' if status.complete else 'no'}")


@benchmark_app.command("review")
def benchmark_review(
    database: DatabaseOption = Path("artifacts/benchmark.db"),
    manifest_path: Annotated[
        Path,
        typer.Option("--manifest", help="Benchmark manifest to review."),
    ] = Path("artifacts/benchmark-manifest.json"),
    scenario_id: Annotated[
        str | None,
        typer.Option("--scenario", help="Review only one scenario ID."),
    ] = None,
) -> None:
    """Guide explicit human confirmation one scenario at a time."""
    repository = _repository(database)
    try:
        manifest = load_manifest(manifest_path)
        grouped = pending_by_scenario(manifest, database, repository)
    except (BenchmarkManifestError, ValidationError, ValueError, OSError) as exc:
        typer.secho(f"Benchmark review failed safely: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc

    if scenario_id is not None:
        if scenario_id not in {item.scenario_id for item in manifest.scenarios}:
            typer.secho(
                f"Unknown benchmark scenario: {scenario_id}",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=2)
        grouped = {scenario_id: grouped.get(scenario_id, ())}

    grouped = {key: value for key, value in grouped.items() if value}
    if not grouped:
        typer.echo("No pending benchmark scenarios remain.")
        return

    scenario_lookup = {item.scenario_id: item for item in manifest.scenarios}

    for current_scenario_id, expectations in grouped.items():
        scenario = scenario_lookup[current_scenario_id]
        suggested_label = expectations[0].suggested_label
        category_counts = Counter(item.category for item in expectations)

        typer.echo("")
        typer.secho(
            f"Scenario: {scenario.title} ({current_scenario_id})",
            fg=typer.colors.CYAN,
        )
        typer.echo(f"Scan ID: {scenario.scan_id}")
        typer.echo(f"Suggested label: {suggested_label}")
        typer.echo(f"Rationale: {expectations[0].rationale}")
        typer.echo(
            "Categories: "
            + ", ".join(
                f"{category}={count}" for category, count in sorted(category_counts.items())
            )
        )
        for expectation in expectations:
            typer.echo(
                f"  #{expectation.observation_id} [{expectation.severity.upper()}] "
                f"{expectation.category} — {expectation.title}"
            )
            typer.echo(f"    {expectation.url}")

        while True:
            decision = (
                typer.prompt(
                    "Decision: accept / confirmed / false_positive / skip / quit",
                    default="skip",
                )
                .strip()
                .lower()
            )
            if decision in {
                "accept",
                "confirmed",
                "false_positive",
                "skip",
                "quit",
            }:
                break
            typer.secho("Enter one of the displayed decisions.", fg=typer.colors.YELLOW)

        if decision == "quit":
            typer.echo("Benchmark review stopped by operator.")
            return
        if decision == "skip":
            typer.echo("Scenario skipped without changing labels.")
            continue

        try:
            labelled = apply_scenario_review(
                manifest,
                database,
                repository,
                current_scenario_id,
                decision,
            )
        except (BenchmarkManifestError, ValidationError, ValueError) as exc:
            typer.secho(f"Review decision failed safely: {exc}", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=2) from exc

        typer.secho(
            f"Applied human decision to {len(labelled)} findings.",
            fg=typer.colors.GREEN,
        )


@benchmark_app.command("train")
def benchmark_train(
    database: DatabaseOption = Path("artifacts/benchmark.db"),
    manifest_path: Annotated[
        Path,
        typer.Option("--manifest", help="Completed benchmark manifest."),
    ] = Path("artifacts/benchmark-manifest.json"),
    model_path: Annotated[
        Path,
        typer.Option("--model", "-m", help="Benchmark-only model artifact."),
    ] = Path("artifacts/vulnhunter-benchmark-baseline.json"),
    test_fraction: Annotated[
        float,
        typer.Option("--test-fraction", min=0.05, max=0.45),
    ] = 0.2,
    random_seed: Annotated[int, typer.Option("--seed")] = 42,
) -> None:
    """Train a provenance-marked model after all benchmark reviews are complete."""
    repository = _repository(database)

    try:
        manifest = load_manifest(manifest_path)
        validate_manifest_database(manifest, database, repository)
        status = benchmark_status(manifest, database, repository)
        if not status.complete:
            raise BenchmarkError(
                f"Benchmark review is incomplete; {status.pending} finding(s) remain pending."
            )

        dataset = build_dataset(repository.list_training_observations())
        artifact = train_baseline(
            dataset,
            minimum_samples=20,
            minimum_per_class=5,
            minimum_scans=4,
            minimum_scans_per_class=2,
            test_fraction=test_fraction,
            random_seed=random_seed,
            benchmark_provenance=BenchmarkProvenance(
                run_id=manifest.run_id,
                catalog_version=manifest.catalog_version,
                manifest_sha256=manifest_sha256(manifest),
            ),
        )
        save_model(artifact, model_path)
    except (
        BenchmarkError,
        BenchmarkManifestError,
        MachineLearningError,
        ValidationError,
        ValueError,
        OSError,
    ) as exc:
        typer.secho(f"Benchmark training stopped safely: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc

    metrics = artifact.evaluation
    typer.secho("Controlled benchmark model trained", fg=typer.colors.GREEN)
    typer.echo(f"Training samples: {artifact.training_samples}")
    typer.echo(f"Holdout samples: {artifact.holdout_samples}")
    typer.echo(f"Accuracy: {metrics.accuracy:.3f}")
    typer.echo(f"Precision: {metrics.precision:.3f}")
    typer.echo(f"Recall: {metrics.recall:.3f}")
    typer.echo(f"F1 score: {metrics.f1_score:.3f}")
    typer.echo(f"Model: {model_path.expanduser().resolve()}")
    typer.secho(
        "These metrics validate the pipeline on synthetic benchmark data; they do not "
        "represent real-world vulnerability-detection performance.",
        fg=typer.colors.YELLOW,
    )


@benchmark_app.command("tune")
def benchmark_tune(
    database: DatabaseOption = Path("artifacts/benchmark.db"),
    manifest_path: Annotated[
        Path,
        typer.Option("--manifest", help="Completed benchmark manifest."),
    ] = Path("artifacts/benchmark-manifest.json"),
    model_path: Annotated[
        Path,
        typer.Option("--model", "-m", help="Tuned benchmark model artifact."),
    ] = Path("artifacts/vulnhunter-benchmark-tuned.json"),
    test_fraction: Annotated[
        float,
        typer.Option("--test-fraction", min=0.05, max=0.45),
    ] = 0.2,
    random_seed: Annotated[int, typer.Option("--seed")] = 42,
) -> None:
    """Tune on training scans only, then evaluate once on locked holdout scans."""
    repository = _repository(database)

    try:
        manifest = load_manifest(manifest_path)
        validate_manifest_database(manifest, database, repository)
        status = benchmark_status(manifest, database, repository)
        if not status.complete:
            raise BenchmarkError(
                f"Benchmark review is incomplete; {status.pending} finding(s) remain pending."
            )

        dataset = build_dataset(repository.list_training_observations())
        artifact = train_tuned(
            dataset,
            minimum_samples=20,
            minimum_per_class=5,
            minimum_scans=6,
            minimum_scans_per_class=3,
            test_fraction=test_fraction,
            random_seed=random_seed,
            benchmark_provenance=BenchmarkProvenance(
                run_id=manifest.run_id,
                catalog_version=manifest.catalog_version,
                manifest_sha256=manifest_sha256(manifest),
            ),
        )
        save_model(artifact, model_path)
    except (
        BenchmarkError,
        BenchmarkManifestError,
        MachineLearningError,
        ValidationError,
        ValueError,
        OSError,
    ) as exc:
        typer.secho(f"Benchmark tuning stopped safely: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc

    metrics = artifact.evaluation
    tuning = artifact.tuning
    if tuning is None:
        raise typer.Exit(code=2)

    typer.secho("Controlled benchmark model tuned", fg=typer.colors.GREEN)
    typer.echo(f"Selected algorithm: {artifact.model_type}")
    typer.echo(f"Selected alpha: {artifact.alpha:g}")
    typer.echo(f"Selected threshold: {artifact.decision_threshold:.3f}")
    typer.echo(f"Training-only CV F1: {tuning.cross_validation.f1_score:.3f}")
    typer.echo(f"Training samples: {artifact.training_samples}")
    typer.echo(f"Untouched holdout samples: {artifact.holdout_samples}")
    typer.echo(f"Holdout accuracy: {metrics.accuracy:.3f}")
    typer.echo(f"Holdout precision: {metrics.precision:.3f}")
    typer.echo(f"Holdout recall: {metrics.recall:.3f}")
    typer.echo(f"Holdout F1 score: {metrics.f1_score:.3f}")
    typer.echo(f"Model: {model_path.expanduser().resolve()}")
    typer.secho(
        "Candidate selection used training scans only. Synthetic benchmark metrics do not "
        "represent real-world vulnerability-detection performance.",
        fg=typer.colors.YELLOW,
    )


@benchmark_app.command("diagnose")
def benchmark_diagnose(
    database: DatabaseOption = Path("artifacts/benchmark.db"),
    manifest_path: Annotated[
        Path,
        typer.Option("--manifest", help="Benchmark manifest used for the model."),
    ] = Path("artifacts/benchmark-manifest.json"),
    model_path: Annotated[
        Path,
        typer.Option("--model", "-m", help="Benchmark model artifact to diagnose."),
    ] = Path("artifacts/vulnhunter-benchmark-tuned.json"),
) -> None:
    """Explain locked-holdout errors without retraining or changing labels."""
    repository = _repository(database)

    try:
        manifest = load_manifest(manifest_path)
        validate_manifest_database(manifest, database, repository)
        artifact = load_model(model_path)
        if artifact.training_context != "controlled_benchmark":
            raise BenchmarkError("The selected model is not a controlled benchmark artifact.")
        if artifact.benchmark_run_id != manifest.run_id:
            raise BenchmarkManifestError("Model and manifest benchmark run IDs differ.")
        if artifact.benchmark_catalog_version != manifest.catalog_version:
            raise BenchmarkManifestError("Model and manifest catalog versions differ.")
        if artifact.benchmark_manifest_sha256 != manifest_sha256(manifest):
            raise BenchmarkManifestError("Model and manifest integrity digests differ.")

        dataset = build_dataset(repository.list_training_observations())
        report = diagnose_holdout(dataset, artifact)
    except (
        BenchmarkError,
        BenchmarkManifestError,
        MachineLearningError,
        ValidationError,
        ValueError,
        OSError,
    ) as exc:
        typer.secho(f"Benchmark diagnosis stopped safely: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc

    metrics = report.metrics
    typer.secho("Locked holdout diagnosis", fg=typer.colors.CYAN)
    typer.echo(
        "Confusion matrix: "
        f"TP={metrics.true_positive}, FP={metrics.false_positive}, "
        f"FN={metrics.false_negative}, TN={metrics.true_negative}"
    )
    typer.echo(
        f"Accuracy={metrics.accuracy:.3f}, Precision={metrics.precision:.3f}, "
        f"Recall={metrics.recall:.3f}, F1={metrics.f1_score:.3f}"
    )

    typer.echo("")
    typer.echo("Metrics by category:")
    for item in report.by_category:
        slice_metrics = item.metrics
        typer.echo(
            f"  {item.key}: n={slice_metrics.test_samples}, "
            f"TP={slice_metrics.true_positive}, FP={slice_metrics.false_positive}, "
            f"FN={slice_metrics.false_negative}, TN={slice_metrics.true_negative}, "
            f"Accuracy={slice_metrics.accuracy:.3f}, F1={slice_metrics.f1_score:.3f}"
        )

    typer.echo("")
    typer.echo("Metrics by holdout scan:")
    for item in report.by_scan:
        slice_metrics = item.metrics
        typer.echo(
            f"  scan {item.key}: n={slice_metrics.test_samples}, "
            f"TP={slice_metrics.true_positive}, FP={slice_metrics.false_positive}, "
            f"FN={slice_metrics.false_negative}, TN={slice_metrics.true_negative}, "
            f"Accuracy={slice_metrics.accuracy:.3f}, F1={slice_metrics.f1_score:.3f}"
        )

    typer.echo("")
    typer.echo(f"False negatives: {len(report.false_negatives)}")
    for item in report.false_negatives:
        typer.echo(
            f"  #{item.observation_id} scan={item.scan_id} category={item.category} "
            f"p_confirmed={item.confirmed_probability:.3f}"
        )
        typer.echo(f"    {item.url}")

    typer.echo(f"False positives: {len(report.false_positives)}")
    for item in report.false_positives:
        typer.echo(
            f"  #{item.observation_id} scan={item.scan_id} category={item.category} "
            f"p_confirmed={item.confirmed_probability:.3f}"
        )
        typer.echo(f"    {item.url}")

    typer.echo("Diagnosis is read-only; no model, label, or database record was changed.")


if __name__ == "__main__":
    app()
