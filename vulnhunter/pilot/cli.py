"""Read-only command-line interface for controlled pilot-plan validation."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer

from vulnhunter.pilot.loading import PilotPlanLoadError, load_pilot_plan
from vulnhunter.pilot.validation import assess_pilot_plan

app = typer.Typer(
    no_args_is_help=True,
    help="Validate a controlled local/lab VulnHunter pilot plan.",
)


@app.callback()
def main() -> None:
    """Controlled pilot-plan validation commands."""


def _parse_assessed_at(value: str | None) -> datetime | None:
    if value is None:
        return None
    normalized = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise typer.BadParameter("--assessed-at must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


@app.command("validate")
def validate_plan(
    plan: Annotated[Path, typer.Option("--plan", exists=False)],
    format_: Annotated[str, typer.Option("--format")] = "text",
    output: Annotated[Path | None, typer.Option("--output")] = None,
    assessed_at: Annotated[str | None, typer.Option("--assessed-at")] = None,
) -> None:
    """Validate and optionally export deterministic pilot-plan evidence."""
    try:
        loaded = load_pilot_plan(plan)
    except PilotPlanLoadError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc

    report = assess_pilot_plan(
        loaded,
        assessed_at=_parse_assessed_at(assessed_at),
    )
    payload = (
        json.dumps(
            report.model_dump(mode="json"),
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )

    if output is not None:
        resolved = output.expanduser().resolve()
        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.write_text(payload, encoding="utf-8")

    if format_ == "json":
        typer.echo(payload, nl=False)
    elif format_ == "text":
        metrics = report.informational_metrics
        typer.echo(f"Plan: {report.plan_id}")
        typer.echo(f"Valid: {report.valid}")
        typer.echo(f"Applications: {metrics['application_count']}")
        typer.echo(f"Application families: {metrics['application_family_count']}")
        typer.echo(f"Authorization references: {metrics['authorization_reference_count']}")
        typer.echo(f"Connectors disabled: {metrics['connector_disabled']}")
        typer.echo(f"Plan SHA-256: {report.plan_sha256}")
        typer.echo(f"Report SHA-256: {report.report_sha256}")
        if report.hard_blockers:
            typer.echo("Hard blockers:")
            for blocker in report.hard_blockers:
                typer.echo(f"- {blocker}")
        if report.warnings:
            typer.echo("Warnings:")
            for warning in report.warnings:
                typer.echo(f"- {warning}")
    else:
        raise typer.BadParameter("--format must be 'text' or 'json'.")

    if not report.valid:
        raise typer.Exit(code=1)
