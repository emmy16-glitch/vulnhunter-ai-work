"""Read-only CLI for inspecting bounded-agent activity evidence."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from vulnhunter.agent_activity.read_models import snapshot_to_public_dict
from vulnhunter.agent_activity.service import AgentActivityService
from vulnhunter.agent_activity.store import AppendOnlyActivityStore

app = typer.Typer(
    no_args_is_help=True,
    help="Inspect and verify append-only bounded-agent activity evidence.",
)


@app.command("verify")
def verify_stream(
    root: Annotated[Path, typer.Option("--root")],
    run_id: Annotated[str, typer.Option("--run-id")],
) -> None:
    """Verify one run's append-only event chain without modifying it."""
    result = AppendOnlyActivityStore(root).verify(run_id)
    typer.echo(json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True))
    if not result.valid:
        raise typer.Exit(code=1)


@app.command("inspect")
def inspect_stream(
    root: Annotated[Path, typer.Option("--root")],
    run_id: Annotated[str, typer.Option("--run-id")],
    after_sequence: Annotated[int, typer.Option("--after-sequence")] = 0,
    limit: Annotated[int, typer.Option("--limit")] = 200,
    format_: Annotated[str, typer.Option("--format")] = "text",
) -> None:
    """Read one ordered activity page without appending or executing anything."""
    service = AgentActivityService(AppendOnlyActivityStore(root))
    snapshot = service.feed(
        run_id,
        after_sequence=after_sequence,
        limit=limit,
    )
    if format_ == "json":
        typer.echo(
            json.dumps(
                snapshot_to_public_dict(snapshot),
                indent=2,
                sort_keys=True,
            )
        )
        return
    if format_ != "text":
        raise typer.BadParameter("--format must be 'text' or 'json'")
    typer.echo(f"Run: {snapshot.run_id}")
    typer.echo(f"State: {snapshot.run_state or 'no activity'}")
    typer.echo(f"Terminal: {snapshot.terminal}")
    typer.echo(f"Last sequence: {snapshot.last_sequence}")
    for event in snapshot.events:
        typer.echo(
            f"[{event.sequence}] {event.timestamp.isoformat()} {event.event_type}: {event.summary}"
        )
