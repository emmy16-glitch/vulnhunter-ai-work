"""Standalone CLI for controlled project-knowledge ingestion."""

from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Annotated

import typer

from vulnhunter.knowledge.errors import KnowledgeError
from vulnhunter.knowledge.models import (
    HumanReviewStatus,
    InjectionReviewStatus,
    Sensitivity,
    SourceType,
    TrustLevel,
)
from vulnhunter.knowledge.service import register_source, review_source
from vulnhunter.knowledge.store import KnowledgeStore

app = typer.Typer(
    name="knowledge",
    help="Register and review untrusted project sources without executing them.",
    no_args_is_help=True,
)

RootOption = Annotated[
    Path,
    typer.Option(
        "--root",
        help="Knowledge-store root directory.",
        file_okay=False,
        dir_okay=True,
        resolve_path=True,
    ),
]


@app.command("init")
def initialize(root: RootOption = Path("knowledge")) -> None:
    """Create the controlled source-ingestion directory structure."""
    store = KnowledgeStore(root)
    store.initialize()
    typer.echo(f"Knowledge store initialised: {store.root}")


@app.command("register")
def register(
    source: Annotated[
        Path,
        typer.Argument(
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            resolve_path=True,
        ),
    ],
    title: Annotated[str, typer.Option("--title", prompt=True)],
    origin: Annotated[str, typer.Option("--origin", prompt=True)],
    source_type: Annotated[SourceType, typer.Option("--type")],
    sensitivity: Annotated[Sensitivity, typer.Option("--sensitivity")],
    trust_level: Annotated[TrustLevel, typer.Option("--trust")],
    publication_date: Annotated[str | None, typer.Option("--publication-date")] = None,
    root: RootOption = Path("knowledge"),
) -> None:
    """Preserve one approved source and generate a human-review packet."""
    try:
        manifest = register_source(
            root,
            source,
            title=title,
            origin=origin,
            source_type=source_type,
            sensitivity=sensitivity,
            trust_level=trust_level,
            publication_date=(date.fromisoformat(publication_date) if publication_date else None),
        )
    except (KnowledgeError, OSError, ValueError) as exc:
        typer.secho(f"Registration failed: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc

    typer.secho("Source registered safely", fg=typer.colors.GREEN)
    typer.echo(f"Source ID: {manifest.source_id}")
    typer.echo(f"SHA-256: {manifest.sha256}")
    typer.echo(f"Preserved path: {manifest.preserved_relative_path}")
    typer.echo(f"Prompt-injection review: {manifest.prompt_injection_review_status.value}")
    typer.echo(f"Review packet: review/pending/{manifest.source_id}.md")


@app.command("status")
def status(root: RootOption = Path("knowledge")) -> None:
    """Display controlled knowledge-store readiness and review state."""
    state = KnowledgeStore(root).status()
    typer.echo(f"Total sources: {state.total_sources}")
    typer.echo(f"Pending review: {state.pending_review}")
    typer.echo(f"Approved: {state.approved}")
    typer.echo(f"Needs changes: {state.needs_changes}")
    typer.echo(f"Rejected: {state.rejected}")
    typer.echo(f"Machine-flagged injection review: {state.injection_flagged}")
    typer.echo(f"Wiki notes: {state.wiki_notes}")


@app.command("review")
def review(
    source_id: str,
    status: HumanReviewStatus,
    note: Annotated[str, typer.Option("--note", prompt=True)],
    injection_status: Annotated[
        InjectionReviewStatus | None,
        typer.Option("--injection-status"),
    ] = None,
    root: RootOption = Path("knowledge"),
) -> None:
    """Apply an explicit human review decision to one registered source."""
    try:
        manifest = review_source(
            root,
            source_id,
            status=status,
            note=note,
            injection_status=injection_status,
        )
    except (KnowledgeError, OSError, ValueError) as exc:
        typer.secho(f"Review failed: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc

    typer.secho("Human review recorded", fg=typer.colors.GREEN)
    typer.echo(f"Source ID: {manifest.source_id}")
    typer.echo(f"Review status: {manifest.human_review_status.value}")
    typer.echo(f"Prompt-injection review: {manifest.prompt_injection_review_status.value}")


@app.command("publish")
def publish(
    source_id: str,
    slug: Annotated[str, typer.Option("--slug")],
    title: Annotated[str, typer.Option("--title")],
    body_file: Annotated[
        Path,
        typer.Option(
            "--body-file",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            resolve_path=True,
        ),
    ],
    root: RootOption = Path("knowledge"),
) -> None:
    """Publish a human-authored atomised note from an approved source."""
    try:
        body = body_file.read_text(encoding="utf-8")
        path = KnowledgeStore(root).publish_note(
            source_id,
            slug=slug,
            title=title,
            body=body,
        )
    except (KnowledgeError, OSError, UnicodeError, ValueError) as exc:
        typer.secho(f"Publication failed: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc

    typer.secho("Atomised note published", fg=typer.colors.GREEN)
    typer.echo(f"Path: {path}")
