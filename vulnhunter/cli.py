"""Command-line interface for VulnHunter AI."""

from __future__ import annotations

import os
import platform
import sys
from pathlib import Path

import typer

from vulnhunter import __version__
from vulnhunter.exceptions import ScopeValidationError
from vulnhunter.scope import validate_target

app = typer.Typer(
    name="vulnhunter",
    help="Authorised laboratory-only vulnerability testing research platform.",
    no_args_is_help=True,
)

scope_app = typer.Typer(
    help="Validate and manage authorised laboratory targets.",
    no_args_is_help=True,
)

app.add_typer(scope_app, name="scope")


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


if __name__ == "__main__":
    app()
