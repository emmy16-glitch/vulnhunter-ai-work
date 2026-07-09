"""Typer commands for explicit laboratory target authorization."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from vulnhunter.authorization.models import AuthorizationLimits
from vulnhunter.authorization.service import (
    issue_authorization,
    validate_scan_authorization,
)
from vulnhunter.authorization.store import AuthorizationStore
from vulnhunter.exceptions import AuthorizationError, ScopeValidationError
from vulnhunter.scope import validate_target

app = typer.Typer(
    help="Create, inspect, validate, and revoke explicit scan authorizations.",
    no_args_is_help=True,
)

AuthorizationDatabaseOption = Annotated[
    Path,
    typer.Option(
        "--authorization-database",
        "-a",
        help="SQLite file containing authorization records and audit events.",
    ),
]


def open_authorization_store(path: Path) -> AuthorizationStore:
    """Open and initialize a local authorization registry."""
    store = AuthorizationStore.from_path(path)
    store.initialize()
    return store


def parse_iso_timestamp(value: str) -> datetime:
    """Parse one timezone-aware ISO-8601 timestamp for CLI use."""
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise AuthorizationError(
            "Timestamp must be ISO-8601, for example 2026-08-01T18:00:00+01:00."
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise AuthorizationError("Timestamp must include a timezone offset.")
    return parsed.astimezone(UTC)


@app.command("create")
def create_authorization(
    url: str,
    owner: Annotated[str, typer.Option("--owner", help="Owner of the target.")],
    approved_by: Annotated[
        str,
        typer.Option("--approved-by", help="Person granting testing permission."),
    ],
    purpose: Annotated[
        str,
        typer.Option("--purpose", help="Specific approved testing purpose."),
    ],
    expires_at: Annotated[
        str,
        typer.Option(
            "--expires-at",
            help="Timezone-aware ISO-8601 expiry, such as 2026-08-01T18:00:00+01:00.",
        ),
    ],
    database: AuthorizationDatabaseOption = Path("authorizations.db"),
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
    minimum_delay: Annotated[
        float,
        typer.Option("--minimum-delay", min=0, max=10),
    ] = 0.2,
    evidence_reference: Annotated[
        str | None,
        typer.Option(
            "--evidence-reference",
            help="Reference to the permission evidence; do not paste secrets.",
        ),
    ] = None,
) -> None:
    """Create a time-limited authorization for one validated lab target."""
    try:
        target = validate_target(url)
        record = issue_authorization(
            open_authorization_store(database),
            target,
            owner=owner,
            approved_by=approved_by,
            purpose=purpose,
            expires_at=parse_iso_timestamp(expires_at),
            evidence_reference=evidence_reference,
            limits=AuthorizationLimits(
                maximum_pages=maximum_pages,
                maximum_depth=maximum_depth,
                maximum_requests=maximum_requests,
                minimum_request_delay_seconds=minimum_delay,
            ),
        )
    except (
        AuthorizationError,
        ScopeValidationError,
        ValidationError,
        ValueError,
    ) as exc:
        typer.secho(
            f"Authorization creation failed safely: {exc}",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=2) from exc

    typer.secho("Authorization created", fg=typer.colors.GREEN)
    typer.echo(f"Authorization ID: {record.authorization_id}")
    typer.echo(f"Target: {record.target_url}")
    typer.echo(f"Valid from: {record.valid_from.isoformat()}")
    typer.echo(f"Expires: {record.expires_at.isoformat()}")
    typer.echo(f"Record SHA-256: {record.record_sha256}")


@app.command("list")
def list_authorizations(
    database: AuthorizationDatabaseOption = Path("authorizations.db"),
    limit: Annotated[int, typer.Option("--limit", min=1, max=1_000)] = 100,
) -> None:
    """List recent authorization records."""
    try:
        records = open_authorization_store(database).list(limit=limit)
    except (AuthorizationError, ValidationError, ValueError) as exc:
        typer.secho(f"Unable to list authorizations: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc

    if not records:
        typer.echo("No authorizations found.")
        return

    now = datetime.now(UTC)
    for record in records:
        effective = (
            "expired" if record.status == "active" and now >= record.expires_at else record.status
        )
        typer.echo(
            f"{record.authorization_id} {effective.upper()} "
            f"expires={record.expires_at.isoformat()} target={record.target_url}"
        )


@app.command("show")
def show_authorization(
    authorization_id: str,
    database: AuthorizationDatabaseOption = Path("authorizations.db"),
) -> None:
    """Display one integrity-checked authorization."""
    try:
        record = open_authorization_store(database).get(authorization_id)
    except (AuthorizationError, ValidationError, ValueError) as exc:
        typer.secho(f"Unable to load authorization: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc

    typer.echo(f"Authorization ID: {record.authorization_id}")
    typer.echo(f"Status: {record.status}")
    typer.echo(f"Target: {record.target_url}")
    typer.echo(f"Path boundary: {record.path_boundary}")
    typer.echo(f"Approved addresses: {', '.join(record.approved_addresses)}")
    typer.echo(f"Owner: {record.owner}")
    typer.echo(f"Approved by: {record.approved_by}")
    typer.echo(f"Purpose: {record.purpose}")
    typer.echo(f"Valid from: {record.valid_from.isoformat()}")
    typer.echo(f"Expires: {record.expires_at.isoformat()}")
    typer.echo(
        "Limits: "
        f"pages={record.limits.maximum_pages}, "
        f"depth={record.limits.maximum_depth}, "
        f"requests={record.limits.maximum_requests}, "
        f"minimum_delay={record.limits.minimum_request_delay_seconds:g}s"
    )
    typer.echo(f"Record SHA-256: {record.record_sha256}")
    if record.revoked_at:
        typer.echo(f"Revoked at: {record.revoked_at.isoformat()}")
        typer.echo(f"Revocation reason: {record.revocation_reason}")


@app.command("check")
def check_authorization(
    authorization_id: str,
    url: str,
    database: AuthorizationDatabaseOption = Path("authorizations.db"),
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
    request_delay: Annotated[
        float,
        typer.Option("--delay", min=0, max=10),
    ] = 0.2,
) -> None:
    """Validate a proposed passive scan without starting it."""
    try:
        target = validate_target(url)
        decision = validate_scan_authorization(
            open_authorization_store(database),
            authorization_id,
            target,
            maximum_pages=maximum_pages,
            maximum_depth=maximum_depth,
            maximum_requests=maximum_requests,
            request_delay_seconds=request_delay,
        )
    except (
        AuthorizationError,
        ScopeValidationError,
        ValidationError,
        ValueError,
    ) as exc:
        typer.secho(f"Authorization rejected: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc

    typer.secho("Authorization accepted", fg=typer.colors.GREEN)
    typer.echo(f"Authorization ID: {decision.authorization_id}")
    typer.echo(f"Target: {decision.target_url}")
    typer.echo(f"Checked at: {decision.checked_at.isoformat()}")


@app.command("revoke")
def revoke_authorization(
    authorization_id: str,
    reason: Annotated[str, typer.Option("--reason", help="Required revocation reason.")],
    database: AuthorizationDatabaseOption = Path("authorizations.db"),
) -> None:
    """Revoke an authorization without deleting its history."""
    try:
        record = open_authorization_store(database).revoke(
            authorization_id,
            reason=reason,
        )
    except (AuthorizationError, ValidationError, ValueError) as exc:
        typer.secho(f"Revocation failed safely: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc

    typer.secho("Authorization revoked", fg=typer.colors.YELLOW)
    typer.echo(f"Authorization ID: {record.authorization_id}")
    typer.echo(f"Revoked at: {record.revoked_at.isoformat() if record.revoked_at else ''}")


@app.command("events")
def authorization_events(
    authorization_id: str,
    database: AuthorizationDatabaseOption = Path("authorizations.db"),
    limit: Annotated[int, typer.Option("--limit", min=1, max=2_000)] = 200,
) -> None:
    """Display the append-only audit trail for one authorization."""
    try:
        events = open_authorization_store(database).list_events(
            authorization_id,
            limit=limit,
        )
    except (AuthorizationError, ValidationError, ValueError) as exc:
        typer.secho(f"Unable to load events: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc

    for event in reversed(events):
        typer.echo(
            f"#{event.event_id} {event.occurred_at.isoformat()} {event.event_type} {event.detail}"
        )
