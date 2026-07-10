"""CLI for governed collection campaigns and authenticated review identities."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from vulnhunter.authorization import AuthorizationStore
from vulnhunter.exceptions import GovernanceError
from vulnhunter.governance.models import CampaignLimits, IdentityStatus, ReviewOutcome
from vulnhunter.governance.readiness import assess_pilot_readiness
from vulnhunter.governance.service import (
    activate_campaign,
    adjudicate_governed_review,
    approve_campaign,
    assess_release,
    assign_reviewers,
    bootstrap_administrator,
    change_identity_status,
    complete_campaign,
    create_campaign,
    create_identity,
    link_scan,
    reactivate_identity,
    register_application,
    release_dataset,
    submit_governed_review,
)
from vulnhunter.governance.store import GovernanceStore
from vulnhunter.observations.storage import ScanRepository

app = typer.Typer(
    help="Govern authorized collection campaigns and authenticated review identities.",
    no_args_is_help=True,
)
identity_app = typer.Typer(
    help="Manage local authenticated governance identities.", no_args_is_help=True
)
campaign_app = typer.Typer(help="Manage governed data-collection campaigns.", no_args_is_help=True)
app.add_typer(identity_app, name="identity")
app.add_typer(campaign_app, name="campaign")

GovernanceDatabase = Annotated[
    Path,
    typer.Option(
        "--governance-database",
        help="SQLite governance registry.",
    ),
]
AuthorizationDatabase = Annotated[
    Path,
    typer.Option(
        "--authorization-database",
        help="SQLite target-authorization registry.",
    ),
]
ActorSecret = Annotated[
    str,
    typer.Option(
        "--secret",
        prompt=True,
        hide_input=True,
        help="Local identity secret. Omit the option value to use a hidden prompt.",
    ),
]


def open_governance_store(path: Path) -> GovernanceStore:
    store = GovernanceStore.from_path(path)
    store.initialize()
    return store


def open_authorization_store(path: Path) -> AuthorizationStore:
    store = AuthorizationStore.from_path(path)
    store.initialize()
    return store


def open_repository(path: Path) -> ScanRepository:
    repository = ScanRepository.from_path(path)
    repository.initialize()
    return repository


def repository_map(paths: list[Path]) -> dict[str, ScanRepository]:
    if not paths:
        raise ValueError("At least one --scan-database is required.")
    result: dict[str, ScanRepository] = {}
    for path in paths:
        resolved = str(path.expanduser().resolve())
        result[resolved] = open_repository(path)
    return result


def _run(operation):
    try:
        return operation()
    except (GovernanceError, ValidationError, ValueError, OSError) as exc:
        typer.secho(f"Governance operation stopped safely: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc


@identity_app.command("bootstrap")
def identity_bootstrap(
    reviewer_id: Annotated[str, typer.Option("--reviewer")],
    display_name: Annotated[str, typer.Option("--display-name")],
    secret: Annotated[
        str,
        typer.Option(
            "--secret",
            prompt=True,
            hide_input=True,
            confirmation_prompt=True,
        ),
    ],
    governance_database: GovernanceDatabase = Path("governance.db"),
) -> None:
    """Create the first campaign administrator in an empty registry."""
    identity = _run(
        lambda: bootstrap_administrator(
            open_governance_store(governance_database),
            reviewer_id=reviewer_id,
            display_name=display_name,
            secret=secret,
        )
    )
    typer.secho(f"Bootstrapped administrator: {identity.reviewer_id}", fg=typer.colors.GREEN)


@identity_app.command("create")
def identity_create(
    actor: Annotated[str, typer.Option("--actor")],
    actor_secret: ActorSecret,
    reviewer_id: Annotated[str, typer.Option("--reviewer")],
    display_name: Annotated[str, typer.Option("--display-name")],
    new_secret: Annotated[
        str,
        typer.Option(
            "--new-secret",
            prompt=True,
            hide_input=True,
            confirmation_prompt=True,
        ),
    ],
    roles: Annotated[list[str] | None, typer.Option("--role")] = None,
    conflict_tags: Annotated[list[str] | None, typer.Option("--conflict-tag")] = None,
    governance_database: GovernanceDatabase = Path("governance.db"),
) -> None:
    """Create a reviewer, adjudicator, or additional administrator."""
    identity = _run(
        lambda: create_identity(
            open_governance_store(governance_database),
            actor_id=actor,
            actor_secret=actor_secret,
            reviewer_id=reviewer_id,
            display_name=display_name,
            secret=new_secret,
            roles=tuple(roles or ()),
            conflict_tags=tuple(conflict_tags or ()),
        )
    )
    typer.secho(f"Created identity: {identity.reviewer_id}", fg=typer.colors.GREEN)
    typer.echo("Roles: " + ", ".join(identity.roles))


@identity_app.command("list")
def identity_list(
    governance_database: GovernanceDatabase = Path("governance.db"),
) -> None:
    """List identities without exposing credential material."""
    identities = _run(lambda: open_governance_store(governance_database).list_identities())
    if not identities:
        typer.echo("No governance identities found.")
        return
    for identity in identities:
        typer.echo(
            f"{identity.reviewer_id} status={identity.status} "
            f"roles={','.join(identity.roles)} conflicts={','.join(identity.conflict_tags) or '-'}"
        )


@identity_app.command("status")
def identity_status(
    actor: Annotated[str, typer.Option("--actor")],
    secret: ActorSecret,
    reviewer_id: Annotated[str, typer.Option("--reviewer")],
    status: Annotated[IdentityStatus, typer.Option("--status")],
    reason: Annotated[str, typer.Option("--reason")],
    governance_database: GovernanceDatabase = Path("governance.db"),
) -> None:
    """Disable or permanently revoke another identity."""
    identity = _run(
        lambda: change_identity_status(
            open_governance_store(governance_database),
            actor_id=actor,
            actor_secret=secret,
            reviewer_id=reviewer_id,
            status=status,
            reason=reason,
        )
    )
    typer.secho(f"Identity {identity.reviewer_id} is {identity.status}.", fg=typer.colors.GREEN)


@identity_app.command("reactivate")
def identity_reactivate(
    actor: Annotated[str, typer.Option("--actor")],
    secret: ActorSecret,
    reviewer_id: Annotated[str, typer.Option("--reviewer")],
    reason: Annotated[str, typer.Option("--reason")],
    governance_database: GovernanceDatabase = Path("governance.db"),
) -> None:
    """Reactivate a disabled identity; revoked identities stay revoked."""
    identity = _run(
        lambda: reactivate_identity(
            open_governance_store(governance_database),
            actor_id=actor,
            actor_secret=secret,
            reviewer_id=reviewer_id,
            reason=reason,
        )
    )
    typer.secho(f"Identity {identity.reviewer_id} is active.", fg=typer.colors.GREEN)


@identity_app.command("integrity")
def identity_integrity(
    governance_database: GovernanceDatabase = Path("governance.db"),
) -> None:
    """Verify all governance records and the global event hash chain."""
    _run(lambda: open_governance_store(governance_database).verify_integrity())
    typer.secho("Governance integrity verified.", fg=typer.colors.GREEN)


@campaign_app.command("create")
def campaign_create(
    actor: Annotated[str, typer.Option("--actor")],
    secret: ActorSecret,
    title: Annotated[str, typer.Option("--title")],
    purpose: Annotated[str, typer.Option("--purpose")],
    owner: Annotated[str, typer.Option("--owner")],
    maximum_pages: Annotated[int, typer.Option("--max-pages", min=1, max=500)] = 20,
    maximum_depth: Annotated[int, typer.Option("--max-depth", min=0, max=10)] = 2,
    maximum_requests: Annotated[int, typer.Option("--max-requests", min=1, max=10_000)] = 100,
    minimum_delay: Annotated[float, typer.Option("--minimum-delay", min=0, max=10)] = 0.2,
    maximum_scans_per_application: Annotated[
        int,
        typer.Option("--max-scans-per-application", min=1, max=1_000),
    ] = 10,
    minimum_applications: Annotated[int, typer.Option("--minimum-applications", min=1)] = 2,
    minimum_families: Annotated[int, typer.Option("--minimum-families", min=1)] = 2,
    minimum_observations: Annotated[int, typer.Option("--minimum-observations", min=1)] = 20,
    governance_database: GovernanceDatabase = Path("governance.db"),
) -> None:
    """Create a draft governed collection campaign."""
    campaign = _run(
        lambda: create_campaign(
            open_governance_store(governance_database),
            actor_id=actor,
            actor_secret=secret,
            title=title,
            purpose=purpose,
            owner_id=owner,
            limits=CampaignLimits(
                maximum_pages=maximum_pages,
                maximum_depth=maximum_depth,
                maximum_requests=maximum_requests,
                minimum_request_delay_seconds=minimum_delay,
                maximum_scans_per_application=maximum_scans_per_application,
            ),
            minimum_applications=minimum_applications,
            minimum_application_families=minimum_families,
            minimum_reviewed_observations=minimum_observations,
        )
    )
    typer.secho(f"Created campaign: {campaign.campaign_id}", fg=typer.colors.GREEN)


@campaign_app.command("add-application")
def campaign_add_application(
    campaign_id: Annotated[str, typer.Argument()],
    actor: Annotated[str, typer.Option("--actor")],
    secret: ActorSecret,
    authorization_id: Annotated[str, typer.Option("--authorization")],
    application_family: Annotated[str, typer.Option("--family")],
    environment: Annotated[str, typer.Option("--environment")],
    conflict_tags: Annotated[list[str] | None, typer.Option("--conflict-tag")] = None,
    governance_database: GovernanceDatabase = Path("governance.db"),
    authorization_database: AuthorizationDatabase = Path("authorizations.db"),
) -> None:
    """Bind an active authorization into a campaign draft."""
    application = _run(
        lambda: register_application(
            open_governance_store(governance_database),
            open_authorization_store(authorization_database),
            actor_id=actor,
            actor_secret=secret,
            campaign_id=campaign_id,
            authorization_id=authorization_id,
            application_family=application_family,
            environment=environment,
            conflict_tags=tuple(conflict_tags or ()),
        )
    )
    typer.secho(f"Registered application: {application.application_id}", fg=typer.colors.GREEN)


@campaign_app.command("approve")
def campaign_approve(
    campaign_id: Annotated[str, typer.Argument()],
    actor: Annotated[str, typer.Option("--actor")],
    secret: ActorSecret,
    governance_database: GovernanceDatabase = Path("governance.db"),
    authorization_database: AuthorizationDatabase = Path("authorizations.db"),
) -> None:
    """Approve the exact draft with a distinct administrator."""
    campaign = _run(
        lambda: approve_campaign(
            open_governance_store(governance_database),
            open_authorization_store(authorization_database),
            actor_id=actor,
            actor_secret=secret,
            campaign_id=campaign_id,
        )
    )
    typer.secho(f"Approved campaign: {campaign.campaign_id}", fg=typer.colors.GREEN)
    typer.echo(f"Manifest SHA-256: {campaign.approved_manifest_sha256}")


@campaign_app.command("activate")
def campaign_activate(
    campaign_id: Annotated[str, typer.Argument()],
    actor: Annotated[str, typer.Option("--actor")],
    secret: ActorSecret,
    governance_database: GovernanceDatabase = Path("governance.db"),
    authorization_database: AuthorizationDatabase = Path("authorizations.db"),
) -> None:
    """Activate an approved campaign after revalidating authorizations."""
    campaign = _run(
        lambda: activate_campaign(
            open_governance_store(governance_database),
            open_authorization_store(authorization_database),
            actor_id=actor,
            actor_secret=secret,
            campaign_id=campaign_id,
        )
    )
    typer.secho(f"Campaign {campaign.campaign_id} is active.", fg=typer.colors.GREEN)


@campaign_app.command("link-scan")
def campaign_link_scan(
    campaign_id: Annotated[str, typer.Argument()],
    application_id: Annotated[str, typer.Option("--application")],
    scan_id: Annotated[int, typer.Option("--scan-id", min=1)],
    scan_database: Annotated[Path, typer.Option("--scan-database")],
    actor: Annotated[str, typer.Option("--actor")],
    secret: ActorSecret,
    governance_database: GovernanceDatabase = Path("governance.db"),
    authorization_database: AuthorizationDatabase = Path("authorizations.db"),
) -> None:
    """Link a completed scan using authorization and scan evidence."""
    linked = _run(
        lambda: link_scan(
            open_governance_store(governance_database),
            open_authorization_store(authorization_database),
            open_repository(scan_database),
            actor_id=actor,
            actor_secret=secret,
            campaign_id=campaign_id,
            application_id=application_id,
            scan_database=scan_database,
            scan_id=scan_id,
        )
    )
    typer.secho(
        f"Linked scan {linked.scan_database}#{linked.scan_id}.",
        fg=typer.colors.GREEN,
    )


@campaign_app.command("assign")
def campaign_assign(
    campaign_id: Annotated[str, typer.Argument()],
    observation_id: Annotated[int, typer.Option("--observation", min=1)],
    scan_database: Annotated[Path, typer.Option("--scan-database")],
    first_reviewer: Annotated[str, typer.Option("--first-reviewer")],
    second_reviewer: Annotated[str, typer.Option("--second-reviewer")],
    actor: Annotated[str, typer.Option("--actor")],
    secret: ActorSecret,
    adjudicator: Annotated[str | None, typer.Option("--adjudicator")] = None,
    governance_database: GovernanceDatabase = Path("governance.db"),
) -> None:
    """Assign two conflict-checked reviewers and an optional adjudicator."""
    assignment = _run(
        lambda: assign_reviewers(
            open_governance_store(governance_database),
            open_repository(scan_database),
            actor_id=actor,
            actor_secret=secret,
            campaign_id=campaign_id,
            scan_database=scan_database,
            observation_id=observation_id,
            first_reviewer_id=first_reviewer,
            second_reviewer_id=second_reviewer,
            adjudicator_id=adjudicator,
        )
    )
    typer.secho(
        f"Assigned observation {assignment.observation_id} to "
        f"{assignment.primary_reviewers[0]} and {assignment.primary_reviewers[1]}.",
        fg=typer.colors.GREEN,
    )


@campaign_app.command("review")
def campaign_review(
    campaign_id: Annotated[str, typer.Argument()],
    observation_id: Annotated[int, typer.Option("--observation", min=1)],
    scan_database: Annotated[Path, typer.Option("--scan-database")],
    actor: Annotated[str, typer.Option("--actor")],
    secret: ActorSecret,
    outcome: Annotated[ReviewOutcome, typer.Option("--label")],
    note: Annotated[str | None, typer.Option("--note")] = None,
    governance_database: GovernanceDatabase = Path("governance.db"),
) -> None:
    """Submit an authenticated assigned primary-review decision."""
    attestation = _run(
        lambda: submit_governed_review(
            open_governance_store(governance_database),
            open_repository(scan_database),
            actor_id=actor,
            actor_secret=secret,
            campaign_id=campaign_id,
            scan_database=scan_database,
            observation_id=observation_id,
            outcome=outcome,
            note=note,
        )
    )
    typer.secho(f"Review attested: {attestation.attestation_id}", fg=typer.colors.GREEN)


@campaign_app.command("adjudicate")
def campaign_adjudicate(
    campaign_id: Annotated[str, typer.Argument()],
    observation_id: Annotated[int, typer.Option("--observation", min=1)],
    scan_database: Annotated[Path, typer.Option("--scan-database")],
    actor: Annotated[str, typer.Option("--actor")],
    secret: ActorSecret,
    outcome: Annotated[ReviewOutcome, typer.Option("--label")],
    rationale: Annotated[str, typer.Option("--rationale")],
    governance_database: GovernanceDatabase = Path("governance.db"),
) -> None:
    """Resolve a disagreement using the assigned authenticated adjudicator."""
    attestation = _run(
        lambda: adjudicate_governed_review(
            open_governance_store(governance_database),
            open_repository(scan_database),
            actor_id=actor,
            actor_secret=secret,
            campaign_id=campaign_id,
            scan_database=scan_database,
            observation_id=observation_id,
            outcome=outcome,
            rationale=rationale,
        )
    )
    typer.secho(f"Adjudication attested: {attestation.attestation_id}", fg=typer.colors.GREEN)


@campaign_app.command("status")
def campaign_status(
    campaign_id: Annotated[str, typer.Argument()],
    governance_database: GovernanceDatabase = Path("governance.db"),
) -> None:
    """Show campaign lifecycle, diversity, scan, and review counts."""
    store = open_governance_store(governance_database)
    campaign = _run(lambda: store.get_campaign(campaign_id))
    applications = _run(lambda: store.list_applications(campaign_id))
    scans = _run(lambda: store.list_scans(campaign_id))
    assignments = _run(lambda: store.list_assignments(campaign_id))
    typer.echo(f"Campaign: {campaign.campaign_id}")
    typer.echo(f"Status: {campaign.status}")
    typer.echo(f"Applications: {len(applications)}")
    typer.echo(f"Application families: {len({item.application_family for item in applications})}")
    typer.echo(f"Linked scans: {len(scans)}")
    typer.echo(f"Assignments: {len(assignments)}")
    typer.echo(f"Approved manifest: {campaign.approved_manifest_sha256 or '-'}")


@campaign_app.command("release-check")
def campaign_release_check(
    campaign_id: Annotated[str, typer.Argument()],
    scan_databases: Annotated[list[Path], typer.Option("--scan-database")],
    governance_database: GovernanceDatabase = Path("governance.db"),
    authorization_database: AuthorizationDatabase = Path("authorizations.db"),
) -> None:
    """Evaluate the deterministic dataset release gate without changing state."""
    assessment = _run(
        lambda: assess_release(
            open_governance_store(governance_database),
            open_authorization_store(authorization_database),
            repository_map(scan_databases),
            campaign_id=campaign_id,
            require_completed=True,
        )
    )
    typer.echo(json.dumps(assessment.model_dump(mode="json"), indent=2, sort_keys=True))
    if not assessment.ready:
        raise typer.Exit(code=1)


@campaign_app.command("readiness")
def campaign_readiness(
    campaign_id: Annotated[str, typer.Argument()],
    scan_databases: Annotated[list[Path], typer.Option("--scan-database")],
    governance_database: GovernanceDatabase = Path("governance.db"),
    authorization_database: AuthorizationDatabase = Path("authorizations.db"),
    output: Annotated[Path | None, typer.Option("--output")] = None,
    format_: Annotated[str, typer.Option("--format")] = "text",
) -> None:
    """Export deterministic governed pilot and dataset-readiness evidence."""
    report = _run(
        lambda: assess_pilot_readiness(
            open_governance_store(governance_database),
            open_authorization_store(authorization_database),
            repository_map(scan_databases),
            campaign_id=campaign_id,
        )
    )
    payload = json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"
    if output is not None:
        resolved = output.expanduser().resolve()
        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.write_text(payload, encoding="utf-8")
    if format_ == "json":
        typer.echo(payload, nl=False)
    elif format_ == "text":
        metrics = report.informational_metrics
        typer.echo(f"Campaign: {report.campaign_id}")
        typer.echo(f"Pilot ready: {report.pilot_ready}")
        typer.echo(f"Model-training ready: {report.model_training_ready}")
        typer.echo(f"Applications: {metrics['application_count']}")
        typer.echo(f"Application families: {metrics['application_family_count']}")
        typer.echo(f"Linked scans: {metrics['scan_count']}")
        typer.echo(f"Observations: {metrics['observation_count']}")
        typer.echo(f"Final labels: {metrics['class_counts']}")
        typer.echo(f"Release manifest SHA-256: {report.release_manifest_sha256 or '-'}")
        typer.echo(f"Dataset SHA-256: {report.dataset_sha256}")
        typer.echo(f"Report SHA-256: {report.report_sha256}")
        if report.hard_release_blockers:
            typer.echo("Hard release blockers:")
            for reason in report.hard_release_blockers:
                typer.echo(f"- {reason}")
        if report.model_training_blockers:
            typer.echo("Model-training blockers:")
            for reason in report.model_training_blockers:
                typer.echo(f"- {reason}")
        if report.warnings:
            typer.echo("Warnings:")
            for reason in report.warnings:
                typer.echo(f"- {reason}")
    else:
        raise typer.BadParameter("--format must be 'text' or 'json'.")
    if not report.pilot_ready:
        raise typer.Exit(code=1)


@campaign_app.command("complete")
def campaign_complete(
    campaign_id: Annotated[str, typer.Argument()],
    scan_databases: Annotated[list[Path], typer.Option("--scan-database")],
    actor: Annotated[str, typer.Option("--actor")],
    secret: ActorSecret,
    governance_database: GovernanceDatabase = Path("governance.db"),
    authorization_database: AuthorizationDatabase = Path("authorizations.db"),
) -> None:
    """Complete a campaign after every collection and review gate passes."""
    campaign = _run(
        lambda: complete_campaign(
            open_governance_store(governance_database),
            open_authorization_store(authorization_database),
            repository_map(scan_databases),
            actor_id=actor,
            actor_secret=secret,
            campaign_id=campaign_id,
        )
    )
    typer.secho(f"Campaign {campaign.campaign_id} completed.", fg=typer.colors.GREEN)


@campaign_app.command("release")
def campaign_release(
    campaign_id: Annotated[str, typer.Argument()],
    scan_databases: Annotated[list[Path], typer.Option("--scan-database")],
    actor: Annotated[str, typer.Option("--actor")],
    secret: ActorSecret,
    output: Annotated[Path, typer.Option("--output")] = Path("artifacts/dataset-release.json"),
    governance_database: GovernanceDatabase = Path("governance.db"),
    authorization_database: AuthorizationDatabase = Path("authorizations.db"),
) -> None:
    """Create and export the immutable governed dataset release manifest."""
    manifest = _run(
        lambda: release_dataset(
            open_governance_store(governance_database),
            open_authorization_store(authorization_database),
            repository_map(scan_databases),
            actor_id=actor,
            actor_secret=secret,
            campaign_id=campaign_id,
        )
    )
    output = output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(manifest.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    typer.secho(f"Dataset release manifest: {output}", fg=typer.colors.GREEN)
    typer.echo(f"Manifest SHA-256: {manifest.manifest_sha256}")
