"""CLI for runtime-enforced unattended operation permissions."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from vulnhunter.exceptions import UnattendedError
from vulnhunter.unattended.models import ActionKind, BlockerClass, CommandId
from vulnhunter.unattended.service import (
    approve_manifest,
    check_action,
    complete_run,
    create_manifest,
    load_manifest_spec,
    recommend_from_file,
    record_failure,
    record_task_success,
    run_fixed_command,
    start_run,
    write_manifest_template,
)
from vulnhunter.unattended.store import UnattendedStore

app = typer.Typer(
    help="Govern bounded unattended work with explicit runtime-enforced permissions.",
    no_args_is_help=True,
)

StoreOption = Annotated[
    Path,
    typer.Option("--store", help="Local permission manifests, runs, evidence, and events."),
]


def _store(path: Path) -> UnattendedStore:
    return UnattendedStore.from_path(path)


def _fail(exc: Exception) -> None:
    typer.secho(f"Unattended operation failed: {exc}", fg=typer.colors.RED, err=True)
    raise typer.Exit(code=2) from exc


@app.command("template")
def template(
    destination: Path,
    repository: Annotated[Path, typer.Option("--repository")] = Path("."),
) -> None:
    """Write a conservative permission-manifest template."""
    try:
        path = write_manifest_template(destination, repository=repository)
    except (UnattendedError, ValueError) as exc:
        _fail(exc)
    typer.echo(f"Permission manifest template: {path}")


@app.command("recommend")
def recommend(profile: Path) -> None:
    """Apply the scheduling decision matrix to a task profile JSON."""
    try:
        result = recommend_from_file(profile)
    except (UnattendedError, ValueError) as exc:
        _fail(exc)
    typer.echo(f"Permitted: {'yes' if result.permitted else 'no'}")
    typer.echo(f"Mode: {result.mode.value if result.mode else '-'}")
    for item in result.rationale:
        typer.echo(f"- {item}")
    typer.echo("Required controls:")
    for item in result.required_controls:
        typer.echo(f"- {item}")
    if not result.permitted:
        raise typer.Exit(code=1)


@app.command("create")
def create(
    specification: Path,
    store: StoreOption = Path("artifacts/unattended"),
) -> None:
    """Persist one immutable permission manifest."""
    try:
        manifest = create_manifest(_store(store), load_manifest_spec(specification))
    except (UnattendedError, ValueError) as exc:
        _fail(exc)
    typer.echo(f"Manifest created: {manifest.manifest_id}")


@app.command("approve")
def approve(
    manifest_id: str,
    approver: Annotated[str, typer.Option("--approver")],
    reason: Annotated[str, typer.Option("--reason")],
    store: StoreOption = Path("artifacts/unattended"),
) -> None:
    """Approve the exact immutable manifest as a distinct human actor."""
    try:
        record = approve_manifest(_store(store), manifest_id, approver_id=approver, reason=reason)
    except (UnattendedError, ValueError) as exc:
        _fail(exc)
    typer.echo(f"Manifest approved: {record.manifest_id}")
    typer.echo(f"Manifest SHA-256: {record.manifest_sha256}")


@app.command("start")
def start(
    manifest_id: str,
    actor: Annotated[str, typer.Option("--actor")],
    store: StoreOption = Path("artifacts/unattended"),
) -> None:
    """Start one run from an active approved manifest."""
    try:
        run = start_run(_store(store), manifest_id, actor_id=actor)
    except (UnattendedError, ValueError) as exc:
        _fail(exc)
    typer.echo(f"Run started: {run.run_id}")
    typer.echo(f"Repository commit: {run.repository_commit}")


@app.command("check")
def check(
    manifest_id: str,
    action: Annotated[ActionKind, typer.Option("--action")],
    value: Annotated[str, typer.Option("--value")],
    store: StoreOption = Path("artifacts/unattended"),
) -> None:
    """Check one concrete runtime action against a manifest."""
    try:
        decision = check_action(_store(store), manifest_id, action=action, value=value)
    except (UnattendedError, ValueError) as exc:
        _fail(exc)
    typer.echo(f"Allowed: {'yes' if decision.allowed else 'no'}")
    typer.echo(f"Reason: {decision.rationale}")
    if not decision.allowed:
        raise typer.Exit(code=1)


@app.command("run-command")
def run_command(
    run_id: str,
    command: Annotated[CommandId, typer.Option("--command")],
    actor: Annotated[str, typer.Option("--actor")],
    timeout: Annotated[int, typer.Option("--timeout", min=5, max=3_600)] = 300,
    store: StoreOption = Path("artifacts/unattended"),
) -> None:
    """Run one approved fixed command without a shell."""
    try:
        evidence, run = run_fixed_command(
            _store(store),
            run_id,
            command_id=command,
            actor_id=actor,
            timeout_seconds=timeout,
        )
    except (UnattendedError, ValueError) as exc:
        _fail(exc)
    typer.echo(f"Command: {evidence.command_id.value}")
    typer.echo(f"Return code: {evidence.return_code}")
    typer.echo(f"Iterations used: {run.iterations_used}")
    if evidence.stdout:
        typer.echo(evidence.stdout)
    if evidence.stderr:
        typer.echo(evidence.stderr, err=True)
    if evidence.return_code != 0:
        raise typer.Exit(code=1)


@app.command("record-failure")
def failure(
    run_id: str,
    actor: Annotated[str, typer.Option("--actor")],
    item: Annotated[str, typer.Option("--item")],
    operation: Annotated[str, typer.Option("--operation")],
    code: Annotated[str, typer.Option("--code")],
    summary: Annotated[str, typer.Option("--summary")],
    blocker: Annotated[BlockerClass, typer.Option("--class")],
    store: StoreOption = Path("artifacts/unattended"),
) -> None:
    """Record and classify one failure for blocker isolation."""
    try:
        record, run = record_failure(
            _store(store),
            run_id,
            actor_id=actor,
            item_id=item,
            operation=operation,
            error_code=code,
            summary=summary,
            blocker_class=blocker,
        )
    except (UnattendedError, ValueError) as exc:
        _fail(exc)
    typer.echo(f"Occurrence: {record.occurrence}")
    typer.echo(f"Isolated: {'yes' if record.isolated else 'no'}")
    typer.echo(f"Workflow halted: {'yes' if record.workflow_halted else 'no'}")
    typer.echo(f"Run state: {run.state.value}")


@app.command("task-success")
def task_success(
    run_id: str,
    actor: Annotated[str, typer.Option("--actor")],
    task: Annotated[str, typer.Option("--task")],
    store: StoreOption = Path("artifacts/unattended"),
) -> None:
    """Record successful progress on one declared independent task."""
    try:
        run = record_task_success(_store(store), run_id, actor_id=actor, task_id=task)
    except (UnattendedError, ValueError) as exc:
        _fail(exc)
    typer.echo(f"Task recorded: {task}")
    typer.echo(f"Run state: {run.state.value}")


@app.command("complete")
def complete(
    run_id: str,
    actor: Annotated[str, typer.Option("--actor")],
    store: StoreOption = Path("artifacts/unattended"),
) -> None:
    """Complete a run only after every required verifier passed."""
    try:
        run = complete_run(_store(store), run_id, actor_id=actor)
    except (UnattendedError, ValueError) as exc:
        _fail(exc)
    typer.echo(f"Run completed: {run.run_id}")


@app.command("status")
def status(
    subject_id: str,
    run: Annotated[bool, typer.Option("--run")] = False,
    store: StoreOption = Path("artifacts/unattended"),
) -> None:
    """Verify and display one manifest or run."""
    try:
        repository = _store(store)
        if run:
            record = repository.verify_run(subject_id)
            typer.echo(f"Run ID: {record.run_id}")
            typer.echo(f"State: {record.state.value}")
            typer.echo(f"Iterations: {record.iterations_used}")
            typer.echo(f"Isolated items: {', '.join(record.isolated_item_ids) or '-'}")
        else:
            manifest = repository.verify_manifest(subject_id)
            typer.echo(f"Manifest ID: {manifest.manifest_id}")
            typer.echo(f"Mode: {manifest.execution_mode.value}")
            typer.echo(f"Loop ID: {manifest.loop_id}")
    except (UnattendedError, ValueError) as exc:
        _fail(exc)


@app.command("revoke")
def revoke(
    manifest_id: str,
    actor: Annotated[str, typer.Option("--actor")],
    reason: Annotated[str, typer.Option("--reason")],
    store: StoreOption = Path("artifacts/unattended"),
) -> None:
    """Revoke a manifest without deleting its audit history."""
    try:
        _store(store).revoke_manifest(manifest_id, actor_id=actor, reason=reason)
    except (UnattendedError, ValueError) as exc:
        _fail(exc)
    typer.echo(f"Manifest revoked: {manifest_id}")
