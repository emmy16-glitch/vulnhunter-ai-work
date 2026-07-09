"""CLI for bounded engineering orchestration and evaluation."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from vulnhunter.exceptions import VulnHunterError
from vulnhunter.orchestration.models import HumanDecision, ReviewDecision
from vulnhunter.orchestration.service import (
    create_loop,
    escalate_loop,
    evaluate_loop,
    load_spec,
    record_human_approval,
    record_learning,
    recovery_plan,
    rollback_loop,
    submit_independent_review,
    verify_security_policy,
    write_template,
)
from vulnhunter.orchestration.store import LoopStore

app = typer.Typer(
    help="Run bounded engineering loops with proof, review, approval, and audit trails.",
    no_args_is_help=True,
)

StoreOption = Annotated[
    Path,
    typer.Option(
        "--store",
        help="Local directory for loop manifests, evidence, and hash-chained events.",
    ),
]


def _store(path: Path) -> LoopStore:
    return LoopStore.from_path(path)


def _fail(exc: Exception) -> None:
    typer.secho(f"Loop operation failed: {exc}", fg=typer.colors.RED, err=True)
    raise typer.Exit(code=2) from exc


@app.command("template")
def template(
    destination: Path,
) -> None:
    """Write a complete JSON specification template."""
    try:
        path = write_template(destination)
    except VulnHunterError as exc:
        _fail(exc)
    typer.echo(f"Loop specification template: {path}")


@app.command("create")
def create(
    specification: Path,
    creator: Annotated[str, typer.Option("--creator")],
    builder: Annotated[str, typer.Option("--builder")],
    store: StoreOption = Path("artifacts/loops"),
    repository: Annotated[
        Path,
        typer.Option("--repository", help="Git repository governed by the loop."),
    ] = Path("."),
) -> None:
    """Create a bounded loop from a clean Git baseline."""
    try:
        manifest = create_loop(
            _store(store),
            load_spec(specification),
            creator_id=creator,
            builder_id=builder,
            repository=repository,
        )
    except (VulnHunterError, ValueError) as exc:
        _fail(exc)
    typer.echo(f"Loop created: {manifest.loop_id}")
    typer.echo(f"Baseline: {manifest.baseline_commit}")
    typer.echo(f"Builder: {manifest.builder_id}")


@app.command("list")
def list_loops(
    store: StoreOption = Path("artifacts/loops"),
) -> None:
    """List newest orchestration loops."""
    try:
        manifests = _store(store).list_manifests()
    except VulnHunterError as exc:
        _fail(exc)
    if not manifests:
        typer.echo("No orchestration loops found.")
        return
    for item in manifests:
        typer.echo(
            f"{item.loop_id}  {item.state.value}  iterations={item.iteration_count}  "
            f"{item.spec.title}"
        )


@app.command("status")
def status(
    loop_id: str,
    store: StoreOption = Path("artifacts/loops"),
) -> None:
    """Display loop controls, roles, usage, and current state."""
    try:
        loop_store = _store(store)
        manifest, events = loop_store.verify_integrity(loop_id)
    except VulnHunterError as exc:
        _fail(exc)
    typer.echo(f"Loop ID: {manifest.loop_id}")
    typer.echo(f"State: {manifest.state.value}")
    typer.echo(f"Objective: {manifest.spec.objective}")
    typer.echo(f"Builder: {manifest.builder_id}")
    typer.echo(f"Test runner: {manifest.latest_runner_id or '-'}")
    typer.echo(f"Security verifier: {manifest.latest_security_verifier_id or '-'}")
    typer.echo(f"Reviewer: {manifest.latest_reviewer_id or '-'}")
    typer.echo(f"Human approver: {manifest.human_approver_id or '-'}")
    typer.echo(f"Iterations: {manifest.iteration_count}")
    typer.echo(f"Consecutive failures: {manifest.consecutive_failures}")
    typer.echo(f"Repeated errors: {manifest.repeated_error_count}")
    typer.echo(f"No-progress count: {manifest.no_progress_count}")
    typer.echo(f"Tokens recorded: {manifest.tokens_used}")
    typer.echo(f"Cost recorded: ${manifest.cost_usd:.4f}")
    typer.echo(f"Audit events: {len(events)}")


@app.command("verify")
def verify(
    loop_id: str,
    runner: Annotated[str, typer.Option("--runner")],
    tokens_used: Annotated[int, typer.Option("--tokens-used", min=0)] = 0,
    cost_usd: Annotated[float, typer.Option("--cost-usd", min=0)] = 0,
    store: StoreOption = Path("artifacts/loops"),
) -> None:
    """Run fixed deterministic checks and record proof evidence."""
    try:
        evidence, manifest, stop_reasons = evaluate_loop(
            _store(store),
            loop_id,
            runner_id=runner,
            tokens_used=tokens_used,
            cost_usd=cost_usd,
        )
    except (VulnHunterError, ValueError) as exc:
        _fail(exc)
    typer.echo(f"Iteration: {evidence.iteration}")
    typer.echo(f"Changed files: {evidence.changed_files_count}")
    typer.echo(f"Diff SHA-256: {evidence.diff_sha256}")
    for check in evidence.checks:
        typer.echo(
            f"{check.verifier.value}: {'PASS' if check.passed else 'FAIL'} "
            f"({check.duration_seconds:.3f}s)"
        )
    typer.echo(f"Verification: {'PASS' if evidence.passed else 'FAIL'}")
    typer.echo(f"State: {manifest.state.value}")
    for reason in stop_reasons:
        typer.secho(f"Escalation: {reason}", fg=typer.colors.YELLOW)
    if not evidence.passed:
        raise typer.Exit(code=1)


@app.command("security-check")
def security_check(
    loop_id: str,
    verifier: Annotated[str, typer.Option("--verifier")],
    store: StoreOption = Path("artifacts/loops"),
) -> None:
    """Run the separate deterministic security-policy gate."""
    try:
        evidence, manifest = verify_security_policy(
            _store(store),
            loop_id,
            verifier_id=verifier,
        )
    except (VulnHunterError, ValueError) as exc:
        _fail(exc)
    typer.echo(f"Security policy: {'PASS' if evidence.passed else 'FAIL'}")
    typer.echo(f"Diff SHA-256: {evidence.diff_sha256}")
    for finding in evidence.findings:
        typer.echo(f"- {finding}")
    typer.echo(f"State: {manifest.state.value}")
    if not evidence.passed:
        raise typer.Exit(code=1)


@app.command("review")
def review(
    loop_id: str,
    reviewer: Annotated[str, typer.Option("--reviewer")],
    decision: Annotated[ReviewDecision, typer.Option("--decision")],
    summary: Annotated[str, typer.Option("--summary")],
    limitation: Annotated[
        list[str] | None,
        typer.Option("--limitation", help="Repeat for each known limitation."),
    ] = None,
    store: StoreOption = Path("artifacts/loops"),
) -> None:
    """Record independent review of the diff and verifier evidence."""
    try:
        _, manifest = submit_independent_review(
            _store(store),
            loop_id,
            reviewer_id=reviewer,
            decision=decision,
            summary=summary,
            limitations=tuple(limitation or ()),
        )
    except (VulnHunterError, ValueError) as exc:
        _fail(exc)
    typer.echo(f"Review recorded: {decision.value}")
    typer.echo(f"State: {manifest.state.value}")


@app.command("approve")
def approve(
    loop_id: str,
    human: Annotated[str, typer.Option("--human")],
    decision: Annotated[HumanDecision, typer.Option("--decision")],
    note: Annotated[str, typer.Option("--note")],
    store: StoreOption = Path("artifacts/loops"),
) -> None:
    """Record explicit human approval or rejection."""
    try:
        _, manifest = record_human_approval(
            _store(store),
            loop_id,
            human_id=human,
            decision=decision,
            note=note,
        )
    except (VulnHunterError, ValueError) as exc:
        _fail(exc)
    typer.echo(f"Human decision recorded: {decision.value}")
    typer.echo(f"State: {manifest.state.value}")


@app.command("learn")
def learn(
    loop_id: str,
    actor: Annotated[str, typer.Option("--actor")],
    summary: Annotated[str, typer.Option("--summary")],
    limitation: Annotated[
        list[str],
        typer.Option("--limitation", help="Repeat for each known limitation."),
    ],
    documentation: Annotated[
        list[str],
        typer.Option("--documentation", help="Repeat for each changed document."),
    ],
    store: StoreOption = Path("artifacts/loops"),
) -> None:
    """Close an approved loop with documentation and a learning record."""
    try:
        _, manifest, path = record_learning(
            _store(store),
            loop_id,
            actor_id=actor,
            summary=summary,
            limitations=tuple(limitation),
            documentation_paths=tuple(documentation),
        )
    except (VulnHunterError, ValueError) as exc:
        _fail(exc)
    typer.echo(f"Learning record: {path}")
    typer.echo(f"State: {manifest.state.value}")


@app.command("evidence")
def evidence(
    loop_id: str,
    show_output: Annotated[
        bool,
        typer.Option("--show-output", help="Display redacted verifier output excerpts."),
    ] = False,
    store: StoreOption = Path("artifacts/loops"),
) -> None:
    """Display the latest deterministic and security evidence bundle."""
    try:
        loop_store = _store(store)
        manifest, _ = loop_store.verify_integrity(loop_id)
        evaluation = loop_store.load_latest_evaluation(loop_id)
    except VulnHunterError as exc:
        _fail(exc)
    typer.echo(f"Loop: {manifest.loop_id}")
    typer.echo(f"Iteration: {evaluation.iteration}")
    typer.echo(f"Verification: {'PASS' if evaluation.passed else 'FAIL'}")
    typer.echo(f"Changed files: {evaluation.changed_files_count}")
    typer.echo(f"Diff SHA-256: {evaluation.diff_sha256}")
    for path in evaluation.changed_files:
        typer.echo(f"- {path}")
    for check in evaluation.checks:
        typer.echo(
            f"{check.verifier.value}: {'PASS' if check.passed else 'FAIL'} "
            f"exit={check.exit_code} output={check.output_sha256[:12]}"
        )
        if show_output and check.output_excerpt:
            typer.echo(check.output_excerpt)
    try:
        security = loop_store.load_latest_security(loop_id)
    except VulnHunterError:
        typer.echo("Security policy: not recorded")
        return
    typer.echo(f"Security policy: {'PASS' if security.passed else 'FAIL'}")
    for finding in security.findings:
        typer.echo(f"- {finding}")


@app.command("escalate")
def escalate(
    loop_id: str,
    actor: Annotated[str, typer.Option("--actor")],
    reason: Annotated[str, typer.Option("--reason")],
    store: StoreOption = Path("artifacts/loops"),
) -> None:
    """Stop a non-terminal loop and require explicit human recovery."""
    try:
        manifest = escalate_loop(
            _store(store),
            loop_id,
            actor_id=actor,
            reason=reason,
        )
    except (VulnHunterError, ValueError) as exc:
        _fail(exc)
    typer.echo(f"State: {manifest.state.value}")


@app.command("events")
def events(
    loop_id: str,
    store: StoreOption = Path("artifacts/loops"),
) -> None:
    """Verify and display the hash-chained audit trail."""
    try:
        _, records = _store(store).verify_integrity(loop_id)
    except VulnHunterError as exc:
        _fail(exc)
    for event in records:
        typer.echo(
            f"{event.sequence:04d}  {event.created_at.isoformat()}  "
            f"{event.actor_id}  {event.event_type}  {event.event_hash[:12]}"
        )


@app.command("recovery-plan")
def show_recovery_plan(
    loop_id: str,
    store: StoreOption = Path("artifacts/loops"),
) -> None:
    """Show a non-destructive stop and recovery plan."""
    try:
        lines = recovery_plan(_store(store), loop_id)
    except VulnHunterError as exc:
        _fail(exc)
    for line in lines:
        typer.echo(line)


@app.command("rollback")
def rollback(
    loop_id: str,
    actor: Annotated[str, typer.Option("--actor")],
    apply: Annotated[
        bool,
        typer.Option("--apply", help="Actually restore the clean loop baseline."),
    ] = False,
    confirm: Annotated[
        str,
        typer.Option("--confirm", help="Must exactly equal the loop ID."),
    ] = "",
    store: StoreOption = Path("artifacts/loops"),
) -> None:
    """Preview or apply a guarded rollback that never rewrites commits."""
    try:
        lines, manifest = rollback_loop(
            _store(store),
            loop_id,
            actor_id=actor,
            confirmation=confirm,
            apply=apply,
        )
    except (VulnHunterError, ValueError) as exc:
        _fail(exc)
    for line in lines:
        typer.echo(line)
    if manifest is not None:
        typer.echo(f"State: {manifest.state.value}")
