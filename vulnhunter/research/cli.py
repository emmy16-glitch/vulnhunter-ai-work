"""CLI for immutable-evaluator transactional research experiments."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from vulnhunter.exceptions import ResearchError
from vulnhunter.research.models import SearchPolicy
from vulnhunter.research.service import (
    abort_experiment,
    approve_search_policy,
    create_experiment,
    decide_experiment,
    evaluate_experiment,
    load_spec,
    mark_candidate_ready,
    prepare_experiment,
    promote_experiment,
    record_baseline,
    run_meta_analysis,
    write_template,
)
from vulnhunter.research.store import ResearchStore

app = typer.Typer(
    help=(
        "Run isolated keep-or-revert experiments with immutable evaluator boundaries, "
        "trusted metrics, and human promotion."
    ),
    no_args_is_help=True,
)

StoreOption = Annotated[
    Path,
    typer.Option(
        "--store",
        help="Local directory for experiment manifests, evidence, and event chains.",
    ),
]


def _store(path: Path) -> ResearchStore:
    return ResearchStore.from_path(path)


def _fail(exc: Exception) -> None:
    typer.secho(f"Research operation failed: {exc}", fg=typer.colors.RED, err=True)
    raise typer.Exit(code=2) from exc


@app.command("template")
def template(destination: Path) -> None:
    """Write a strict one-hypothesis experiment specification template."""
    try:
        path = write_template(destination)
    except ResearchError as exc:
        _fail(exc)
    typer.echo(f"Experiment specification template: {path}")


@app.command("create")
def create(
    specification: Path,
    creator: Annotated[str, typer.Option("--creator")],
    builder: Annotated[str, typer.Option("--builder")],
    store: StoreOption = Path("artifacts/research"),
    repository: Annotated[
        Path,
        typer.Option("--repository", help="Clean Git repository to govern."),
    ] = Path("."),
) -> None:
    """Create an experiment record and protected evaluator snapshot."""
    try:
        manifest = create_experiment(
            _store(store),
            load_spec(specification),
            creator_id=creator,
            builder_id=builder,
            repository=repository,
        )
    except (ResearchError, ValueError) as exc:
        _fail(exc)
    typer.echo(f"Experiment created: {manifest.experiment_id}")
    typer.echo(f"Baseline: {manifest.baseline_commit}")
    typer.echo(f"Policy SHA-256: {manifest.policy_sha256}")
    typer.echo(f"Protected snapshot: {manifest.protected_snapshot_sha256}")


@app.command("prepare")
def prepare(
    experiment_id: str,
    actor: Annotated[str, typer.Option("--actor")],
    store: StoreOption = Path("artifacts/research"),
    worktree_root: Annotated[
        Path | None,
        typer.Option(
            "--worktree-root",
            help="Optional parent directory for isolated Git worktrees.",
        ),
    ] = None,
) -> None:
    """Create an isolated branch/worktree from the exact clean baseline."""
    try:
        manifest = prepare_experiment(
            _store(store),
            experiment_id,
            actor_id=actor,
            worktree_root=worktree_root,
        )
    except (ResearchError, ValueError) as exc:
        _fail(exc)
    typer.echo(f"State: {manifest.state.value}")
    typer.echo(f"Worktree: {manifest.worktree_path}")
    typer.echo(f"Branch: {manifest.branch_name}")


@app.command("record-baseline")
def baseline(
    experiment_id: str,
    evaluator: Annotated[str, typer.Option("--evaluator")],
    report: Annotated[
        Path,
        typer.Option("--report", help="Trusted baseline metric-report JSON."),
    ],
    store: StoreOption = Path("artifacts/research"),
) -> None:
    """Record immutable baseline metrics from an independent evaluator."""
    try:
        manifest = record_baseline(
            _store(store),
            experiment_id,
            evaluator_id=evaluator,
            report_path=report,
        )
    except (ResearchError, ValueError) as exc:
        _fail(exc)
    typer.echo(f"Baseline metrics recorded. State: {manifest.state.value}")


@app.command("candidate")
def candidate(
    experiment_id: str,
    builder: Annotated[str, typer.Option("--builder")],
    tokens_used: Annotated[int, typer.Option("--tokens-used", min=0)] = 0,
    cost_usd: Annotated[float, typer.Option("--cost-usd", min=0)] = 0.0,
    store: StoreOption = Path("artifacts/research"),
) -> None:
    """Bind exactly one clean candidate commit and archive its patch."""
    try:
        manifest = mark_candidate_ready(
            _store(store),
            experiment_id,
            builder_id=builder,
            tokens_used=tokens_used,
            cost_usd=cost_usd,
        )
    except (ResearchError, ValueError) as exc:
        _fail(exc)
    typer.echo(f"Candidate commit: {manifest.candidate_commit}")
    typer.echo(f"Patch SHA-256: {manifest.patch_sha256}")
    typer.echo(f"State: {manifest.state.value}")


@app.command("evaluate")
def evaluate(
    experiment_id: str,
    evaluator: Annotated[str, typer.Option("--evaluator")],
    report: Annotated[
        Path,
        typer.Option("--report", help="Trusted candidate metric-report JSON."),
    ],
    store: StoreOption = Path("artifacts/research"),
) -> None:
    """Run fixed verifiers, protected-file checks, and metric gates."""
    try:
        evidence, manifest = evaluate_experiment(
            _store(store),
            experiment_id,
            evaluator_id=evaluator,
            candidate_report_path=report,
        )
    except (ResearchError, ValueError) as exc:
        _fail(exc)
    typer.echo(f"Evaluation: {'PASS' if evidence.passed else 'FAIL'}")
    typer.echo(f"Objective delta: {evidence.objective_delta}")
    typer.echo(f"Diff SHA-256: {evidence.diff_sha256}")
    for check in evidence.checks:
        typer.echo(
            f"{check.verifier.value}: {'PASS' if check.passed else 'FAIL'} "
            f"({check.duration_seconds:.3f}s)"
        )
    for item in (
        *evidence.boundary_violations,
        *evidence.protected_violations,
        *evidence.regression_failures,
        *evidence.safety_failures,
    ):
        typer.secho(f"- {item}", fg=typer.colors.YELLOW)
    typer.echo(f"State: {manifest.state.value}")
    if not evidence.passed:
        raise typer.Exit(code=1)


@app.command("decide")
def decide(
    experiment_id: str,
    decider: Annotated[str, typer.Option("--decider")],
    keep_rejected_worktree: Annotated[
        bool,
        typer.Option(
            "--keep-rejected-worktree",
            help="Debug only: preserve a rejected worktree instead of reverting it.",
        ),
    ] = False,
    store: StoreOption = Path("artifacts/research"),
) -> None:
    """Apply the deterministic keep-or-revert gate."""
    try:
        decision, manifest, cleaned = decide_experiment(
            _store(store),
            experiment_id,
            decider_id=decider,
            cleanup_rejected=not keep_rejected_worktree,
        )
    except (ResearchError, ValueError) as exc:
        _fail(exc)
    typer.echo(f"Decision: {decision.outcome.value}")
    typer.echo(f"Objective delta: {decision.objective_delta}")
    typer.echo(f"State: {manifest.state.value}")
    typer.echo(f"Rejected worktree removed: {'yes' if cleaned else 'no'}")
    for reason in decision.reasons:
        typer.echo(f"- {reason}")


@app.command("promote")
def promote(
    experiment_id: str,
    human: Annotated[str, typer.Option("--human")],
    confirm: Annotated[
        str,
        typer.Option("--confirm", help="Must exactly equal the experiment ID."),
    ],
    store: StoreOption = Path("artifacts/research"),
) -> None:
    """Human-confirm and cherry-pick one accepted candidate into the primary tree."""
    try:
        manifest = promote_experiment(
            _store(store),
            experiment_id,
            human_id=human,
            confirm=confirm,
        )
    except (ResearchError, ValueError) as exc:
        _fail(exc)
    typer.echo(f"Experiment promoted. State: {manifest.state.value}")


@app.command("abort")
def abort(
    experiment_id: str,
    actor: Annotated[str, typer.Option("--actor")],
    reason: Annotated[str, typer.Option("--reason")],
    confirm: Annotated[
        str,
        typer.Option("--confirm", help="Must exactly equal the experiment ID."),
    ],
    store: StoreOption = Path("artifacts/research"),
) -> None:
    """Remove only the isolated worktree and preserve experiment evidence."""
    try:
        manifest = abort_experiment(
            _store(store),
            experiment_id,
            actor_id=actor,
            reason=reason,
            confirm=confirm,
        )
    except (ResearchError, ValueError) as exc:
        _fail(exc)
    typer.echo(f"Experiment aborted. State: {manifest.state.value}")


@app.command("status")
def status(
    experiment_id: str,
    store: StoreOption = Path("artifacts/research"),
) -> None:
    """Display state, provenance, roles, budgets, and integrity status."""
    try:
        manifest, events = _store(store).verify_integrity(experiment_id)
    except ResearchError as exc:
        _fail(exc)
    typer.echo(f"Experiment ID: {manifest.experiment_id}")
    typer.echo(f"State: {manifest.state.value}")
    typer.echo(f"Hypothesis: {manifest.spec.hypothesis}")
    typer.echo(f"Strategy: {manifest.spec.strategy_family}")
    typer.echo(f"Baseline: {manifest.baseline_commit}")
    typer.echo(f"Candidate: {manifest.candidate_commit or '-'}")
    typer.echo(f"Builder: {manifest.builder_id}")
    typer.echo(f"Evaluator: {manifest.latest_evaluator_id or '-'}")
    typer.echo(f"Decider: {manifest.latest_decider_id or '-'}")
    typer.echo(f"Human promoter: {manifest.human_promoter_id or '-'}")
    typer.echo(f"Tokens: {manifest.tokens_used}")
    typer.echo(f"Cost: ${manifest.cost_usd:.4f}")
    typer.echo(f"Events: {len(events)}")


@app.command("list")
def list_experiments(
    store: StoreOption = Path("artifacts/research"),
) -> None:
    """List newest experiments and deterministic decisions."""
    try:
        manifests = _store(store).list_manifests()
    except ResearchError as exc:
        _fail(exc)
    if not manifests:
        typer.echo("No research experiments found.")
        return
    for item in manifests:
        typer.echo(
            f"{item.experiment_id}  {item.state.value}  "
            f"strategy={item.spec.strategy_family}  {item.spec.title}"
        )


@app.command("integrity")
def integrity(
    experiment_id: str,
    store: StoreOption = Path("artifacts/research"),
) -> None:
    """Verify manifest, policy, protected snapshot, events, and evidence hashes."""
    try:
        _, events = _store(store).verify_integrity(experiment_id)
    except ResearchError as exc:
        _fail(exc)
    typer.echo(f"Integrity verification passed. Events: {len(events)}")


@app.command("meta-analyze")
def meta_analyze(
    output: Annotated[
        Path | None,
        typer.Option("--output", help="Optional path for the proposed policy JSON."),
    ] = None,
    store: StoreOption = Path("artifacts/research"),
) -> None:
    """Analyze search stagnation and propose non-executable outer-loop guidance."""
    try:
        analysis, path = run_meta_analysis(_store(store))
    except ResearchError as exc:
        _fail(exc)
    typer.echo(f"Stagnation detected: {'yes' if analysis.stagnation_detected else 'no'}")
    typer.echo(f"Rejection rate: {analysis.rejection_rate:.3f}")
    for item in analysis.recommendations:
        typer.echo(f"- {item}")
    typer.echo(f"Analysis evidence: {path}")
    typer.echo("Human approval required: yes")
    if output is not None:
        destination = output.expanduser().resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            analysis.proposed_policy.model_dump_json(indent=2) + "\n",
            encoding="utf-8",
        )
        typer.echo(f"Proposed policy: {destination}")


@app.command("approve-policy")
def approve_policy(
    policy_file: Path,
    human: Annotated[str, typer.Option("--human")],
    store: StoreOption = Path("artifacts/research"),
) -> None:
    """Approve outer-loop guidance without changing evaluator boundaries."""
    try:
        policy = SearchPolicy.model_validate_json(policy_file.read_text(encoding="utf-8"))
        approved = approve_search_policy(_store(store), policy, human_id=human)
    except (OSError, ValueError, ResearchError) as exc:
        _fail(exc)
    typer.echo(
        f"Search policy generation {approved.generation} approved by {approved.approved_by}."
    )
