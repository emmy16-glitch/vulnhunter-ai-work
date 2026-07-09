"""Lifecycle services for isolated keep-or-revert research experiments."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from vulnhunter.exceptions import (
    ResearchEvaluationError,
    ResearchGitError,
    ResearchStateError,
)
from vulnhunter.research.boundaries import (
    build_protected_snapshot,
    default_evaluator_policy,
    policy_sha256,
    validate_editable_patterns,
)
from vulnhunter.research.evaluator import (
    decide_from_evaluation,
    evaluate_candidate,
    evaluation_sha256,
    record_metric_report,
)
from vulnhunter.research.gitops import (
    candidate_commit,
    current_commit,
    current_tree,
    diff_bytes,
    prepare_worktree,
    promote_candidate,
    remove_worktree,
    repository_root,
    working_tree_is_clean,
)
from vulnhunter.research.meta import analyze_search, default_search_policy
from vulnhunter.research.models import (
    DecisionOutcome,
    ExperimentManifest,
    ExperimentSpec,
    ExperimentState,
    SearchPolicy,
    normalize_actor_id,
)
from vulnhunter.research.store import ResearchStore


def load_spec(path: Path) -> ExperimentSpec:
    """Load one strict JSON experiment specification."""
    try:
        return ExperimentSpec.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValidationError) as exc:
        raise ResearchEvaluationError("Experiment specification is unreadable or invalid.") from exc


def write_template(path: Path) -> Path:
    """Write a complete bounded experiment template."""
    destination = path.expanduser().resolve()
    if destination.exists():
        raise ResearchStateError(f"Refusing to overwrite existing file: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    template = {
        "title": "Improve reviewed-observation ranking without weakening safety",
        "hypothesis": (
            "Adding one bounded privacy-safe feature family will improve holdout F1 "
            "without reducing recall, authorization, scope, or redaction guarantees."
        ),
        "strategy_family": "feature_engineering",
        "editable_paths": [
            "vulnhunter/ml/features.py",
            "vulnhunter/ml/estimators.py",
        ],
        "objective": {
            "metric": "holdout_f1",
            "direction": "maximize",
            "minimum_delta": 0.01,
        },
        "regression_gates": [
            {
                "metric": "holdout_recall",
                "direction": "maximize",
                "maximum_degradation": 0.0,
            },
            {
                "metric": "prediction_latency_ms",
                "direction": "minimize",
                "maximum_degradation": 5.0,
            },
        ],
        "required_safety_checks": [
            "laboratory_scope_enforced",
            "authorization_required",
            "redaction_preserved",
            "human_labels_authoritative",
            "scan_group_isolation_preserved",
            "evaluator_resources_unchanged",
        ],
        "verifiers": [
            "ruff_check",
            "compileall",
            "pytest",
            "ruff_format_check",
            "git_diff_check",
        ],
        "limits": {
            "maximum_changed_files": 20,
            "maximum_diff_bytes": 500000,
            "maximum_elapsed_seconds": 7200,
            "per_check_timeout_seconds": 300,
            "maximum_tokens": 200000,
            "maximum_cost_usd": 25.0,
        },
    }
    destination.write_text(json.dumps(template, indent=2) + "\n", encoding="utf-8")
    return destination


def create_experiment(
    store: ResearchStore,
    spec: ExperimentSpec,
    *,
    creator_id: str,
    builder_id: str,
    repository: Path,
) -> ExperimentManifest:
    """Create a trusted experiment record from a clean baseline."""
    root = repository_root(repository)
    if not working_tree_is_clean(root):
        raise ResearchGitError("Create experiments only from a clean Git working tree.")

    creator = normalize_actor_id(creator_id)
    builder = normalize_actor_id(builder_id)
    if creator == builder:
        raise ResearchStateError("The experiment creator and builder must be distinct roles.")

    policy = default_evaluator_policy()
    validate_editable_patterns(spec, policy)
    baseline_commit = current_commit(root)
    now = datetime.now(UTC)
    experiment_id = f"exp-{now:%Y%m%dT%H%M%SZ}-{uuid.uuid4().hex[:8]}"
    snapshot = build_protected_snapshot(
        root,
        policy,
        repository_commit=baseline_commit,
    )
    manifest = ExperimentManifest(
        experiment_id=experiment_id,
        spec=spec,
        creator_id=creator,
        builder_id=builder,
        repository_root=str(root),
        store_root=str(store.root),
        baseline_commit=baseline_commit,
        baseline_tree=current_tree(root),
        policy_sha256=policy_sha256(policy),
        protected_snapshot_sha256=snapshot.snapshot_sha256,
        created_at=now,
        updated_at=now,
    )
    store.create(manifest, policy=policy, snapshot=snapshot)
    store.append_event(
        experiment_id,
        "experiment_created",
        creator,
        {
            "title": spec.title,
            "strategy_family": spec.strategy_family,
            "baseline_commit": baseline_commit,
            "policy_sha256": manifest.policy_sha256,
            "protected_snapshot_sha256": manifest.protected_snapshot_sha256,
            "editable_paths": list(spec.editable_paths),
            "objective": spec.objective.model_dump(mode="json"),
            "regression_gates": [item.model_dump(mode="json") for item in spec.regression_gates],
        },
    )
    return manifest


def prepare_experiment(
    store: ResearchStore,
    experiment_id: str,
    *,
    actor_id: str,
    worktree_root: Path | None = None,
) -> ExperimentManifest:
    """Create a clean isolated branch/worktree for the builder."""
    manifest = store.load(experiment_id)
    _require_state(manifest, {ExperimentState.DRAFT}, "preparation")
    actor = normalize_actor_id(actor_id)
    if actor not in {manifest.creator_id, manifest.builder_id}:
        raise ResearchStateError("Only the experiment creator or builder may prepare it.")

    repository = Path(manifest.repository_root)
    root = (
        worktree_root.expanduser().resolve()
        if worktree_root is not None
        else repository.parent / ".vulnhunter-worktrees"
    )
    path, branch = prepare_worktree(
        repository,
        experiment_id=experiment_id,
        baseline_commit=manifest.baseline_commit,
        worktree_root=root,
    )
    updated = manifest.model_copy(
        update={
            "updated_at": datetime.now(UTC),
            "state": ExperimentState.PREPARED,
            "worktree_path": str(path),
            "branch_name": branch,
        }
    )
    store.save(updated)
    store.append_event(
        experiment_id,
        "worktree_prepared",
        actor,
        {
            "worktree_path": str(path),
            "branch_name": branch,
            "baseline_commit": manifest.baseline_commit,
        },
    )
    return updated


def record_baseline(
    store: ResearchStore,
    experiment_id: str,
    *,
    evaluator_id: str,
    report_path: Path,
) -> ExperimentManifest:
    """Record immutable baseline metrics from an independent evaluator."""
    manifest = store.load(experiment_id)
    _require_state(
        manifest,
        {ExperimentState.PREPARED},
        "baseline recording",
    )
    evaluator = normalize_actor_id(evaluator_id)
    if evaluator == manifest.builder_id:
        raise ResearchStateError("The builder cannot record trusted baseline metrics.")
    record = record_metric_report(report_path, evaluator_id=evaluator)
    _validate_required_metrics(manifest, record.report.metrics)
    path = store.save_baseline_report(experiment_id, record)
    updated = manifest.model_copy(
        update={
            "updated_at": datetime.now(UTC),
            "state": ExperimentState.BASELINE_RECORDED,
            "latest_evaluator_id": evaluator,
        }
    )
    store.save(updated)
    store.append_event(
        experiment_id,
        "baseline_metrics_recorded",
        evaluator,
        {
            "source_sha256": record.source_sha256,
            "metrics": record.report.metrics,
            "evidence_file": store.evidence_relative_path(experiment_id, path),
            "evidence_sha256": store.sha256_file(path),
        },
    )
    return updated


def mark_candidate_ready(
    store: ResearchStore,
    experiment_id: str,
    *,
    builder_id: str,
    tokens_used: int = 0,
    cost_usd: float = 0.0,
) -> ExperimentManifest:
    """Bind one clean candidate commit and preserve its patch evidence."""
    manifest = store.load(experiment_id)
    _require_state(
        manifest,
        {ExperimentState.BASELINE_RECORDED},
        "candidate registration",
    )
    builder = normalize_actor_id(builder_id)
    if builder != manifest.builder_id:
        raise ResearchStateError("Only the assigned builder may register the candidate.")
    _enforce_resources(manifest, tokens_used=tokens_used, cost_usd=cost_usd)
    if manifest.worktree_path is None:
        raise ResearchStateError("The experiment worktree is missing.")

    commit, tree = candidate_commit(
        Path(manifest.worktree_path),
        baseline_commit=manifest.baseline_commit,
    )
    patch = diff_bytes(
        Path(manifest.worktree_path),
        baseline_commit=manifest.baseline_commit,
        candidate=commit,
    )
    patch_path = store.save_patch(experiment_id, patch)
    patch_hash = hashlib.sha256(patch).hexdigest()
    updated = manifest.model_copy(
        update={
            "updated_at": datetime.now(UTC),
            "state": ExperimentState.CANDIDATE_READY,
            "candidate_commit": commit,
            "candidate_tree": tree,
            "patch_sha256": patch_hash,
            "tokens_used": manifest.tokens_used + tokens_used,
            "cost_usd": manifest.cost_usd + cost_usd,
        }
    )
    store.save(updated)
    store.append_event(
        experiment_id,
        "candidate_registered",
        builder,
        {
            "candidate_commit": commit,
            "candidate_tree": tree,
            "patch_sha256": patch_hash,
            "tokens_used": tokens_used,
            "cost_usd": cost_usd,
            "evidence_file": store.evidence_relative_path(experiment_id, patch_path),
            "evidence_sha256": store.sha256_file(patch_path),
        },
    )
    return updated


def evaluate_experiment(
    store: ResearchStore,
    experiment_id: str,
    *,
    evaluator_id: str,
    candidate_report_path: Path,
):
    """Run immutable checks and record the complete evaluation proof bundle."""
    manifest = store.load(experiment_id)
    _require_state(manifest, {ExperimentState.CANDIDATE_READY}, "evaluation")
    evaluator = normalize_actor_id(evaluator_id)
    if evaluator == manifest.builder_id:
        raise ResearchStateError("The evaluator must be independent from the builder.")

    candidate = record_metric_report(candidate_report_path, evaluator_id=evaluator)
    _validate_required_metrics(manifest, candidate.report.metrics)
    candidate_path = store.save_candidate_report(experiment_id, candidate)
    baseline = store.load_baseline_report(experiment_id)
    policy = store.load_policy(experiment_id)
    snapshot = store.load_snapshot(experiment_id)
    evaluation = evaluate_candidate(
        manifest,
        policy=policy,
        snapshot=snapshot,
        baseline=baseline,
        candidate=candidate,
        evaluator_id=evaluator,
    )
    evaluation_path = store.save_evaluation(experiment_id, evaluation)
    updated = manifest.model_copy(
        update={
            "updated_at": datetime.now(UTC),
            "state": ExperimentState.EVALUATED,
            "latest_evaluator_id": evaluator,
        }
    )
    store.save(updated)
    store.append_event(
        experiment_id,
        "candidate_evaluated",
        evaluator,
        {
            "passed": evaluation.passed,
            "objective_delta": evaluation.objective_delta,
            "boundary_violations": list(evaluation.boundary_violations),
            "protected_violations": list(evaluation.protected_violations),
            "regression_failures": list(evaluation.regression_failures),
            "safety_failures": list(evaluation.safety_failures),
            "diff_sha256": evaluation.diff_sha256,
            "candidate_report_file": store.evidence_relative_path(experiment_id, candidate_path),
            "candidate_report_sha256": store.sha256_file(candidate_path),
            "evidence_file": store.evidence_relative_path(experiment_id, evaluation_path),
            "evidence_sha256": store.sha256_file(evaluation_path),
        },
    )
    return evaluation, updated


def decide_experiment(
    store: ResearchStore,
    experiment_id: str,
    *,
    decider_id: str,
    cleanup_rejected: bool = True,
):
    """Keep an improving candidate or transactionally remove rejected work."""
    manifest = store.load(experiment_id)
    _require_state(manifest, {ExperimentState.EVALUATED}, "decision")
    decider = normalize_actor_id(decider_id)
    evaluation = store.load_evaluation(experiment_id)
    baseline = store.load_baseline_report(experiment_id)
    candidate = store.load_candidate_report(experiment_id)
    evaluation_path = store.experiment_directory(experiment_id) / "evidence" / "evaluation.json"
    decision = decide_from_evaluation(
        manifest,
        evaluation,
        baseline=baseline,
        candidate=candidate,
        decider_id=decider,
        evaluation_sha256=evaluation_sha256(evaluation),
    )
    decision_path = store.save_decision(experiment_id, decision)
    state = {
        DecisionOutcome.ACCEPT: ExperimentState.ACCEPTED,
        DecisionOutcome.REJECT: ExperimentState.REJECTED,
        DecisionOutcome.INCONCLUSIVE: ExperimentState.INCONCLUSIVE,
    }[decision.outcome]
    updated = manifest.model_copy(
        update={
            "updated_at": datetime.now(UTC),
            "state": state,
            "decision": decision.outcome,
            "latest_decider_id": decider,
        }
    )
    store.save(updated)
    store.append_event(
        experiment_id,
        "experiment_decided",
        decider,
        {
            "outcome": decision.outcome.value,
            "reasons": list(decision.reasons),
            "objective_delta": decision.objective_delta,
            "diff_sha256": decision.diff_sha256,
            "evaluation_sha256": store.sha256_file(evaluation_path),
            "evidence_file": store.evidence_relative_path(experiment_id, decision_path),
            "evidence_sha256": store.sha256_file(decision_path),
        },
    )

    cleaned = False
    if decision.outcome is not DecisionOutcome.ACCEPT and cleanup_rejected:
        _cleanup_worktree(updated, force=True)
        cleaned = True
        updated = updated.model_copy(
            update={
                "updated_at": datetime.now(UTC),
                "worktree_path": None,
                "branch_name": None,
            }
        )
        store.save(updated)
        store.append_event(
            experiment_id,
            "rejected_candidate_reverted",
            decider,
            {
                "worktree_removed": True,
                "candidate_patch_preserved": True,
            },
        )
    return decision, updated, cleaned


def promote_experiment(
    store: ResearchStore,
    experiment_id: str,
    *,
    human_id: str,
    confirm: str,
) -> ExperimentManifest:
    """Promote one accepted candidate after exact human confirmation."""
    manifest = store.load(experiment_id)
    _require_state(manifest, {ExperimentState.ACCEPTED}, "promotion")
    human = normalize_actor_id(human_id)
    if confirm != experiment_id:
        raise ResearchStateError("Promotion confirmation must exactly equal the experiment ID.")
    if human in {
        manifest.builder_id,
        manifest.latest_evaluator_id,
        manifest.latest_decider_id,
    }:
        raise ResearchStateError(
            "The human promoter must be independent from builder, evaluator, and decider."
        )
    if manifest.candidate_commit is None:
        raise ResearchStateError("The accepted experiment has no candidate commit.")

    promoted_commit = promote_candidate(
        Path(manifest.repository_root),
        baseline_commit=manifest.baseline_commit,
        candidate=manifest.candidate_commit,
    )
    _cleanup_worktree(manifest, force=True)
    updated = manifest.model_copy(
        update={
            "updated_at": datetime.now(UTC),
            "state": ExperimentState.PROMOTED,
            "human_promoter_id": human,
            "worktree_path": None,
            "branch_name": None,
        }
    )
    store.save(updated)
    store.append_event(
        experiment_id,
        "candidate_promoted",
        human,
        {
            "candidate_commit": manifest.candidate_commit,
            "promoted_commit": promoted_commit,
            "primary_worktree_was_clean": True,
        },
    )
    return updated


def abort_experiment(
    store: ResearchStore,
    experiment_id: str,
    *,
    actor_id: str,
    reason: str,
    confirm: str,
) -> ExperimentManifest:
    """Stop an experiment and remove only its isolated worktree/branch."""
    manifest = store.load(experiment_id)
    if manifest.state in {ExperimentState.PROMOTED, ExperimentState.ABORTED}:
        raise ResearchStateError(f"Cannot abort an experiment in state {manifest.state.value}.")
    if confirm != experiment_id:
        raise ResearchStateError("Abort confirmation must exactly equal the experiment ID.")
    actor = normalize_actor_id(actor_id)
    _cleanup_worktree(manifest, force=True)
    updated = manifest.model_copy(
        update={
            "updated_at": datetime.now(UTC),
            "state": ExperimentState.ABORTED,
            "worktree_path": None,
            "branch_name": None,
        }
    )
    store.save(updated)
    store.append_event(
        experiment_id,
        "experiment_aborted",
        actor,
        {"reason": reason, "isolated_worktree_removed": True},
    )
    return updated


def run_meta_analysis(store: ResearchStore):
    """Analyze search traces and propose a non-executable policy revision."""
    manifests = store.list_manifests()
    policy = store.load_search_policy() or default_search_policy()
    analysis = analyze_search(manifests, current_policy=policy)
    path = store.save_meta_analysis(analysis)
    return analysis, path


def approve_search_policy(
    store: ResearchStore,
    policy: SearchPolicy,
    *,
    human_id: str,
) -> SearchPolicy:
    """Record explicit human approval for outer-loop guidance."""
    human = normalize_actor_id(human_id)
    current = store.load_search_policy()
    if current is not None and policy.generation <= current.generation:
        raise ResearchStateError(
            "A search-policy generation must advance beyond the currently approved policy."
        )
    approved = policy.model_copy(update={"approved_by": human, "approved_at": datetime.now(UTC)})
    store.save_search_policy(approved)
    return approved


def _cleanup_worktree(manifest: ExperimentManifest, *, force: bool) -> None:
    if manifest.worktree_path is None:
        return
    path = Path(manifest.worktree_path)
    if not path.exists() and not manifest.branch_name:
        return
    remove_worktree(
        Path(manifest.repository_root),
        path,
        manifest.branch_name,
        force=force,
    )
    if path.parent.name == ".vulnhunter-worktrees" and path.parent.exists():
        try:
            path.parent.rmdir()
        except OSError:
            pass


def _validate_required_metrics(
    manifest: ExperimentManifest,
    metrics: dict[str, float],
) -> None:
    required = {
        manifest.spec.objective.metric,
        *(gate.metric for gate in manifest.spec.regression_gates),
    }
    missing = sorted(required - set(metrics))
    if missing:
        raise ResearchEvaluationError(
            "Metric report is missing required metrics: " + ", ".join(missing)
        )


def _enforce_resources(
    manifest: ExperimentManifest,
    *,
    tokens_used: int,
    cost_usd: float,
) -> None:
    if tokens_used < 0 or cost_usd < 0:
        raise ResearchStateError("Recorded token and cost usage cannot be negative.")
    limits = manifest.spec.limits
    total_tokens = manifest.tokens_used + tokens_used
    total_cost = manifest.cost_usd + cost_usd
    if limits.maximum_tokens is not None and total_tokens > limits.maximum_tokens:
        raise ResearchStateError("Experiment token budget would be exceeded.")
    if limits.maximum_cost_usd is not None and total_cost > limits.maximum_cost_usd:
        raise ResearchStateError("Experiment cost budget would be exceeded.")
    elapsed = (datetime.now(UTC) - manifest.created_at).total_seconds()
    if elapsed > limits.maximum_elapsed_seconds:
        raise ResearchStateError("Experiment elapsed-time ceiling has been exceeded.")


def _require_state(
    manifest: ExperimentManifest,
    allowed: set[ExperimentState],
    operation: str,
) -> None:
    if manifest.state not in allowed:
        names = ", ".join(sorted(item.value for item in allowed))
        raise ResearchStateError(
            f"Experiment {operation} requires state {names}; current state is "
            f"{manifest.state.value}."
        )
