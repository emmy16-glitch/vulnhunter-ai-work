"""End-to-end tests for transactional keep-or-revert experiments."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from vulnhunter.orchestration import VerifierKind
from vulnhunter.research.models import (
    DecisionOutcome,
    ExperimentSpec,
    ExperimentState,
    ObjectiveDirection,
    ObjectiveSpec,
    RegressionGate,
)
from vulnhunter.research.service import (
    create_experiment,
    decide_experiment,
    evaluate_experiment,
    mark_candidate_ready,
    prepare_experiment,
    promote_experiment,
    record_baseline,
)
from vulnhunter.research.store import ResearchStore


def _git(repository: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _repository(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init")
    _git(root, "config", "user.name", "Test User")
    _git(root, "config", "user.email", "test@example.invalid")
    (root / "candidate.py").write_text("VALUE = 1\n")
    (root / "tests").mkdir()
    (root / "tests/test_guard.py").write_text("def test_guard():\n    assert True\n")
    _git(root, "add", ".")
    _git(root, "commit", "-m", "baseline")
    return root


def _spec() -> ExperimentSpec:
    return ExperimentSpec(
        title="Improve candidate metric",
        hypothesis=(
            "Changing the bounded candidate value will improve the objective without "
            "regressing latency or evaluator safety checks."
        ),
        strategy_family="feature_engineering",
        editable_paths=("candidate.py",),
        objective=ObjectiveSpec(
            metric="score",
            direction=ObjectiveDirection.MAXIMIZE,
            minimum_delta=0.1,
        ),
        regression_gates=(
            RegressionGate(
                metric="latency",
                direction=ObjectiveDirection.MINIMIZE,
                maximum_degradation=1.0,
            ),
        ),
        required_safety_checks=("redaction_preserved",),
        verifiers=(VerifierKind.GIT_DIFF_CHECK,),
    )


def _report(path: Path, score: float, latency: float, safety: bool = True) -> Path:
    path.write_text(
        json.dumps(
            {
                "metrics": {"score": score, "latency": latency},
                "safety_checks": {"redaction_preserved": safety},
            }
        )
    )
    return path


def _prepared(tmp_path: Path):
    root = _repository(tmp_path)
    store = ResearchStore(tmp_path / "store")
    manifest = create_experiment(
        store,
        _spec(),
        creator_id="creator.one",
        builder_id="builder.one",
        repository=root,
    )
    manifest = prepare_experiment(
        store,
        manifest.experiment_id,
        actor_id="creator.one",
        worktree_root=tmp_path / "worktrees",
    )
    record_baseline(
        store,
        manifest.experiment_id,
        evaluator_id="evaluator.one",
        report_path=_report(tmp_path / "baseline.json", 1.0, 10.0),
    )
    return root, store, store.load(manifest.experiment_id)


def test_accepted_candidate_is_promoted_only_after_human_confirmation(
    tmp_path: Path,
) -> None:
    root, store, manifest = _prepared(tmp_path)
    worktree = Path(manifest.worktree_path or "")
    (worktree / "candidate.py").write_text("VALUE = 2\n")
    _git(worktree, "add", "candidate.py")
    _git(worktree, "commit", "-m", "candidate")
    mark_candidate_ready(
        store,
        manifest.experiment_id,
        builder_id="builder.one",
    )
    evaluation, _ = evaluate_experiment(
        store,
        manifest.experiment_id,
        evaluator_id="evaluator.one",
        candidate_report_path=_report(tmp_path / "candidate.json", 1.2, 10.5),
    )
    decision, decided, cleaned = decide_experiment(
        store,
        manifest.experiment_id,
        decider_id="decider.one",
    )

    assert evaluation.passed is True
    assert decision.outcome is DecisionOutcome.ACCEPT
    assert decided.state is ExperimentState.ACCEPTED
    assert cleaned is False

    promoted = promote_experiment(
        store,
        manifest.experiment_id,
        human_id="human.one",
        confirm=manifest.experiment_id,
    )

    assert promoted.state is ExperimentState.PROMOTED
    assert (root / "candidate.py").read_text() == "VALUE = 2\n"
    assert not worktree.exists()


def test_regressing_candidate_is_rejected_and_worktree_removed(tmp_path: Path) -> None:
    _, store, manifest = _prepared(tmp_path)
    worktree = Path(manifest.worktree_path or "")
    (worktree / "candidate.py").write_text("VALUE = 9\n")
    _git(worktree, "add", "candidate.py")
    _git(worktree, "commit", "-m", "candidate")
    mark_candidate_ready(
        store,
        manifest.experiment_id,
        builder_id="builder.one",
    )
    evaluation, _ = evaluate_experiment(
        store,
        manifest.experiment_id,
        evaluator_id="evaluator.one",
        candidate_report_path=_report(tmp_path / "candidate.json", 1.2, 20.0),
    )
    decision, decided, cleaned = decide_experiment(
        store,
        manifest.experiment_id,
        decider_id="decider.one",
    )

    assert evaluation.passed is False
    assert decision.outcome is DecisionOutcome.REJECT
    assert decided.state is ExperimentState.REJECTED
    assert cleaned is True
    assert not worktree.exists()
    assert (
        store.experiment_directory(manifest.experiment_id) / "evidence/candidate.patch"
    ).is_file()


def test_candidate_cannot_change_protected_tests(tmp_path: Path) -> None:
    _, store, manifest = _prepared(tmp_path)
    worktree = Path(manifest.worktree_path or "")
    (worktree / "candidate.py").write_text("VALUE = 2\n")
    (worktree / "tests/test_guard.py").write_text("def test_guard():\n    assert False\n")
    _git(worktree, "add", ".")
    _git(worktree, "commit", "-m", "cheat evaluator")
    mark_candidate_ready(
        store,
        manifest.experiment_id,
        builder_id="builder.one",
    )
    evaluation, _ = evaluate_experiment(
        store,
        manifest.experiment_id,
        evaluator_id="evaluator.one",
        candidate_report_path=_report(tmp_path / "candidate.json", 9.0, 1.0),
    )

    assert evaluation.passed is False
    assert any("tests/test_guard.py" in item for item in evaluation.boundary_violations)
    assert any("tests/test_guard.py" in item for item in evaluation.protected_violations)
