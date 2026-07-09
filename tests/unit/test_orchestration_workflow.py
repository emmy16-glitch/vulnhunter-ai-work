"""End-to-end local tests for bounded orchestration controls."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from vulnhunter.exceptions import LoopBudgetError, LoopPolicyError
from vulnhunter.orchestration.models import (
    HumanDecision,
    LoopSpec,
    LoopState,
    ResourceBudget,
    ReviewDecision,
    StopControls,
    VerifierKind,
)
from vulnhunter.orchestration.service import (
    create_loop,
    escalate_loop,
    evaluate_loop,
    record_human_approval,
    record_learning,
    rollback_loop,
    submit_independent_review,
    verify_security_policy,
)
from vulnhunter.orchestration.store import LoopStore


def git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def make_repository(tmp_path: Path) -> Path:
    root = tmp_path / "repository"
    root.mkdir()
    (root / "src").mkdir()
    (root / "docs").mkdir()
    (root / "src" / "feature.py").write_text("VALUE = 1\n", encoding="utf-8")
    (root / "docs" / "change.md").write_text("# Baseline\n", encoding="utf-8")
    git(root, "init")
    git(root, "config", "user.email", "test@example.invalid")
    git(root, "config", "user.name", "VulnHunter Tests")
    git(root, "add", ".")
    git(root, "commit", "-m", "Initial baseline")
    return root


def make_spec(
    *,
    controls: StopControls | None = None,
    budget: ResourceBudget | None = None,
) -> LoopSpec:
    return LoopSpec(
        title="Implement bounded feature",
        objective=(
            "Implement a bounded local feature and prove completion through independent gates."
        ),
        required_context=("AGENTS.md", "src/feature.py"),
        allowed_actions=(
            "edit_allowed_files",
            "run_deterministic_verifiers",
            "record_redacted_evidence",
            "update_documentation",
        ),
        allowed_paths=("src/**", "docs/**"),
        verifiers=(VerifierKind.GIT_DIFF_CHECK,),
        required_evidence=("Clean diff", "Security policy", "Independent review"),
        recovery_instructions=("Stop and inspect the latest evidence.",),
        documentation_paths=("docs/**",),
        stop_controls=controls or StopControls(),
        resource_budget=budget or ResourceBudget(),
    )


def create_test_loop(tmp_path: Path, spec: LoopSpec | None = None):
    root = make_repository(tmp_path)
    store = LoopStore.from_path(tmp_path / "loop-store")
    manifest = create_loop(
        store,
        spec or make_spec(),
        creator_id="human.owner",
        builder_id="builder.agent",
        repository=root,
    )
    return root, store, manifest


def test_complete_proof_review_approval_and_learning_flow(tmp_path) -> None:
    root, store, manifest = create_test_loop(tmp_path)
    (root / "src" / "feature.py").write_text("VALUE = 2\n", encoding="utf-8")
    (root / "docs" / "change.md").write_text(
        "# Change\n\nUpdated feature contract.\n",
        encoding="utf-8",
    )

    evaluation, after_evaluation, reasons = evaluate_loop(
        store,
        manifest.loop_id,
        runner_id="test.runner",
        tokens_used=1_000,
        cost_usd=0.25,
    )
    assert evaluation.passed is True
    assert reasons == ()
    assert after_evaluation.state == LoopState.AWAITING_SECURITY

    security, after_security = verify_security_policy(
        store,
        manifest.loop_id,
        verifier_id="security.verifier",
    )
    assert security.passed is True
    assert after_security.state == LoopState.AWAITING_REVIEW

    _, after_review = submit_independent_review(
        store,
        manifest.loop_id,
        reviewer_id="independent.reviewer",
        decision=ReviewDecision.APPROVE,
        summary="The bounded diff matches the objective and the evidence is complete.",
        limitations=("This verifies local repository behaviour only.",),
    )
    assert after_review.state == LoopState.AWAITING_HUMAN

    _, after_approval = record_human_approval(
        store,
        manifest.loop_id,
        human_id="human.approver",
        decision=HumanDecision.APPROVE,
        note="Approved after reviewing the diff, evidence, and recorded limitation.",
    )
    assert after_approval.state == LoopState.AWAITING_DOCUMENTATION

    _, completed, learning_path = record_learning(
        store,
        manifest.loop_id,
        actor_id="human.approver",
        summary=("The bounded workflow proved the implementation and preserved independent gates."),
        limitations=("The harness does not sandbox arbitrary repository test code.",),
        documentation_paths=("docs/change.md",),
    )
    assert completed.state == LoopState.COMPLETED
    assert learning_path.is_file()
    assert len(store.verify_event_chain(manifest.loop_id)) == 6


def test_role_separation_rejects_builder_as_runner(tmp_path) -> None:
    root, store, manifest = create_test_loop(tmp_path)
    (root / "src" / "feature.py").write_text("VALUE = 2\n", encoding="utf-8")

    with pytest.raises(LoopPolicyError, match="test runner"):
        evaluate_loop(
            store,
            manifest.loop_id,
            runner_id="builder.agent",
        )


def test_repeated_failure_and_no_progress_escalate(tmp_path) -> None:
    controls = StopControls(
        maximum_iterations=5,
        maximum_consecutive_failures=5,
        maximum_repeated_error_count=2,
        maximum_no_progress_count=1,
    )
    root, store, manifest = create_test_loop(tmp_path, make_spec(controls=controls))
    (root / "src" / "feature.py").write_text(
        "VALUE = 2  \n",
        encoding="utf-8",
    )

    first, first_manifest, _ = evaluate_loop(
        store,
        manifest.loop_id,
        runner_id="test.runner",
    )
    assert first.passed is False
    assert first_manifest.state == LoopState.ACTIVE

    second, second_manifest, reasons = evaluate_loop(
        store,
        manifest.loop_id,
        runner_id="test.runner",
    )
    assert second.passed is False
    assert second_manifest.state == LoopState.ESCALATED
    assert any("Repeated-error" in item for item in reasons)
    assert any("No-progress" in item for item in reasons)


def test_token_budget_fails_before_verifier_execution(tmp_path) -> None:
    budget = ResourceBudget(maximum_tokens=10, maximum_cost_usd=1)
    root, store, manifest = create_test_loop(tmp_path, make_spec(budget=budget))
    (root / "src" / "feature.py").write_text("VALUE = 2\n", encoding="utf-8")

    with pytest.raises(LoopBudgetError, match="Token budget"):
        evaluate_loop(
            store,
            manifest.loop_id,
            runner_id="test.runner",
            tokens_used=11,
        )


def test_security_policy_detects_unsafe_transport_setting(tmp_path) -> None:
    root, store, manifest = create_test_loop(tmp_path)
    (root / "src" / "feature.py").write_text(
        "client = Client(trust_env=True)\n",
        encoding="utf-8",
    )
    (root / "docs" / "change.md").write_text("# Unsafe change\n", encoding="utf-8")
    evaluation, _, _ = evaluate_loop(
        store,
        manifest.loop_id,
        runner_id="test.runner",
    )
    assert evaluation.passed is True

    security, updated = verify_security_policy(
        store,
        manifest.loop_id,
        verifier_id="security.verifier",
    )
    assert security.passed is False
    assert updated.state == LoopState.ACTIVE
    assert "Environment proxy inheritance was enabled." in security.findings


def test_guarded_rollback_restores_only_baseline_worktree(tmp_path) -> None:
    root, store, manifest = create_test_loop(tmp_path)
    original = (root / "src" / "feature.py").read_text(encoding="utf-8")
    (root / "src" / "feature.py").write_text("VALUE = 99\n", encoding="utf-8")

    plan, unchanged = rollback_loop(
        store,
        manifest.loop_id,
        actor_id="human.owner",
        confirmation="",
        apply=False,
    )
    assert unchanged is None
    assert any("guarded rollback" in line.lower() for line in plan)

    _, rolled_back = rollback_loop(
        store,
        manifest.loop_id,
        actor_id="human.owner",
        confirmation=manifest.loop_id,
        apply=True,
    )
    assert rolled_back is not None
    assert rolled_back.state == LoopState.ROLLED_BACK
    assert (root / "src" / "feature.py").read_text(encoding="utf-8") == original
    assert git(root, "status", "--porcelain") == ""


def test_repository_change_after_verification_blocks_security_gate(tmp_path) -> None:
    root, store, manifest = create_test_loop(tmp_path)
    (root / "src" / "feature.py").write_text("VALUE = 2\n", encoding="utf-8")
    (root / "docs" / "change.md").write_text("# Verified\n", encoding="utf-8")
    evaluation, _, _ = evaluate_loop(
        store,
        manifest.loop_id,
        runner_id="test.runner",
    )
    assert evaluation.passed is True

    (root / "src" / "feature.py").write_text("VALUE = 3\n", encoding="utf-8")
    security, updated = verify_security_policy(
        store,
        manifest.loop_id,
        verifier_id="security.verifier",
    )

    assert security.passed is False
    assert updated.state == LoopState.ACTIVE
    assert any("changed after deterministic verification" in item for item in security.findings)


def test_evidence_tampering_is_detected(tmp_path) -> None:
    root, store, manifest = create_test_loop(tmp_path)
    (root / "src" / "feature.py").write_text("VALUE = 2\n", encoding="utf-8")
    (root / "docs" / "change.md").write_text("# Verified\n", encoding="utf-8")
    evaluate_loop(store, manifest.loop_id, runner_id="test.runner")

    evidence_path = (
        store.loop_directory(manifest.loop_id) / "evidence" / "iteration-001-evaluation.json"
    )
    evidence_path.write_text("{}\n", encoding="utf-8")

    with pytest.raises(Exception, match="evidence failed integrity"):
        store.verify_integrity(manifest.loop_id)


def test_manual_escalation_stops_non_terminal_loop(tmp_path) -> None:
    _, store, manifest = create_test_loop(tmp_path)

    escalated = escalate_loop(
        store,
        manifest.loop_id,
        actor_id="human.owner",
        reason="Architecture uncertainty requires explicit human direction.",
    )

    assert escalated.state == LoopState.ESCALATED
    assert store.verify_event_chain(manifest.loop_id)[-1].event_type == "human_escalation_required"
