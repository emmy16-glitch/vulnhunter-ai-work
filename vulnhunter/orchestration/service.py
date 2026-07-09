"""State machine and controls for bounded engineering loops."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import uuid
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from vulnhunter.exceptions import (
    LoopBudgetError,
    LoopIntegrityError,
    LoopPolicyError,
    LoopStateError,
)
from vulnhunter.orchestration.evaluator import (
    changed_files,
    collect_change_evidence,
    current_commit,
    current_tree,
    path_is_allowed,
    repository_root,
    run_evaluation,
    run_security_verification,
    working_tree_is_clean,
)
from vulnhunter.orchestration.models import (
    HumanApprovalRecord,
    HumanDecision,
    LearningRecord,
    LoopManifest,
    LoopSpec,
    LoopState,
    ReviewDecision,
    ReviewRecord,
    SecurityEvidence,
    normalize_actor_id,
)
from vulnhunter.orchestration.store import LoopStore


def load_spec(path: Path) -> LoopSpec:
    """Load one strict JSON loop specification."""
    try:
        return LoopSpec.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValidationError) as exc:
        raise LoopPolicyError(f"Loop specification is invalid: {exc}") from exc


def write_template(path: Path) -> Path:
    """Write a complete example specification without overwriting files."""
    if path.exists():
        raise LoopPolicyError(f"Template destination already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    template = {
        "title": "Implement one bounded VulnHunter change",
        "objective": (
            "Implement one precisely scoped change and prove it with deterministic "
            "tests, policy checks, independent review, and human approval."
        ),
        "required_context": [
            "AGENTS.md",
            "Relevant implementation and tests",
            "Applicable ADRs and security boundaries",
        ],
        "allowed_actions": [
            "edit_allowed_files",
            "run_deterministic_verifiers",
            "record_redacted_evidence",
            "update_documentation",
        ],
        "allowed_paths": [
            "vulnhunter/example/**",
            "tests/unit/test_example.py",
            "docs/intelligence/EXAMPLE.md",
            "docs/adr/README.md",
        ],
        "verifiers": [
            "ruff_check",
            "compileall",
            "pytest",
            "ruff_format_check",
            "git_diff_check",
        ],
        "required_evidence": [
            "Focused regression tests",
            "Full test suite",
            "Lint and format checks",
            "Changed-file and diff hashes",
            "Security-policy verification",
            "Independent review",
        ],
        "recovery_instructions": [
            "Stop when a hard limit is reached.",
            "Inspect the evidence and failure signature.",
            "Use the generated recovery plan before any rollback.",
            "Escalate architectural or security-policy uncertainty to a human.",
        ],
        "documentation_paths": [
            "docs/intelligence/EXAMPLE.md",
            "docs/adr/README.md",
        ],
        "stop_controls": {
            "maximum_iterations": 5,
            "maximum_elapsed_seconds": 3600,
            "per_check_timeout_seconds": 180,
            "maximum_consecutive_failures": 3,
            "maximum_repeated_error_count": 2,
            "maximum_no_progress_count": 2,
            "maximum_changed_files": 40,
            "maximum_diff_bytes": 2000000,
        },
        "resource_budget": {
            "maximum_tokens": 200000,
            "maximum_cost_usd": 25.0,
        },
    }
    path.write_text(json.dumps(template, indent=2) + "\n", encoding="utf-8")
    return path


def create_loop(
    store: LoopStore,
    spec: LoopSpec,
    *,
    creator_id: str,
    builder_id: str,
    repository: Path,
) -> LoopManifest:
    """Create a loop only from a clean Git baseline."""
    root = repository_root(repository)
    if not working_tree_is_clean(root):
        raise LoopPolicyError(
            "Create a loop only from a clean Git working tree so rollback and diff "
            "evidence have an unambiguous baseline."
        )

    creator = normalize_actor_id(creator_id)
    builder = normalize_actor_id(builder_id)
    now = datetime.now(UTC)
    loop_id = f"loop-{now:%Y%m%dT%H%M%SZ}-{uuid.uuid4().hex[:8]}"
    manifest = LoopManifest(
        loop_id=loop_id,
        spec=spec,
        creator_id=creator,
        builder_id=builder,
        repository_root=str(root),
        baseline_commit=current_commit(root),
        baseline_tree=current_tree(root),
        created_at=now,
        updated_at=now,
    )
    store.create(manifest)
    store.append_event(
        loop_id,
        "loop_created",
        creator,
        {
            "objective": spec.objective,
            "builder_id": builder,
            "baseline_commit": manifest.baseline_commit,
            "allowed_paths": list(spec.allowed_paths),
            "verifiers": [item.value for item in spec.verifiers],
            "stop_controls": spec.stop_controls.model_dump(mode="json"),
            "resource_budget": spec.resource_budget.model_dump(mode="json"),
        },
    )
    return manifest


def evaluate_loop(
    store: LoopStore,
    loop_id: str,
    *,
    runner_id: str,
    tokens_used: int = 0,
    cost_usd: float = 0,
):
    """Run deterministic proof collection and enforce hard controls."""
    manifest = store.load(loop_id)
    _require_state(
        manifest,
        {LoopState.ACTIVE, LoopState.AWAITING_SECURITY},
        "verification",
    )
    runner = normalize_actor_id(runner_id)
    if runner == manifest.builder_id:
        raise LoopPolicyError("The test runner must be independent from the builder.")

    _enforce_before_iteration(manifest, tokens_used=tokens_used, cost_usd=cost_usd)
    root = _manifest_repository(manifest)
    evidence = run_evaluation(
        root,
        manifest,
        runner_id=runner,
        tokens_used=tokens_used,
        cost_usd=cost_usd,
    )

    repeated_error_count = (
        manifest.repeated_error_count + 1
        if evidence.failure_signature
        and evidence.failure_signature == manifest.latest_failure_signature
        else (1 if evidence.failure_signature else 0)
    )
    no_progress_count = (
        manifest.no_progress_count + 1
        if evidence.change_fingerprint == manifest.latest_change_fingerprint
        else 0
    )
    consecutive_failures = 0 if evidence.passed else manifest.consecutive_failures + 1
    state = LoopState.AWAITING_SECURITY if evidence.passed else LoopState.ACTIVE

    controls = manifest.spec.stop_controls
    stop_reasons: list[str] = []
    if consecutive_failures >= controls.maximum_consecutive_failures:
        stop_reasons.append("Maximum consecutive verifier failures reached.")
    if repeated_error_count >= controls.maximum_repeated_error_count:
        stop_reasons.append("Repeated-error threshold reached.")
    if no_progress_count >= controls.maximum_no_progress_count:
        stop_reasons.append("No-progress threshold reached.")
    if evidence.iteration >= controls.maximum_iterations and not evidence.passed:
        stop_reasons.append("Maximum iteration count reached.")
    elapsed_after = (datetime.now(UTC) - manifest.created_at).total_seconds()
    if elapsed_after >= controls.maximum_elapsed_seconds:
        stop_reasons.append("Maximum loop elapsed time reached.")
    if stop_reasons:
        state = LoopState.ESCALATED

    updated = manifest.model_copy(
        update={
            "updated_at": datetime.now(UTC),
            "state": state,
            "iteration_count": evidence.iteration,
            "consecutive_failures": consecutive_failures,
            "repeated_error_count": repeated_error_count,
            "no_progress_count": no_progress_count,
            "tokens_used": manifest.tokens_used + tokens_used,
            "cost_usd": manifest.cost_usd + cost_usd,
            "latest_change_fingerprint": evidence.change_fingerprint,
            "latest_failure_signature": evidence.failure_signature,
            "latest_runner_id": runner,
            "latest_security_verifier_id": None,
            "latest_reviewer_id": None,
            "human_approver_id": None,
        }
    )
    evidence_path = store.save_evaluation(loop_id, evidence)
    store.save(updated)
    store.append_event(
        loop_id,
        "verification_completed",
        runner,
        {
            "iteration": evidence.iteration,
            "passed": evidence.passed,
            "changed_files": list(evidence.changed_files),
            "out_of_scope_paths": list(evidence.out_of_scope_paths),
            "diff_sha256": evidence.diff_sha256,
            "failure_signature": evidence.failure_signature,
            "stop_reasons": stop_reasons,
            "state": state.value,
            "evidence_file": str(evidence_path.relative_to(store.loop_directory(loop_id))),
            "evidence_sha256": _sha256_file(evidence_path),
        },
    )
    if stop_reasons:
        store.append_event(
            loop_id,
            "human_escalation_required",
            runner,
            {"reasons": stop_reasons},
        )
    return evidence, updated, tuple(stop_reasons)


def verify_security_policy(
    store: LoopStore,
    loop_id: str,
    *,
    verifier_id: str,
) -> tuple[SecurityEvidence, LoopManifest]:
    """Run a separate deterministic security-policy verification role."""
    manifest = store.load(loop_id)
    _require_state(manifest, {LoopState.AWAITING_SECURITY}, "security verification")
    verifier = normalize_actor_id(verifier_id)
    if verifier in {manifest.builder_id, manifest.latest_runner_id}:
        raise LoopPolicyError(
            "The security verifier must be independent from builder and test runner."
        )

    latest = store.load_latest_evaluation(loop_id)
    if not latest.passed or latest.iteration != manifest.iteration_count:
        raise LoopStateError("Latest deterministic verification has not passed.")

    evidence = run_security_verification(
        _manifest_repository(manifest),
        manifest,
        verifier_id=verifier,
    )
    if evidence.diff_sha256 != latest.diff_sha256:
        evidence = evidence.model_copy(
            update={
                "passed": False,
                "findings": tuple(
                    dict.fromkeys(
                        (
                            "Repository changed after deterministic verification; "
                            "rerun the verifier suite.",
                            *evidence.findings,
                        )
                    )
                ),
            }
        )
    state = LoopState.AWAITING_REVIEW if evidence.passed else LoopState.ACTIVE
    updated = manifest.model_copy(
        update={
            "updated_at": datetime.now(UTC),
            "state": state,
            "latest_security_verifier_id": verifier,
        }
    )
    evidence_path = store.save_security(loop_id, evidence)
    store.save(updated)
    store.append_event(
        loop_id,
        "security_verification_completed",
        verifier,
        {
            "iteration": evidence.iteration,
            "passed": evidence.passed,
            "findings": list(evidence.findings),
            "diff_sha256": evidence.diff_sha256,
            "state": state.value,
            "evidence_file": str(evidence_path.relative_to(store.loop_directory(loop_id))),
            "evidence_sha256": _sha256_file(evidence_path),
        },
    )
    return evidence, updated


def submit_independent_review(
    store: LoopStore,
    loop_id: str,
    *,
    reviewer_id: str,
    decision: ReviewDecision,
    summary: str,
    limitations: tuple[str, ...] = (),
) -> tuple[ReviewRecord, LoopManifest]:
    """Record an independent diff/evidence review."""
    manifest = store.load(loop_id)
    _require_state(manifest, {LoopState.AWAITING_REVIEW}, "independent review")
    reviewer = normalize_actor_id(reviewer_id)
    prior_roles = {
        manifest.builder_id,
        manifest.latest_runner_id,
        manifest.latest_security_verifier_id,
    }
    if reviewer in prior_roles:
        raise LoopPolicyError(
            "The independent reviewer must differ from builder, test runner, and security verifier."
        )

    evaluation = store.load_latest_evaluation(loop_id)
    security = store.load_latest_security(loop_id)
    if not security.passed or security.iteration != manifest.iteration_count:
        raise LoopStateError("Latest security verification has not passed.")
    _ensure_diff_unchanged(manifest, evaluation.diff_sha256)

    record = ReviewRecord(
        iteration=manifest.iteration_count,
        reviewer_id=reviewer,
        created_at=datetime.now(UTC),
        decision=decision,
        summary=summary,
        limitations=limitations,
    )
    state = LoopState.AWAITING_HUMAN if decision == ReviewDecision.APPROVE else LoopState.ACTIVE
    updated = manifest.model_copy(
        update={
            "updated_at": datetime.now(UTC),
            "state": state,
            "latest_reviewer_id": reviewer,
        }
    )
    evidence_path = store.save_review(loop_id, record)
    store.save(updated)
    store.append_event(
        loop_id,
        "independent_review_completed",
        reviewer,
        {
            "iteration": record.iteration,
            "decision": decision.value,
            "summary": summary,
            "limitations": list(limitations),
            "state": state.value,
            "diff_sha256": evaluation.diff_sha256,
            "security_diff_sha256": security.diff_sha256,
            "evidence_file": str(evidence_path.relative_to(store.loop_directory(loop_id))),
            "evidence_sha256": _sha256_file(evidence_path),
        },
    )
    return record, updated


def record_human_approval(
    store: LoopStore,
    loop_id: str,
    *,
    human_id: str,
    decision: HumanDecision,
    note: str,
) -> tuple[HumanApprovalRecord, LoopManifest]:
    """Record the explicit human approval gate."""
    manifest = store.load(loop_id)
    _require_state(manifest, {LoopState.AWAITING_HUMAN}, "human approval")
    human = normalize_actor_id(human_id)
    prior_roles = {
        manifest.builder_id,
        manifest.latest_runner_id,
        manifest.latest_security_verifier_id,
        manifest.latest_reviewer_id,
    }
    if human in prior_roles:
        raise LoopPolicyError(
            "The human approver must be independent from the recorded agent roles."
        )

    review = store.load_latest_review(loop_id)
    if review.decision != ReviewDecision.APPROVE:
        raise LoopStateError("Independent review has not approved this iteration.")
    evaluation = store.load_latest_evaluation(loop_id)
    _ensure_diff_unchanged(manifest, evaluation.diff_sha256)

    record = HumanApprovalRecord(
        iteration=manifest.iteration_count,
        human_id=human,
        created_at=datetime.now(UTC),
        decision=decision,
        note=note,
    )
    state = (
        LoopState.AWAITING_DOCUMENTATION
        if decision == HumanDecision.APPROVE
        else LoopState.REJECTED
    )
    updated = manifest.model_copy(
        update={
            "updated_at": datetime.now(UTC),
            "state": state,
            "human_approver_id": human,
        }
    )
    evidence_path = store.save_approval(loop_id, record)
    store.save(updated)
    store.append_event(
        loop_id,
        "human_decision_recorded",
        human,
        {
            "iteration": record.iteration,
            "decision": decision.value,
            "note": note,
            "state": state.value,
            "diff_sha256": evaluation.diff_sha256,
            "evidence_file": str(evidence_path.relative_to(store.loop_directory(loop_id))),
            "evidence_sha256": _sha256_file(evidence_path),
        },
    )
    return record, updated


def record_learning(
    store: LoopStore,
    loop_id: str,
    *,
    actor_id: str,
    summary: str,
    limitations: tuple[str, ...],
    documentation_paths: tuple[str, ...],
) -> tuple[LearningRecord, LoopManifest, Path]:
    """Close an approved loop with permanent documentation evidence."""
    manifest = store.load(loop_id)
    _require_state(
        manifest,
        {LoopState.AWAITING_DOCUMENTATION},
        "documentation and learning",
    )
    actor = normalize_actor_id(actor_id)
    if actor != manifest.human_approver_id:
        raise LoopPolicyError(
            "The recorded human approver must attest to the final learning record."
        )

    root = _manifest_repository(manifest)
    evaluation = store.load_latest_evaluation(loop_id)
    _ensure_diff_unchanged(manifest, evaluation.diff_sha256)
    changed = set(changed_files(root, manifest.baseline_commit))
    normalized_paths: list[str] = []
    for value in documentation_paths:
        relative = value.strip().replace("\\", "/")
        if not relative or relative.startswith("/") or ".." in Path(relative).parts:
            raise LoopPolicyError(f"Invalid documentation path: {value}")
        if relative not in changed:
            raise LoopPolicyError(
                f"Documentation evidence was not changed in this loop: {relative}"
            )
        if not path_is_allowed(relative, manifest.spec.documentation_paths):
            raise LoopPolicyError(
                f"Documentation path is outside the declared documentation boundary: {relative}"
            )
        if not (root / relative).is_file():
            raise LoopPolicyError(f"Documentation path does not exist: {relative}")
        normalized_paths.append(relative)

    record = LearningRecord(
        iteration=manifest.iteration_count,
        actor_id=actor,
        created_at=datetime.now(UTC),
        summary=summary,
        limitations=limitations,
        documentation_paths=tuple(normalized_paths),
    )
    path = store.save_learning(loop_id, record)
    updated = manifest.model_copy(
        update={
            "updated_at": datetime.now(UTC),
            "state": LoopState.COMPLETED,
        }
    )
    store.save(updated)
    store.append_event(
        loop_id,
        "learning_record_completed",
        actor,
        {
            "iteration": record.iteration,
            "summary": summary,
            "limitations": list(limitations),
            "documentation_paths": list(normalized_paths),
            "state": LoopState.COMPLETED.value,
            "diff_sha256": evaluation.diff_sha256,
            "evidence_file": str(path.relative_to(store.loop_directory(loop_id))),
            "evidence_sha256": _sha256_file(path),
        },
    )
    store.verify_integrity(loop_id)
    return record, updated, path


def escalate_loop(
    store: LoopStore,
    loop_id: str,
    *,
    actor_id: str,
    reason: str,
) -> LoopManifest:
    """Stop the active workflow and require explicit human recovery."""
    manifest = store.load(loop_id)
    terminal = {
        LoopState.COMPLETED,
        LoopState.REJECTED,
        LoopState.ESCALATED,
        LoopState.ROLLED_BACK,
    }
    if manifest.state in terminal:
        raise LoopStateError(f"Loop is already in terminal state {manifest.state.value}.")
    actor = normalize_actor_id(actor_id)
    normalized_reason = reason.strip()
    if len(normalized_reason) < 10:
        raise LoopPolicyError("Escalation reason must contain at least 10 characters.")
    updated = manifest.model_copy(
        update={
            "updated_at": datetime.now(UTC),
            "state": LoopState.ESCALATED,
        }
    )
    store.save(updated)
    store.append_event(
        loop_id,
        "human_escalation_required",
        actor,
        {"reason": normalized_reason, "state": LoopState.ESCALATED.value},
    )
    return updated


def recovery_plan(store: LoopStore, loop_id: str) -> tuple[str, ...]:
    """Return non-destructive recovery instructions for the current state."""
    manifest = store.load(loop_id)
    root = _manifest_repository(manifest)
    paths = changed_files(root, manifest.baseline_commit)
    lines = [
        f"Loop: {loop_id}",
        f"State: {manifest.state.value}",
        f"Baseline commit: {manifest.baseline_commit}",
        f"Changed files: {len(paths)}",
    ]
    lines.extend(f"  - {path}" for path in paths)
    lines.append("Recovery instructions:")
    lines.extend(f"  - {item}" for item in manifest.spec.recovery_instructions)
    if current_commit(root) != manifest.baseline_commit:
        lines.append("Automatic rollback is disabled because HEAD moved after the loop baseline.")
    else:
        lines.append(
            "A guarded rollback is available only with --apply and exact loop-ID confirmation."
        )
    return tuple(lines)


def rollback_loop(
    store: LoopStore,
    loop_id: str,
    *,
    actor_id: str,
    confirmation: str,
    apply: bool,
) -> tuple[tuple[str, ...], LoopManifest | None]:
    """Restore baseline files only after an explicit, exact confirmation."""
    manifest = store.load(loop_id)
    _require_state(
        manifest,
        {LoopState.ACTIVE, LoopState.ESCALATED, LoopState.REJECTED},
        "rollback",
    )
    actor = normalize_actor_id(actor_id)
    plan = recovery_plan(store, loop_id)
    if not apply:
        return plan, None
    if confirmation != loop_id:
        raise LoopPolicyError("Rollback confirmation must exactly match the loop ID.")

    root = _manifest_repository(manifest)
    if current_commit(root) != manifest.baseline_commit:
        raise LoopPolicyError("Automatic rollback refuses to rewrite or cross committed history.")
    paths = changed_files(root, manifest.baseline_commit)
    out_of_scope = tuple(
        path for path in paths if not path_is_allowed(path, manifest.spec.allowed_paths)
    )
    if out_of_scope:
        raise LoopPolicyError(
            "Rollback refused because changed paths exceed the declared boundary: "
            + ", ".join(out_of_scope)
        )

    tracked = _git_lines(root, "ls-files")
    tracked_paths = [path for path in paths if path in tracked]
    untracked_paths = [path for path in paths if path not in tracked]

    store.append_event(
        loop_id,
        "rollback_started",
        actor,
        {"paths": list(paths), "baseline_commit": manifest.baseline_commit},
    )
    if tracked_paths:
        subprocess.run(
            [
                "git",
                "restore",
                "--source",
                manifest.baseline_commit,
                "--staged",
                "--worktree",
                "--",
                *tracked_paths,
            ],
            cwd=root,
            check=True,
        )
    for relative in untracked_paths:
        path = (root / relative).resolve(strict=False)
        path.relative_to(root)
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            path.unlink(missing_ok=True)

    remaining = changed_files(root, manifest.baseline_commit)
    if remaining:
        raise LoopIntegrityError(
            "Rollback was incomplete; remaining paths: " + ", ".join(remaining)
        )

    updated = manifest.model_copy(
        update={
            "updated_at": datetime.now(UTC),
            "state": LoopState.ROLLED_BACK,
        }
    )
    store.save(updated)
    store.append_event(
        loop_id,
        "rollback_completed",
        actor,
        {"state": LoopState.ROLLED_BACK.value},
    )
    return plan, updated


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _ensure_diff_unchanged(manifest: LoopManifest, expected_sha256: str) -> None:
    _, _, current_sha256, _, _ = collect_change_evidence(
        _manifest_repository(manifest),
        manifest,
    )
    if current_sha256 != expected_sha256:
        raise LoopStateError(
            "Repository changed after the last accepted verification; rerun the "
            "deterministic verifier suite."
        )


def _enforce_before_iteration(
    manifest: LoopManifest,
    *,
    tokens_used: int,
    cost_usd: float,
) -> None:
    controls = manifest.spec.stop_controls
    if manifest.iteration_count >= controls.maximum_iterations:
        raise LoopBudgetError("Maximum loop iteration count has been reached.")
    elapsed = (datetime.now(UTC) - manifest.created_at).total_seconds()
    if elapsed >= controls.maximum_elapsed_seconds:
        raise LoopBudgetError("Maximum loop elapsed time has been reached.")
    if tokens_used < 0 or cost_usd < 0:
        raise LoopBudgetError("Resource usage values must not be negative.")

    budget = manifest.spec.resource_budget
    if (
        budget.maximum_tokens is not None
        and manifest.tokens_used + tokens_used > budget.maximum_tokens
    ):
        raise LoopBudgetError("Token budget would be exceeded.")
    if (
        budget.maximum_cost_usd is not None
        and manifest.cost_usd + cost_usd > budget.maximum_cost_usd
    ):
        raise LoopBudgetError("Cost budget would be exceeded.")


def _require_state(
    manifest: LoopManifest,
    allowed: set[LoopState],
    action: str,
) -> None:
    if manifest.state not in allowed:
        expected = ", ".join(sorted(item.value for item in allowed))
        raise LoopStateError(
            f"Cannot perform {action} while loop is {manifest.state.value}; "
            f"expected one of: {expected}."
        )


def _manifest_repository(manifest: LoopManifest) -> Path:
    root = Path(manifest.repository_root).resolve()
    if not (root / ".git").exists():
        raise LoopIntegrityError("Loop repository root is no longer a Git repository.")
    return root


def _git_lines(root: Path, *arguments: str) -> set[str]:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return {line for line in completed.stdout.splitlines() if line}
