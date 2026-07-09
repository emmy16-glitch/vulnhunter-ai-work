"""Trusted candidate evaluation and objective/regression gates."""

from __future__ import annotations

import hashlib
import json
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from vulnhunter.exceptions import ResearchEvaluationError
from vulnhunter.orchestration import CommandEvidence, verifier_registry
from vulnhunter.research.boundaries import (
    validate_candidate_paths,
    verify_protected_snapshot,
)
from vulnhunter.research.gitops import changed_files, diff_bytes
from vulnhunter.research.models import (
    DecisionOutcome,
    EvaluatorPolicy,
    ExperimentDecision,
    ExperimentEvaluation,
    ExperimentManifest,
    MetricReport,
    ObjectiveDirection,
    ProtectedSnapshot,
    RecordedMetricReport,
    normalize_actor_id,
)
from vulnhunter.security import redact_text

_OUTPUT_LIMIT = 16_000


def load_metric_report(path: Path) -> tuple[MetricReport, str]:
    """Load a non-executable JSON metric report and return its hash."""
    try:
        data = path.read_bytes()
        report = MetricReport.model_validate_json(data)
    except (OSError, ValidationError) as exc:
        raise ResearchEvaluationError(
            "Metric reports must be valid JSON matching the trusted metric schema."
        ) from exc
    return report, hashlib.sha256(data).hexdigest()


def record_metric_report(
    path: Path,
    *,
    evaluator_id: str,
) -> RecordedMetricReport:
    """Attach actor and source provenance to a metric report."""
    evaluator = normalize_actor_id(evaluator_id)
    report, digest = load_metric_report(path)
    return RecordedMetricReport(
        report=report,
        evaluator_id=evaluator,
        recorded_at=datetime.now(UTC),
        source_path=path.name,
        source_sha256=digest,
    )


def evaluate_candidate(
    manifest: ExperimentManifest,
    *,
    policy: EvaluatorPolicy,
    snapshot: ProtectedSnapshot,
    baseline: RecordedMetricReport,
    candidate: RecordedMetricReport,
    evaluator_id: str,
) -> ExperimentEvaluation:
    """Run fixed verifiers and all immutable objective/safety gates."""
    evaluator = normalize_actor_id(evaluator_id)
    if evaluator == manifest.builder_id:
        raise ResearchEvaluationError(
            "The candidate evaluator must be independent from the builder."
        )
    if candidate.evaluator_id != evaluator:
        raise ResearchEvaluationError(
            "The candidate report evaluator must match the actor running evaluation."
        )
    if manifest.worktree_path is None or manifest.candidate_commit is None:
        raise ResearchEvaluationError("The experiment has no prepared candidate worktree.")

    worktree = Path(manifest.worktree_path)
    changed = changed_files(
        worktree,
        baseline_commit=manifest.baseline_commit,
        candidate=manifest.candidate_commit,
    )
    patch = diff_bytes(
        worktree,
        baseline_commit=manifest.baseline_commit,
        candidate=manifest.candidate_commit,
    )
    diff_digest = hashlib.sha256(patch).hexdigest()

    boundary_violations = validate_candidate_paths(changed, manifest.spec, policy)
    protected_violations = verify_protected_snapshot(worktree, snapshot)
    limits = manifest.spec.limits
    if len(changed) > limits.maximum_changed_files:
        boundary_violations = (
            *boundary_violations,
            f"changed-file limit exceeded: {len(changed)} > {limits.maximum_changed_files}",
        )
    if len(patch) > limits.maximum_diff_bytes:
        boundary_violations = (
            *boundary_violations,
            f"diff-size limit exceeded: {len(patch)} > {limits.maximum_diff_bytes}",
        )

    registry = verifier_registry()
    if any(verifier not in policy.fixed_verifiers for verifier in manifest.spec.verifiers):
        raise ResearchEvaluationError(
            "The experiment requested a verifier outside the immutable evaluator policy."
        )

    checks_list: list[CommandEvidence] = []
    for verifier in manifest.spec.verifiers:
        argv = registry[verifier].argv
        if verifier.value == "git_diff_check":
            argv = (
                "git",
                "diff",
                "--check",
                f"{manifest.baseline_commit}..{manifest.candidate_commit}",
                "--",
            )
        checks_list.append(
            _run_fixed_verifier(
                worktree,
                verifier=verifier,
                argv=argv,
                timeout_seconds=limits.per_check_timeout_seconds,
            )
        )
    checks = tuple(checks_list)

    objective_delta, objective_passed = _objective_result(
        manifest,
        baseline.report,
        candidate.report,
    )
    regression_failures = _regression_failures(
        manifest,
        baseline.report,
        candidate.report,
    )
    safety_failures = _safety_failures(manifest, candidate.report)

    passed = all(
        (
            not boundary_violations,
            not protected_violations,
            all(check.passed for check in checks),
            objective_passed,
            not regression_failures,
            not safety_failures,
        )
    )
    failure_signature = None
    if not passed:
        failure_components = [
            *("boundary:" + item for item in boundary_violations),
            *("protected:" + item for item in protected_violations),
            *(f"verifier:{item.verifier.value}" for item in checks if not item.passed),
            *("regression:" + item for item in regression_failures),
            *("safety:" + item for item in safety_failures),
        ]
        if not objective_passed:
            failure_components.append("objective:not_improved")
        failure_signature = hashlib.sha256(
            "\n".join(sorted(failure_components)).encode("utf-8")
        ).hexdigest()

    return ExperimentEvaluation(
        experiment_id=manifest.experiment_id,
        evaluator_id=evaluator,
        created_at=datetime.now(UTC),
        baseline_commit=manifest.baseline_commit,
        candidate_commit=manifest.candidate_commit,
        changed_files=changed,
        diff_bytes=len(patch),
        diff_sha256=diff_digest,
        protected_snapshot_valid=not protected_violations,
        protected_violations=protected_violations,
        boundary_violations=boundary_violations,
        checks=checks,
        baseline_report_sha256=baseline.source_sha256,
        candidate_report_sha256=candidate.source_sha256,
        objective_delta=objective_delta,
        objective_passed=objective_passed,
        regression_failures=regression_failures,
        safety_failures=safety_failures,
        passed=passed,
        failure_signature=failure_signature,
    )


def decide_from_evaluation(
    manifest: ExperimentManifest,
    evaluation: ExperimentEvaluation,
    *,
    baseline: RecordedMetricReport,
    candidate: RecordedMetricReport,
    decider_id: str,
    evaluation_sha256: str,
) -> ExperimentDecision:
    """Apply the deterministic keep-or-revert gate."""
    decider = normalize_actor_id(decider_id)
    if decider in {manifest.builder_id, manifest.latest_evaluator_id}:
        raise ResearchEvaluationError(
            "The decision recorder must be independent from builder and evaluator."
        )
    metric = manifest.spec.objective.metric
    baseline_value = baseline.report.metrics[metric]
    candidate_value = candidate.report.metrics[metric]
    delta, _ = _objective_result(manifest, baseline.report, candidate.report)

    reasons: list[str] = []
    if evaluation.passed:
        outcome = DecisionOutcome.ACCEPT
        reasons.append("Objective improved by the required delta.")
        reasons.append("All regression, safety, boundary, and verifier gates passed.")
    else:
        hard_failure = bool(
            evaluation.boundary_violations
            or evaluation.protected_violations
            or evaluation.regression_failures
            or evaluation.safety_failures
            or any(not item.passed for item in evaluation.checks)
        )
        if hard_failure:
            outcome = DecisionOutcome.REJECT
            reasons.append("One or more immutable regression, safety, or integrity gates failed.")
        else:
            outcome = DecisionOutcome.INCONCLUSIVE
            reasons.append("The candidate did not provide the required objective improvement.")

        reasons.extend(evaluation.boundary_violations)
        reasons.extend(evaluation.protected_violations)
        reasons.extend(evaluation.regression_failures)
        reasons.extend(evaluation.safety_failures)
        reasons.extend(
            f"Verifier failed: {item.verifier.value}"
            for item in evaluation.checks
            if not item.passed
        )
        if not evaluation.objective_passed:
            reasons.append("Objective improvement gate failed.")

    return ExperimentDecision(
        experiment_id=manifest.experiment_id,
        decider_id=decider,
        created_at=datetime.now(UTC),
        outcome=outcome,
        reasons=tuple(dict.fromkeys(reasons)),
        baseline_value=baseline_value,
        candidate_value=candidate_value,
        objective_delta=delta,
        diff_sha256=evaluation.diff_sha256,
        evaluation_sha256=evaluation_sha256,
    )


def _objective_result(
    manifest: ExperimentManifest,
    baseline: MetricReport,
    candidate: MetricReport,
) -> tuple[float, bool]:
    objective = manifest.spec.objective
    try:
        baseline_value = baseline.metrics[objective.metric]
        candidate_value = candidate.metrics[objective.metric]
    except KeyError as exc:
        raise ResearchEvaluationError(
            f"Both reports must contain the objective metric {objective.metric!r}."
        ) from exc

    if objective.direction is ObjectiveDirection.MAXIMIZE:
        delta = candidate_value - baseline_value
    else:
        delta = baseline_value - candidate_value
    return delta, delta >= objective.minimum_delta


def _regression_failures(
    manifest: ExperimentManifest,
    baseline: MetricReport,
    candidate: MetricReport,
) -> tuple[str, ...]:
    failures: list[str] = []
    for gate in manifest.spec.regression_gates:
        if gate.metric not in baseline.metrics or gate.metric not in candidate.metrics:
            failures.append(f"missing regression metric: {gate.metric}")
            continue
        before = baseline.metrics[gate.metric]
        after = candidate.metrics[gate.metric]
        degradation = (
            before - after if gate.direction is ObjectiveDirection.MAXIMIZE else after - before
        )
        if degradation > gate.maximum_degradation:
            failures.append(
                f"{gate.metric} degraded by {degradation:.12g}; "
                f"maximum allowed is {gate.maximum_degradation:.12g}"
            )
    return tuple(failures)


def _safety_failures(
    manifest: ExperimentManifest,
    candidate: MetricReport,
) -> tuple[str, ...]:
    failures: list[str] = []
    for check in manifest.spec.required_safety_checks:
        if candidate.safety_checks.get(check) is not True:
            failures.append(f"required safety check did not pass: {check}")
    return tuple(failures)


def _run_fixed_verifier(
    worktree: Path,
    *,
    verifier,
    argv: tuple[str, ...],
    timeout_seconds: int,
) -> CommandEvidence:
    start = time.monotonic()
    timed_out = False
    try:
        completed = subprocess.run(
            list(argv),
            cwd=worktree,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
        exit_code = completed.returncode
        output = completed.stdout + completed.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        exit_code = 124
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
        output = f"{stdout}{stderr}\nVerifier timed out."
    except OSError as exc:
        raise ResearchEvaluationError(
            f"Unable to execute fixed verifier {verifier.value}."
        ) from exc

    safe_output = redact_text(output)
    encoded = safe_output.encode("utf-8")
    return CommandEvidence(
        verifier=verifier,
        argv=argv,
        exit_code=exit_code,
        passed=exit_code == 0 and not timed_out,
        duration_seconds=time.monotonic() - start,
        output_sha256=hashlib.sha256(encoded).hexdigest(),
        output_excerpt=safe_output[-_OUTPUT_LIMIT:],
        timed_out=timed_out,
    )


def evaluation_sha256(evaluation: ExperimentEvaluation) -> str:
    """Hash an evaluation deterministically for decision binding."""
    payload = evaluation.model_dump(mode="json")
    data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(data).hexdigest()
