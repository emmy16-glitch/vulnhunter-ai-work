from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError
from pydantic import ValidationError

from vulnhunter.source_hunt.benchmark_acceptance import (
    BenchmarkAcceptanceVerdict,
    SourceBenchmarkAcceptanceBundle,
    SourceBenchmarkAcceptanceEvaluator,
    SourceBenchmarkAcceptancePolicy,
    SourceBenchmarkCampaignRunner,
    SourceBenchmarkSuite,
    SourceBenchmarkSuiteEntry,
)
from vulnhunter.source_hunt.benchmark_v2 import (
    BenchmarkCorpusKind,
    SourceBenchmarkCorpus,
    SourceGroundTruthCase,
)
from vulnhunter.source_hunt.models import (
    CandidateDisposition,
    CapabilityAssessment,
    FalsificationDecision,
    GroqHypothesis,
    RepositorySnapshot,
    SourceCandidate,
    SourceHuntReport,
    SourceHuntStage,
    SourceReference,
)

_NOW = datetime(2026, 8, 15, 9, 0, tzinfo=UTC)


def _snapshot(repository_id: str, revision_char: str, snapshot_char: str) -> RepositorySnapshot:
    return RepositorySnapshot(
        repository_id=repository_id,
        repository_root=f"/controlled/{repository_id}",
        revision=revision_char * 40,
        snapshot_sha256=snapshot_char * 64,
        files=(),
        total_bytes=0,
        created_at=_NOW,
    )


def _candidate(
    candidate_id: str,
    vulnerability_class: str,
    path: str,
    line: int,
) -> SourceCandidate:
    reference = SourceReference(
        path=path,
        source_sha256="f" * 64,
        line_start=line,
        line_end=line,
        symbol="handler",
    )
    return SourceCandidate(
        candidate_id=candidate_id,
        hypothesis=GroqHypothesis(
            title=f"{vulnerability_class} candidate",
            vulnerability_class=vulnerability_class,
            summary="Controlled benchmark candidate.",
            entry_point=reference,
            sink=reference,
            path=(reference,),
            evidence_refs=(reference,),
            confidence=90,
        ),
        falsification=FalsificationDecision(
            disposition=CandidateDisposition.SURVIVED,
            reason="The controlled candidate survives deterministic falsification.",
        ),
        capability=CapabilityAssessment(
            meaningful=True,
            required_attacker_capability="Control the benchmark input",
            resulting_capability="Reach the controlled benchmark sink",
            impact_boundary="Controlled laboratory fixture",
            reason="The fixture intentionally models the security boundary.",
        ),
    )


def _report(
    report_id: str,
    snapshot: RepositorySnapshot,
    candidates: tuple[SourceCandidate, ...],
) -> SourceHuntReport:
    return SourceHuntReport(
        report_id=report_id,
        stage=SourceHuntStage.COMPLETE,
        snapshot=snapshot,
        approval_id="controlled-benchmark-approval",
        model="controlled-report",
        surfaces_examined=2,
        model_calls=0,
        candidates=candidates,
        rejected_count=0,
        abstained_count=0,
        created_at=_NOW,
    )


def _suite() -> tuple[SourceBenchmarkSuite, RepositorySnapshot, RepositorySnapshot]:
    controlled_snapshot = _snapshot("controlled-path", "a", "1")
    synthetic_snapshot = _snapshot("synthetic-query", "b", "2")
    controlled = SourceBenchmarkCorpus.create(
        corpus_id="controlled-path",
        kind=BenchmarkCorpusKind.CONTROLLED_LAB,
        cases=(
            SourceGroundTruthCase(
                case_id="PATH-001",
                vulnerability_class="path_traversal",
                path="app.py",
                line_start=10,
                line_end=10,
                expected_vulnerable=True,
            ),
            SourceGroundTruthCase(
                case_id="PATH-CLEAN-001",
                vulnerability_class="path_traversal",
                path="app.py",
                line_start=30,
                line_end=30,
                expected_vulnerable=False,
            ),
        ),
    )
    synthetic = SourceBenchmarkCorpus.create(
        corpus_id="synthetic-query",
        kind=BenchmarkCorpusKind.SYNTHETIC,
        cases=(
            SourceGroundTruthCase(
                case_id="SQL-001",
                vulnerability_class="sql_injection",
                path="query.py",
                line_start=7,
                line_end=7,
                expected_vulnerable=True,
            ),
        ),
    )
    suite = SourceBenchmarkSuite.create(
        suite_id="source-hunt-v2-acceptance",
        entries=(
            SourceBenchmarkSuiteEntry(
                corpus=controlled,
                repository_id=controlled_snapshot.repository_id,
                source_revision=controlled_snapshot.revision,
                snapshot_sha256=controlled_snapshot.snapshot_sha256,
            ),
            SourceBenchmarkSuiteEntry(
                corpus=synthetic,
                repository_id=synthetic_snapshot.repository_id,
                source_revision=synthetic_snapshot.revision,
                snapshot_sha256=synthetic_snapshot.snapshot_sha256,
            ),
        ),
    )
    return suite, controlled_snapshot, synthetic_snapshot


def _policy() -> SourceBenchmarkAcceptancePolicy:
    return SourceBenchmarkAcceptancePolicy.create(
        policy_id="source-hunt-v2-policy",
        minimum_cases=3,
        minimum_controlled_lab_cases=2,
        minimum_precision=1.0,
        minimum_recall=1.0,
        minimum_f1=1.0,
        maximum_false_positives=0,
        maximum_false_negatives=0,
    )


def _baseline_and_candidate_reports():
    suite, controlled_snapshot, synthetic_snapshot = _suite()
    controlled_finding = _candidate("candidate-path", "path_traversal", "app.py", 10)
    sql_finding = _candidate("candidate-sql", "sql_injection", "query.py", 7)
    baseline = {
        "controlled-path": _report(
            "baseline-controlled",
            controlled_snapshot,
            (controlled_finding,),
        ),
        "synthetic-query": _report("baseline-synthetic", synthetic_snapshot, ()),
    }
    candidate = {
        "controlled-path": _report(
            "candidate-controlled",
            controlled_snapshot,
            (controlled_finding,),
        ),
        "synthetic-query": _report(
            "candidate-synthetic",
            synthetic_snapshot,
            (sql_finding,),
        ),
    }
    return suite, baseline, candidate


def test_candidate_is_accepted_only_after_complete_suite_and_regression_gates_pass():
    suite, baseline_reports, candidate_reports = _baseline_and_candidate_reports()
    runner = SourceBenchmarkCampaignRunner()
    baseline = runner.run(
        label="baseline",
        engine_revision="1" * 40,
        suite=suite,
        reports=baseline_reports,
    )
    candidate = runner.run(
        label="candidate",
        engine_revision="2" * 40,
        suite=suite,
        reports=candidate_reports,
    )

    acceptance = SourceBenchmarkAcceptanceEvaluator().evaluate(
        policy=_policy(),
        baseline=baseline,
        candidate=candidate,
    )
    bundle = SourceBenchmarkAcceptanceBundle.create(
        baseline=baseline,
        candidate=candidate,
        acceptance=acceptance,
    )

    assert baseline.metrics.recall == 0.5
    assert candidate.metrics.recall == 1.0
    assert acceptance.verdict == BenchmarkAcceptanceVerdict.ACCEPTED
    assert acceptance.reasons == ()
    assert bundle.production_accuracy_claim_permitted is False


def test_regression_and_absolute_threshold_fail_closed():
    suite, baseline_reports, candidate_reports = _baseline_and_candidate_reports()
    runner = SourceBenchmarkCampaignRunner()
    baseline = runner.run(
        label="baseline",
        engine_revision="1" * 40,
        suite=suite,
        reports=candidate_reports,
    )
    regressed = runner.run(
        label="candidate",
        engine_revision="2" * 40,
        suite=suite,
        reports=baseline_reports,
    )

    acceptance = SourceBenchmarkAcceptanceEvaluator().evaluate(
        policy=_policy(),
        baseline=baseline,
        candidate=regressed,
    )

    assert acceptance.verdict == BenchmarkAcceptanceVerdict.REJECTED
    assert "candidate recall is below the acceptance minimum" in acceptance.reasons
    assert "candidate introduces too many new false negatives versus baseline" in acceptance.reasons
    assert "candidate recall regression exceeds policy" in acceptance.reasons


def test_suite_requires_exact_report_set_and_exact_fixture_snapshot():
    suite, baseline_reports, _candidate_reports = _baseline_and_candidate_reports()
    runner = SourceBenchmarkCampaignRunner()
    missing = dict(baseline_reports)
    missing.pop("synthetic-query")
    with pytest.raises(ValueError, match="report set does not match suite"):
        runner.run(
            label="baseline",
            engine_revision="1" * 40,
            suite=suite,
            reports=missing,
        )

    wrong_snapshot = _snapshot("synthetic-query", "b", "9")
    mismatched = dict(baseline_reports)
    mismatched["synthetic-query"] = _report("wrong-snapshot", wrong_snapshot, ())
    with pytest.raises(ValueError, match="does not match the suite fixture binding"):
        runner.run(
            label="baseline",
            engine_revision="1" * 40,
            suite=suite,
            reports=mismatched,
        )


def test_policy_suite_run_and_bundle_reject_tampering():
    suite, baseline_reports, candidate_reports = _baseline_and_candidate_reports()
    policy = _policy()
    runner = SourceBenchmarkCampaignRunner()
    baseline = runner.run(
        label="baseline",
        engine_revision="1" * 40,
        suite=suite,
        reports=baseline_reports,
    )
    candidate = runner.run(
        label="candidate",
        engine_revision="2" * 40,
        suite=suite,
        reports=candidate_reports,
    )
    acceptance = SourceBenchmarkAcceptanceEvaluator().evaluate(
        policy=policy,
        baseline=baseline,
        candidate=candidate,
    )
    bundle = SourceBenchmarkAcceptanceBundle.create(
        baseline=baseline,
        candidate=candidate,
        acceptance=acceptance,
    )

    policy_payload = policy.model_dump(mode="json")
    policy_payload["minimum_recall"] = 0.5
    with pytest.raises(ValidationError, match="policy digest"):
        SourceBenchmarkAcceptancePolicy.model_validate(policy_payload)

    suite_payload = suite.model_dump(mode="json")
    suite_payload["entries"][0]["repository_id"] = "different-repository"
    with pytest.raises(ValidationError, match="suite digest"):
        SourceBenchmarkSuite.model_validate(suite_payload)

    run_payload = candidate.model_dump(mode="json")
    run_payload["metrics"]["recall"] = 0.25
    with pytest.raises(ValidationError, match="campaign run digest"):
        type(candidate).model_validate(run_payload)

    bundle_payload = bundle.model_dump(mode="json")
    bundle_payload["candidate"]["label"] = "altered"
    with pytest.raises(ValidationError):
        SourceBenchmarkAcceptanceBundle.model_validate(bundle_payload)


def _write_reports(directory: Path, reports: dict[str, SourceHuntReport]) -> None:
    directory.mkdir()
    for corpus_id, report in reports.items():
        (directory / f"{corpus_id}.json").write_text(
            report.model_dump_json(indent=2),
            encoding="utf-8",
        )


def test_management_command_writes_acceptance_evidence_and_rejects_regression(tmp_path):
    suite, baseline_reports, candidate_reports = _baseline_and_candidate_reports()
    suite_path = tmp_path / "suite.json"
    policy_path = tmp_path / "policy.json"
    suite_path.write_text(suite.model_dump_json(indent=2), encoding="utf-8")
    policy_path.write_text(_policy().model_dump_json(indent=2), encoding="utf-8")
    baseline_dir = tmp_path / "baseline"
    candidate_dir = tmp_path / "candidate"
    _write_reports(baseline_dir, baseline_reports)
    _write_reports(candidate_dir, candidate_reports)
    output = tmp_path / "acceptance.json"

    call_command(
        "vh_check_source_hunt_benchmark_acceptance",
        suite_file=str(suite_path),
        policy_file=str(policy_path),
        baseline_report_dir=str(baseline_dir),
        candidate_report_dir=str(candidate_dir),
        baseline_engine_revision="1" * 40,
        candidate_engine_revision="2" * 40,
        output=str(output),
    )

    bundle = SourceBenchmarkAcceptanceBundle.model_validate_json(output.read_text(encoding="utf-8"))
    assert bundle.acceptance.verdict == BenchmarkAcceptanceVerdict.ACCEPTED

    rejected_output = tmp_path / "rejected.json"
    with pytest.raises(CommandError, match="benchmark rejected"):
        call_command(
            "vh_check_source_hunt_benchmark_acceptance",
            suite_file=str(suite_path),
            policy_file=str(policy_path),
            baseline_report_dir=str(candidate_dir),
            candidate_report_dir=str(baseline_dir),
            baseline_engine_revision="1" * 40,
            candidate_engine_revision="2" * 40,
            output=str(rejected_output),
        )
    rejected = SourceBenchmarkAcceptanceBundle.model_validate_json(
        rejected_output.read_text(encoding="utf-8")
    )
    assert rejected.acceptance.verdict == BenchmarkAcceptanceVerdict.REJECTED
    assert json.loads(rejected_output.read_text(encoding="utf-8"))["bundle_sha256"]
