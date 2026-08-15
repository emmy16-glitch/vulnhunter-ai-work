from datetime import UTC, datetime

import pytest

from vulnhunter.source_hunt.benchmark_acceptance import (
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
    RepositorySnapshot,
    SourceHuntReport,
    SourceHuntStage,
)


def _suite_and_report(stage: SourceHuntStage):
    snapshot = RepositorySnapshot(
        repository_id="controlled-abstention",
        repository_root="/controlled/fixture",
        revision="a" * 40,
        snapshot_sha256="b" * 64,
        files=(),
        total_bytes=0,
        created_at=datetime(2026, 8, 15, 12, 0, tzinfo=UTC),
    )
    corpus = SourceBenchmarkCorpus.create(
        corpus_id="controlled-abstention-corpus",
        kind=BenchmarkCorpusKind.CONTROLLED_LAB,
        cases=(
            SourceGroundTruthCase(
                case_id="ABSTAIN-VULN",
                vulnerability_class="path_traversal",
                path="app.py",
                line_start=10,
                line_end=10,
                expected_vulnerable=True,
            ),
            SourceGroundTruthCase(
                case_id="ABSTAIN-SAFE",
                vulnerability_class="path_traversal",
                path="app.py",
                line_start=20,
                line_end=20,
                expected_vulnerable=False,
            ),
        ),
    )
    suite = SourceBenchmarkSuite.create(
        suite_id="controlled-abstention-suite",
        entries=(
            SourceBenchmarkSuiteEntry(
                corpus=corpus,
                repository_id=snapshot.repository_id,
                source_revision=snapshot.revision,
                snapshot_sha256=snapshot.snapshot_sha256,
            ),
        ),
    )
    report = SourceHuntReport(
        report_id="source-report-controlled-abstention",
        stage=stage,
        snapshot=snapshot,
        approval_id="controlled-approval",
        model="controlled-model",
        surfaces_examined=1,
        model_calls=0,
        candidates=(),
        rejected_count=0,
        abstained_count=1,
        safe_error="No candidate survived controlled analysis.",
        created_at=datetime(2026, 8, 15, 12, 1, tzinfo=UTC),
    )
    return suite, report


def test_abstained_report_is_scored_as_false_negative_and_true_negative() -> None:
    suite, report = _suite_and_report(SourceHuntStage.ABSTAINED)

    run = SourceBenchmarkCampaignRunner().run(
        label="abstained-engine",
        engine_revision="c" * 40,
        suite=suite,
        reports={"controlled-abstention-corpus": report},
    )

    assert run.metrics.false_negatives == 1
    assert run.metrics.true_negatives == 1
    assert run.metrics.true_positives == 0
    assert run.metrics.false_positives == 0
    assert run.metrics.recall == 0.0


def test_nonterminal_report_is_rejected_from_benchmark() -> None:
    suite, report = _suite_and_report(SourceHuntStage.SNAPSHOT)

    with pytest.raises(ValueError, match="must be terminal"):
        SourceBenchmarkCampaignRunner().run(
            label="nonterminal-engine",
            engine_revision="d" * 40,
            suite=suite,
            reports={"controlled-abstention-corpus": report},
        )
