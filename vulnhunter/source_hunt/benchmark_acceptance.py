"""Deterministic acceptance policy for controlled Source Hunt benchmark campaigns."""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator

from vulnhunter.source_hunt.benchmark_v2 import (
    BenchmarkCorpusKind,
    SourceBenchmarkCorpus,
    SourceBenchmarkMetrics,
    SourceHuntBenchmarkEvaluator,
)
from vulnhunter.source_hunt.models import SourceHuntReport, SourceHuntStage


def _canonical_sha256(payload: object) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _report_sha256(report: SourceHuntReport) -> str:
    return _canonical_sha256(report.model_dump(mode="json"))


def _aggregate_metrics(metrics: tuple[SourceBenchmarkMetrics, ...]) -> SourceBenchmarkMetrics:
    tp = sum(item.true_positives for item in metrics)
    fp = sum(item.false_positives for item in metrics)
    fn = sum(item.false_negatives for item in metrics)
    tn = sum(item.true_negatives for item in metrics)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return SourceBenchmarkMetrics(
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        true_negatives=tn,
        precision=precision,
        recall=recall,
        f1=f1,
    )


class BenchmarkAcceptanceVerdict(StrEnum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"


class SourceBenchmarkSuiteEntry(BaseModel):
    """One immutable ground-truth corpus bound to an exact fixture snapshot."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    corpus: SourceBenchmarkCorpus
    repository_id: str = Field(min_length=2, max_length=128)
    source_revision: str = Field(min_length=1, max_length=128)
    snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class SourceBenchmarkSuite(BaseModel):
    """A tamper-evident benchmark suite whose fixture set cannot be cherry-picked per run."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    suite_id: str = Field(pattern=r"^[A-Za-z0-9._-]{2,128}$")
    entries: tuple[SourceBenchmarkSuiteEntry, ...]
    suite_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def create(
        cls,
        *,
        suite_id: str,
        entries: tuple[SourceBenchmarkSuiteEntry, ...],
    ) -> SourceBenchmarkSuite:
        if not entries:
            raise ValueError("source benchmark suite cannot be empty")
        corpus_ids = [entry.corpus.corpus_id for entry in entries]
        if len(corpus_ids) != len(set(corpus_ids)):
            raise ValueError("source benchmark suite corpus identifiers must be unique")
        canonical = {
            "suite_id": suite_id,
            "entries": [entry.model_dump(mode="json") for entry in entries],
        }
        return cls(
            suite_id=suite_id,
            entries=entries,
            suite_sha256=_canonical_sha256(canonical),
        )

    @model_validator(mode="after")
    def verify_digest(self) -> SourceBenchmarkSuite:
        if not self.entries:
            raise ValueError("source benchmark suite cannot be empty")
        corpus_ids = [entry.corpus.corpus_id for entry in self.entries]
        if len(corpus_ids) != len(set(corpus_ids)):
            raise ValueError("source benchmark suite corpus identifiers must be unique")
        canonical = {
            "suite_id": self.suite_id,
            "entries": [entry.model_dump(mode="json") for entry in self.entries],
        }
        if _canonical_sha256(canonical) != self.suite_sha256:
            raise ValueError("source benchmark suite digest does not match its contents")
        return self


class SourceBenchmarkAcceptancePolicy(BaseModel):
    """Absolute and baseline-relative gates for promoting a Source Hunt engine revision."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    policy_id: str = Field(pattern=r"^[A-Za-z0-9._-]{2,128}$")
    minimum_cases: int = Field(ge=1)
    minimum_controlled_lab_cases: int = Field(ge=0)
    minimum_precision: float = Field(ge=0, le=1)
    minimum_recall: float = Field(ge=0, le=1)
    minimum_f1: float = Field(ge=0, le=1)
    maximum_false_positives: int = Field(ge=0)
    maximum_false_negatives: int = Field(ge=0)
    maximum_new_false_positives: int = Field(ge=0, default=0)
    maximum_new_false_negatives: int = Field(ge=0, default=0)
    maximum_precision_regression: float = Field(ge=0, le=1, default=0.0)
    maximum_recall_regression: float = Field(ge=0, le=1, default=0.0)
    maximum_f1_regression: float = Field(ge=0, le=1, default=0.0)
    policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def create(
        cls,
        *,
        policy_id: str,
        minimum_cases: int,
        minimum_controlled_lab_cases: int,
        minimum_precision: float,
        minimum_recall: float,
        minimum_f1: float,
        maximum_false_positives: int,
        maximum_false_negatives: int,
        maximum_new_false_positives: int = 0,
        maximum_new_false_negatives: int = 0,
        maximum_precision_regression: float = 0.0,
        maximum_recall_regression: float = 0.0,
        maximum_f1_regression: float = 0.0,
    ) -> SourceBenchmarkAcceptancePolicy:
        canonical = {
            "policy_id": policy_id,
            "minimum_cases": int(minimum_cases),
            "minimum_controlled_lab_cases": int(minimum_controlled_lab_cases),
            "minimum_precision": float(minimum_precision),
            "minimum_recall": float(minimum_recall),
            "minimum_f1": float(minimum_f1),
            "maximum_false_positives": int(maximum_false_positives),
            "maximum_false_negatives": int(maximum_false_negatives),
            "maximum_new_false_positives": int(maximum_new_false_positives),
            "maximum_new_false_negatives": int(maximum_new_false_negatives),
            "maximum_precision_regression": float(maximum_precision_regression),
            "maximum_recall_regression": float(maximum_recall_regression),
            "maximum_f1_regression": float(maximum_f1_regression),
        }
        return cls(**canonical, policy_sha256=_canonical_sha256(canonical))

    @model_validator(mode="after")
    def verify_digest(self) -> SourceBenchmarkAcceptancePolicy:
        canonical = self.model_dump(mode="json", exclude={"policy_sha256"})
        if _canonical_sha256(canonical) != self.policy_sha256:
            raise ValueError(
                "source benchmark acceptance policy digest does not match its contents"
            )
        return self


class SourceBenchmarkRunItem(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    corpus_id: str
    corpus_kind: BenchmarkCorpusKind
    corpus_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    repository_id: str
    source_revision: str
    snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_report_id: str
    source_report_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    metrics: SourceBenchmarkMetrics
    unmatched_candidate_ids: tuple[str, ...]


class SourceBenchmarkCampaignRun(BaseModel):
    """One deterministic engine-revision evaluation over the complete benchmark suite."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    run_id: str = Field(pattern=r"^source-benchmark-run-[0-9a-f]{24}$")
    label: str = Field(pattern=r"^[A-Za-z0-9._-]{2,64}$")
    engine_revision: str = Field(pattern=r"^[0-9a-f]{40,64}$")
    suite_id: str
    suite_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    items: tuple[SourceBenchmarkRunItem, ...]
    metrics: SourceBenchmarkMetrics
    total_cases: int = Field(ge=1)
    controlled_lab_cases: int = Field(ge=0)
    synthetic_cases: int = Field(ge=0)
    run_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    production_accuracy_claim_permitted: bool = False

    @model_validator(mode="after")
    def verify_digest(self) -> SourceBenchmarkCampaignRun:
        canonical = self.model_dump(mode="json", exclude={"run_id", "run_sha256"})
        digest = _canonical_sha256(canonical)
        if digest != self.run_sha256:
            raise ValueError("source benchmark campaign run digest does not match its contents")
        if self.run_id != f"source-benchmark-run-{digest[:24]}":
            raise ValueError("source benchmark campaign run identifier does not match its digest")
        if self.total_cases != self.controlled_lab_cases + self.synthetic_cases:
            raise ValueError("source benchmark campaign case counts are inconsistent")
        return self


class SourceBenchmarkAcceptanceResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    verdict: BenchmarkAcceptanceVerdict
    reasons: tuple[str, ...]
    policy_id: str
    policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    suite_id: str
    suite_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    baseline_run_id: str
    baseline_run_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_run_id: str
    candidate_run_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    precision_delta: float
    recall_delta: float
    f1_delta: float
    result_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    production_accuracy_claim_permitted: bool = False

    @model_validator(mode="after")
    def verify_digest(self) -> SourceBenchmarkAcceptanceResult:
        canonical = self.model_dump(mode="json", exclude={"result_sha256"})
        if _canonical_sha256(canonical) != self.result_sha256:
            raise ValueError(
                "source benchmark acceptance result digest does not match its contents"
            )
        return self


class SourceBenchmarkAcceptanceBundle(BaseModel):
    """Integrity-linked evidence for one baseline-versus-candidate promotion decision."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    baseline: SourceBenchmarkCampaignRun
    candidate: SourceBenchmarkCampaignRun
    acceptance: SourceBenchmarkAcceptanceResult
    bundle_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    production_accuracy_claim_permitted: bool = False

    @classmethod
    def create(
        cls,
        *,
        baseline: SourceBenchmarkCampaignRun,
        candidate: SourceBenchmarkCampaignRun,
        acceptance: SourceBenchmarkAcceptanceResult,
    ) -> SourceBenchmarkAcceptanceBundle:
        canonical = {
            "baseline": baseline.model_dump(mode="json"),
            "candidate": candidate.model_dump(mode="json"),
            "acceptance": acceptance.model_dump(mode="json"),
            "production_accuracy_claim_permitted": False,
        }
        return cls(
            baseline=baseline,
            candidate=candidate,
            acceptance=acceptance,
            bundle_sha256=_canonical_sha256(canonical),
        )

    @model_validator(mode="after")
    def verify_digest(self) -> SourceBenchmarkAcceptanceBundle:
        canonical = self.model_dump(mode="json", exclude={"bundle_sha256"})
        if _canonical_sha256(canonical) != self.bundle_sha256:
            raise ValueError(
                "source benchmark acceptance bundle digest does not match its contents"
            )
        if self.acceptance.baseline_run_sha256 != self.baseline.run_sha256:
            raise ValueError("acceptance result is not bound to the supplied baseline run")
        if self.acceptance.candidate_run_sha256 != self.candidate.run_sha256:
            raise ValueError("acceptance result is not bound to the supplied candidate run")
        return self


class SourceBenchmarkCampaignRunner:
    """Evaluate already-produced Source Hunt reports without executing a scan or model call."""

    def __init__(self, evaluator: SourceHuntBenchmarkEvaluator | None = None) -> None:
        self.evaluator = evaluator or SourceHuntBenchmarkEvaluator()

    def run(
        self,
        *,
        label: str,
        engine_revision: str,
        suite: SourceBenchmarkSuite,
        reports: dict[str, SourceHuntReport],
    ) -> SourceBenchmarkCampaignRun:
        expected_ids = {entry.corpus.corpus_id for entry in suite.entries}
        if set(reports) != expected_ids:
            missing = sorted(expected_ids - set(reports))
            extra = sorted(set(reports) - expected_ids)
            raise ValueError(
                f"source benchmark report set does not match suite; missing={missing}, "
                f"extra={extra}"
            )

        items: list[SourceBenchmarkRunItem] = []
        benchmark_metrics: list[SourceBenchmarkMetrics] = []
        controlled_lab_cases = 0
        synthetic_cases = 0

        for entry in suite.entries:
            report = reports[entry.corpus.corpus_id]
            if report.stage != SourceHuntStage.COMPLETE:
                raise ValueError("source benchmark reports must be complete")
            snapshot = report.snapshot
            if (
                snapshot.repository_id != entry.repository_id
                or snapshot.revision != entry.source_revision
                or snapshot.snapshot_sha256 != entry.snapshot_sha256
            ):
                raise ValueError(
                    f"source benchmark report for {entry.corpus.corpus_id} does not match "
                    "the suite fixture binding"
                )
            evaluated = self.evaluator.evaluate(report=report, corpus=entry.corpus)
            benchmark_metrics.append(evaluated.metrics)
            if entry.corpus.kind == BenchmarkCorpusKind.CONTROLLED_LAB:
                controlled_lab_cases += len(entry.corpus.cases)
            else:
                synthetic_cases += len(entry.corpus.cases)
            items.append(
                SourceBenchmarkRunItem(
                    corpus_id=entry.corpus.corpus_id,
                    corpus_kind=entry.corpus.kind,
                    corpus_sha256=entry.corpus.corpus_sha256,
                    repository_id=entry.repository_id,
                    source_revision=entry.source_revision,
                    snapshot_sha256=entry.snapshot_sha256,
                    source_report_id=report.report_id,
                    source_report_sha256=_report_sha256(report),
                    metrics=evaluated.metrics,
                    unmatched_candidate_ids=evaluated.unmatched_candidate_ids,
                )
            )

        total_cases = controlled_lab_cases + synthetic_cases
        metrics = _aggregate_metrics(tuple(benchmark_metrics))
        canonical = {
            "label": label,
            "engine_revision": engine_revision,
            "suite_id": suite.suite_id,
            "suite_sha256": suite.suite_sha256,
            "items": [item.model_dump(mode="json") for item in items],
            "metrics": metrics.model_dump(mode="json"),
            "total_cases": total_cases,
            "controlled_lab_cases": controlled_lab_cases,
            "synthetic_cases": synthetic_cases,
            "production_accuracy_claim_permitted": False,
        }
        digest = _canonical_sha256(canonical)
        return SourceBenchmarkCampaignRun(
            run_id=f"source-benchmark-run-{digest[:24]}",
            run_sha256=digest,
            **canonical,
        )


class SourceBenchmarkAcceptanceEvaluator:
    """Apply immutable absolute and regression gates to two runs of the same suite."""

    def evaluate(
        self,
        *,
        policy: SourceBenchmarkAcceptancePolicy,
        baseline: SourceBenchmarkCampaignRun,
        candidate: SourceBenchmarkCampaignRun,
    ) -> SourceBenchmarkAcceptanceResult:
        if baseline.suite_sha256 != candidate.suite_sha256:
            raise ValueError("baseline and candidate benchmark runs must use the exact same suite")
        if baseline.engine_revision == candidate.engine_revision:
            raise ValueError("baseline and candidate engine revisions must be distinct")

        reasons: list[str] = []
        metrics = candidate.metrics
        baseline_metrics = baseline.metrics
        if candidate.total_cases < policy.minimum_cases:
            reasons.append("candidate benchmark run does not meet the minimum case count")
        if candidate.controlled_lab_cases < policy.minimum_controlled_lab_cases:
            reasons.append("candidate benchmark run does not meet the controlled-lab case minimum")
        if metrics.precision < policy.minimum_precision:
            reasons.append("candidate precision is below the acceptance minimum")
        if metrics.recall < policy.minimum_recall:
            reasons.append("candidate recall is below the acceptance minimum")
        if metrics.f1 < policy.minimum_f1:
            reasons.append("candidate F1 is below the acceptance minimum")
        if metrics.false_positives > policy.maximum_false_positives:
            reasons.append("candidate false positives exceed the acceptance maximum")
        if metrics.false_negatives > policy.maximum_false_negatives:
            reasons.append("candidate false negatives exceed the acceptance maximum")
        if (
            metrics.false_positives - baseline_metrics.false_positives
            > policy.maximum_new_false_positives
        ):
            reasons.append("candidate introduces too many new false positives versus baseline")
        if (
            metrics.false_negatives - baseline_metrics.false_negatives
            > policy.maximum_new_false_negatives
        ):
            reasons.append("candidate introduces too many new false negatives versus baseline")

        precision_delta = metrics.precision - baseline_metrics.precision
        recall_delta = metrics.recall - baseline_metrics.recall
        f1_delta = metrics.f1 - baseline_metrics.f1
        if -precision_delta > policy.maximum_precision_regression:
            reasons.append("candidate precision regression exceeds policy")
        if -recall_delta > policy.maximum_recall_regression:
            reasons.append("candidate recall regression exceeds policy")
        if -f1_delta > policy.maximum_f1_regression:
            reasons.append("candidate F1 regression exceeds policy")

        verdict = (
            BenchmarkAcceptanceVerdict.ACCEPTED
            if not reasons
            else BenchmarkAcceptanceVerdict.REJECTED
        )
        canonical = {
            "verdict": verdict.value,
            "reasons": reasons,
            "policy_id": policy.policy_id,
            "policy_sha256": policy.policy_sha256,
            "suite_id": candidate.suite_id,
            "suite_sha256": candidate.suite_sha256,
            "baseline_run_id": baseline.run_id,
            "baseline_run_sha256": baseline.run_sha256,
            "candidate_run_id": candidate.run_id,
            "candidate_run_sha256": candidate.run_sha256,
            "precision_delta": precision_delta,
            "recall_delta": recall_delta,
            "f1_delta": f1_delta,
            "production_accuracy_claim_permitted": False,
        }
        return SourceBenchmarkAcceptanceResult(
            result_sha256=_canonical_sha256(canonical),
            **canonical,
        )
