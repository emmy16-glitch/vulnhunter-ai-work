"""Deterministic ground-truth evaluation for Source Hunt reports.

This benchmark intentionally supports only synthetic and controlled-laboratory corpora.
Its metrics must never be represented as production accuracy.
"""

from __future__ import annotations

import hashlib
import json
import re
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator

from vulnhunter.source_hunt.models import CandidateDisposition, SourceCandidate, SourceHuntReport


class BenchmarkCorpusKind(StrEnum):
    SYNTHETIC = "synthetic"
    CONTROLLED_LAB = "controlled_lab"


class SourceGroundTruthCase(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    case_id: str = Field(pattern=r"^[A-Za-z0-9._-]{2,128}$")
    vulnerability_class: str = Field(min_length=2, max_length=80)
    path: str = Field(min_length=1, max_length=512)
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    expected_vulnerable: bool

    @model_validator(mode="after")
    def validate_lines(self) -> SourceGroundTruthCase:
        if self.line_end < self.line_start:
            raise ValueError("ground-truth line range is invalid")
        return self


class SourceBenchmarkCorpus(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    corpus_id: str = Field(pattern=r"^[A-Za-z0-9._-]{2,128}$")
    kind: BenchmarkCorpusKind
    cases: tuple[SourceGroundTruthCase, ...]
    corpus_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def create(
        cls,
        *,
        corpus_id: str,
        kind: BenchmarkCorpusKind,
        cases: tuple[SourceGroundTruthCase, ...],
    ) -> SourceBenchmarkCorpus:
        if not cases:
            raise ValueError("source benchmark corpus cannot be empty")
        case_ids = [case.case_id for case in cases]
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("source benchmark case identifiers must be unique")
        canonical = {
            "corpus_id": corpus_id,
            "kind": kind.value,
            "cases": [case.model_dump(mode="json") for case in cases],
        }
        digest = hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return cls(corpus_id=corpus_id, kind=kind, cases=cases, corpus_sha256=digest)

    @model_validator(mode="after")
    def verify_digest(self) -> SourceBenchmarkCorpus:
        canonical = {
            "corpus_id": self.corpus_id,
            "kind": self.kind.value,
            "cases": [case.model_dump(mode="json") for case in self.cases],
        }
        digest = hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        if digest != self.corpus_sha256:
            raise ValueError("source benchmark corpus digest does not match its contents")
        return self


class SourceBenchmarkMetrics(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    true_positives: int = Field(ge=0)
    false_positives: int = Field(ge=0)
    false_negatives: int = Field(ge=0)
    true_negatives: int = Field(ge=0)
    precision: float = Field(ge=0, le=1)
    recall: float = Field(ge=0, le=1)
    f1: float = Field(ge=0, le=1)


class SourceBenchmarkCaseResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    case_id: str
    expected_vulnerable: bool
    detected: bool
    matched_candidate_ids: tuple[str, ...]


class SourceBenchmarkReport(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    corpus_id: str
    corpus_kind: BenchmarkCorpusKind
    corpus_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_report_id: str
    source_snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    metrics: SourceBenchmarkMetrics
    case_results: tuple[SourceBenchmarkCaseResult, ...]
    unmatched_candidate_ids: tuple[str, ...]
    production_accuracy_claim_permitted: bool = False


class SourceHuntBenchmarkEvaluator:
    """Match survived evidence-bound candidates to immutable lab ground truth."""

    def evaluate(
        self,
        *,
        report: SourceHuntReport,
        corpus: SourceBenchmarkCorpus,
    ) -> SourceBenchmarkReport:
        candidates = tuple(self._survived(report))
        candidate_matches: dict[int, set[str]] = {index: set() for index in range(len(candidates))}
        case_results: list[SourceBenchmarkCaseResult] = []
        tp = fp = fn = tn = 0

        for case in corpus.cases:
            matched_indexes = tuple(
                index
                for index, candidate in enumerate(candidates)
                if self._matches(case, candidate)
            )
            detected = bool(matched_indexes)
            for index in matched_indexes:
                candidate_matches[index].add(case.case_id)
            matched_ids = tuple(candidates[index].candidate_id for index in matched_indexes)
            case_results.append(
                SourceBenchmarkCaseResult(
                    case_id=case.case_id,
                    expected_vulnerable=case.expected_vulnerable,
                    detected=detected,
                    matched_candidate_ids=matched_ids,
                )
            )
            if case.expected_vulnerable and detected:
                tp += 1
            elif case.expected_vulnerable and not detected:
                fn += 1
            elif not case.expected_vulnerable and detected:
                fp += 1
            else:
                tn += 1

        unmatched = tuple(
            candidate.candidate_id
            for index, candidate in enumerate(candidates)
            if not candidate_matches[index]
        )
        fp += len(unmatched)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

        return SourceBenchmarkReport(
            corpus_id=corpus.corpus_id,
            corpus_kind=corpus.kind,
            corpus_sha256=corpus.corpus_sha256,
            source_report_id=report.report_id,
            source_snapshot_sha256=report.snapshot.snapshot_sha256,
            metrics=SourceBenchmarkMetrics(
                true_positives=tp,
                false_positives=fp,
                false_negatives=fn,
                true_negatives=tn,
                precision=precision,
                recall=recall,
                f1=f1,
            ),
            case_results=tuple(case_results),
            unmatched_candidate_ids=unmatched,
        )

    @staticmethod
    def _survived(report: SourceHuntReport):
        for candidate in report.candidates:
            if (
                candidate.falsification.disposition == CandidateDisposition.SURVIVED
                and candidate.capability is not None
                and candidate.capability.meaningful
            ):
                yield candidate

    @staticmethod
    def _normalize_class(value: str) -> str:
        return re.sub(r"[^a-z0-9]+", "", value.lower())

    def _matches(self, case: SourceGroundTruthCase, candidate: SourceCandidate) -> bool:
        if self._normalize_class(case.vulnerability_class) != self._normalize_class(
            candidate.hypothesis.vulnerability_class
        ):
            return False
        references = (
            candidate.hypothesis.entry_point,
            candidate.hypothesis.sink,
            *candidate.hypothesis.path,
            *candidate.hypothesis.evidence_refs,
        )
        return any(
            reference.path == case.path
            and reference.line_start <= case.line_end
            and reference.line_end >= case.line_start
            for reference in references
        )
