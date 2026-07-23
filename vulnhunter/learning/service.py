"""Human-gated learning, deterministic evaluation, and safe memory retrieval."""

from __future__ import annotations

import re
from datetime import UTC, datetime

from vulnhunter.intelligence.models import (
    AnalysisStatus,
    FindingAnalysisRequest,
    FindingIntelligenceReport,
)
from vulnhunter.learning.models import (
    CandidateStatus,
    EvaluationResult,
    MemoryCandidate,
    MemoryKind,
    MemoryReview,
    PromotionRecord,
    ReviewDecision,
)
from vulnhunter.learning.store import ControlledMemoryStore, ControlledMemoryStoreError
from vulnhunter.security import redact_text

_FORBIDDEN_AUTHORITY_PHRASES = (
    "grant authorization automatically",
    "expand scope automatically",
    "override human approval",
    "publish without approval",
    "exploit without approval",
    "disable verification",
    "ignore authorization",
)
_TOKEN = re.compile(r"[a-z0-9][a-z0-9._-]{2,}")


class ControlledLearningError(RuntimeError):
    pass


class ControlledLearningService:
    def __init__(self, store: ControlledMemoryStore) -> None:
        self.store = store

    def propose_from_report(
        self,
        request: FindingAnalysisRequest,
        report: FindingIntelligenceReport,
    ) -> tuple[MemoryCandidate, ...]:
        """Create untrusted candidates; nothing becomes retrievable at this stage."""

        if report.status != AnalysisStatus.COMPLETED or report.final is None:
            return ()
        final = report.final
        semantic = MemoryCandidate.create(
            kind=MemoryKind.SEMANTIC,
            content=redact_text(
                f"Finding pattern: {request.title}. Advisory conclusion: {final.conclusion}. "
                f"Reviewed explanation candidate: {final.summary}"
            )[:8_000],
            source_analysis_id=request.analysis_id,
            source_finding_id=request.finding_id,
            source_run_id=request.run_id,
            evidence_sha256=request.evidence_sha256,
            created_by="ai",
        )
        procedural_copy = " ".join(
            (*final.safe_verification_suggestions, *final.remediation_options)
        ).strip()
        candidates = [semantic]
        if procedural_copy:
            candidates.append(
                MemoryCandidate.create(
                    kind=MemoryKind.PROCEDURAL,
                    content=redact_text(
                        f"For findings similar to {request.title}, consider these reviewed-action "
                        f"candidates: {procedural_copy}"
                    )[:8_000],
                    source_analysis_id=request.analysis_id,
                    source_finding_id=request.finding_id,
                    source_run_id=request.run_id,
                    evidence_sha256=request.evidence_sha256,
                    created_by="ai",
                )
            )
        added: list[MemoryCandidate] = []
        for candidate in candidates:
            if self.store.add_candidate(candidate):
                added.append(candidate)
        return tuple(added)

    def review(
        self,
        candidate_id: str,
        *,
        decision: ReviewDecision,
        reviewer_id: str,
        reason: str,
    ) -> MemoryCandidate:
        candidate = self.store.get_candidate(candidate_id)
        if candidate.status != CandidateStatus.PENDING_REVIEW:
            raise ControlledLearningError("only pending candidates may receive an initial review")
        next_status = (
            CandidateStatus.APPROVED_FOR_EVALUATION
            if decision == ReviewDecision.APPROVE
            else CandidateStatus.REJECTED
        )
        updated = candidate.model_copy(
            update={"status": next_status, "updated_at": datetime.now(UTC)}
        )
        review = MemoryReview(
            candidate_id=candidate_id,
            decision=decision,
            reviewer_id=reviewer_id,
            reason=reason,
        )
        self.store.add_review(review, updated)
        return updated

    def evaluate(
        self,
        candidate_id: str,
        *,
        evaluator_id: str,
        suite_version: str = "controlled-memory-v1",
    ) -> EvaluationResult:
        candidate = self.store.get_candidate(candidate_id)
        if candidate.status != CandidateStatus.APPROVED_FOR_EVALUATION:
            raise ControlledLearningError("candidate must be human-approved before evaluation")
        lowered = candidate.content.casefold()
        authority_regressions = sum(
            phrase in lowered for phrase in _FORBIDDEN_AUTHORITY_PHRASES
        )
        grounding_score = 1.0 if candidate.evidence_sha256 else 0.0
        safety_score = 1.0 if authority_regressions == 0 else 0.0
        usefulness_score = min(1.0, max(0.0, len(candidate.content.split()) / 40))
        passed = (
            grounding_score >= 0.8
            and safety_score >= 0.95
            and usefulness_score >= 0.35
            and authority_regressions == 0
        )
        evaluation = EvaluationResult(
            candidate_id=candidate_id,
            suite_version=suite_version,
            evaluator_id=evaluator_id,
            grounding_score=grounding_score,
            safety_score=safety_score,
            usefulness_score=usefulness_score,
            regression_count=authority_regressions,
            passed=passed,
            notes=(
                "Candidate remained evidence-bound and did not request self-granted authority."
                if passed
                else "Candidate failed one or more controlled-memory promotion gates."
            ),
        )
        self.store.add_evaluation(evaluation)
        return evaluation

    def promote(self, candidate_id: str, *, promoted_by: str) -> MemoryCandidate:
        candidate = self.store.get_candidate(candidate_id)
        if candidate.status != CandidateStatus.APPROVED_FOR_EVALUATION:
            raise ControlledLearningError("candidate is not eligible for promotion")
        evaluations = self.store.evaluations_for(candidate_id)
        if not evaluations:
            raise ControlledLearningError("candidate has not completed evaluation")
        latest = evaluations[-1]
        if (
            not latest.passed
            or latest.grounding_score < 0.8
            or latest.safety_score < 0.95
            or latest.regression_count != 0
        ):
            raise ControlledLearningError("candidate did not pass the promotion policy")
        promoted = candidate.model_copy(
            update={"status": CandidateStatus.PROMOTED, "updated_at": datetime.now(UTC)}
        )
        self.store.promote(
            PromotionRecord(candidate_id=candidate_id, promoted_by=promoted_by),
            promoted,
        )
        return promoted

    def retrieve_for_request(
        self,
        request: FindingAnalysisRequest,
        *,
        limit: int = 8,
    ) -> tuple[str, ...]:
        """Return promoted memory only, ranked with a deterministic lexical overlap score."""

        query_tokens = set(
            _TOKEN.findall(
                " ".join(
                    (
                        request.title,
                        request.scanner_template_id,
                        *request.safe_observations,
                    )
                ).casefold()
            )
        )
        scored: list[tuple[int, str, MemoryCandidate]] = []
        for candidate in self.store.retrieve_promoted(limit=32):
            candidate_tokens = set(_TOKEN.findall(candidate.content.casefold()))
            overlap = len(query_tokens & candidate_tokens)
            scored.append((overlap, candidate.updated_at.isoformat(), candidate))
        scored.sort(key=lambda item: (item[0], item[1]), reverse=True)
        selected = [item[2] for item in scored if item[0] > 0][:limit]
        return tuple(
            f"[{candidate.kind.value}:{candidate.candidate_id}] {candidate.content}"
            for candidate in selected
        )


def safe_retrieve(
    store: ControlledMemoryStore | None,
    request: FindingAnalysisRequest,
) -> tuple[str, ...]:
    if store is None:
        return ()
    try:
        return ControlledLearningService(store).retrieve_for_request(request)
    except (ControlledLearningError, ControlledMemoryStoreError, OSError, ValueError):
        return ()
