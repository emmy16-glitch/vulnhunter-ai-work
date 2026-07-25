"""Deterministic monotonic scrutiny and candidate disposition rules."""

from __future__ import annotations

from vulnhunter.hunt.models import CandidateRecord, CandidateState, CoverageCell, CoverageStatus

_ALLOWED_TRANSITIONS: dict[CandidateState, frozenset[CandidateState]] = {
    CandidateState.GENERATED: frozenset(
        {
            CandidateState.JUDGING,
            CandidateState.EVIDENCE_REQUIRED,
            CandidateState.REJECTED,
        }
    ),
    CandidateState.JUDGING: frozenset(
        {
            CandidateState.EVIDENCE_REQUIRED,
            CandidateState.VERIFIED,
            CandidateState.DOWNGRADED,
            CandidateState.REJECTED,
        }
    ),
    CandidateState.EVIDENCE_REQUIRED: frozenset(
        {
            CandidateState.JUDGING,
            CandidateState.VERIFIED,
            CandidateState.REJECTED,
        }
    ),
    CandidateState.VERIFIED: frozenset(
        {
            CandidateState.CONFIRMED,
            CandidateState.DOWNGRADED,
            CandidateState.REJECTED,
        }
    ),
    CandidateState.CONFIRMED: frozenset({CandidateState.SWEPT}),
    CandidateState.DOWNGRADED: frozenset({CandidateState.SWEPT}),
    CandidateState.REJECTED: frozenset(),
    CandidateState.SWEPT: frozenset(),
}

_EVIDENCE_GATED_STATES = {
    CandidateState.VERIFIED,
    CandidateState.CONFIRMED,
    CandidateState.DOWNGRADED,
    CandidateState.REJECTED,
    CandidateState.SWEPT,
}


def raise_scrutiny(
    cell: CoverageCell,
    *,
    new_level: int,
    evidence_receipt: str,
    status: CoverageStatus | None = None,
) -> CoverageCell:
    """Return a coverage cell whose scrutiny can only increase."""

    if new_level < cell.scrutiny_level:
        raise ValueError("hunt scrutiny cannot be lowered")
    receipt = evidence_receipt.strip()
    if not receipt:
        raise ValueError("raising scrutiny requires an evidence receipt")
    receipts = tuple(dict.fromkeys((*cell.evidence_receipts, receipt)))
    return CoverageCell.model_validate(
        cell.model_copy(
            update={
                "scrutiny_level": new_level,
                "attempts": cell.attempts + 1,
                "evidence_receipts": receipts,
                "status": status or cell.status,
            }
        ).model_dump()
    )


def transition_candidate(
    candidate: CandidateRecord,
    *,
    new_state: CandidateState,
    disposition_reason: str,
    evidence_receipt: str | None = None,
    judge_receipt: str | None = None,
    severity: str | None = None,
) -> CandidateRecord:
    """Apply one certified candidate transition without silent laundering."""

    if new_state not in _ALLOWED_TRANSITIONS[candidate.state]:
        raise ValueError(
            f"candidate transition {candidate.state.value} -> {new_state.value} is not allowed"
        )
    reason = disposition_reason.strip()
    if not reason:
        raise ValueError("candidate transitions require a disposition reason")
    evidence = evidence_receipt.strip() if evidence_receipt else ""
    judge = judge_receipt.strip() if judge_receipt else ""
    if new_state in _EVIDENCE_GATED_STATES and not (evidence or judge):
        raise ValueError("this candidate transition requires an evidence or judge receipt")
    evidence_receipts = tuple(
        dict.fromkeys((*candidate.evidence_receipts, *((evidence,) if evidence else ())))
    )
    judge_receipts = tuple(
        dict.fromkeys((*candidate.judge_receipts, *((judge,) if judge else ())))
    )
    return CandidateRecord.model_validate(
        candidate.model_copy(
            update={
                "state": new_state,
                "severity": severity or candidate.severity,
                "evidence_receipts": evidence_receipts,
                "judge_receipts": judge_receipts,
                "disposition_reason": reason,
            }
        ).model_dump()
    )
