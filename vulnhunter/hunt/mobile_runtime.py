"""Deterministic candidate, judge, verify and variant-sweep loop for APK evidence."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from vulnhunter.actions.models import sha256_json
from vulnhunter.hunt.ledger import transition_candidate
from vulnhunter.hunt.models import CandidateRecord, CandidateState, HuntAltitude
from vulnhunter.mobile.static_worker import MobileStaticAnalysisResult

_VERIFIED_STATUSES = {
    "verified",
    "verified_configuration",
    "verified_content",
    "deterministic",
}
_REJECTED_STATUSES = {"operational_failure", "rejected", "tool_failure"}


class MobileHuntCandidateReceipt(BaseModel):
    """One evidence-bound candidate disposition safe for the chat projection."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    candidate_id: str
    weakness_id: str
    title: str
    severity: str
    state: CandidateState
    confidence: str = "unknown"
    source_status: str = "candidate"
    component: str | None = None
    tool_ids: tuple[str, ...] = ()
    evidence_receipts: tuple[str, ...] = ()
    judge_receipts: tuple[str, ...] = ()
    disposition_reason: str


class MobileHuntRoundReceipt(BaseModel):
    """One completed bounded hunt pass."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    round_index: int = Field(ge=1)
    altitude: HuntAltitude
    label: str
    input_count: int = Field(ge=0)
    net_new_count: int = Field(ge=0)
    evidence_receipts: tuple[str, ...] = ()


class MobileHuntExecutionReceipt(BaseModel):
    """Terminal receipt for the deterministic portion of a Raptor-style loop."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    iterations: int = Field(ge=1, le=8)
    rounds: tuple[MobileHuntRoundReceipt, ...]
    candidates: tuple[MobileHuntCandidateReceipt, ...]
    verified_count: int = Field(ge=0)
    evidence_required_count: int = Field(ge=0)
    rejected_count: int = Field(ge=0)
    stop_reason: str
    receipt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


def _observation_receipt(observation: dict[str, object]) -> str:
    return f"observation:{sha256_json(observation)}"


def _candidate_from_observation(
    observation: dict[str, object],
    *,
    index: int,
) -> CandidateRecord:
    observation_receipt = _observation_receipt(observation)
    candidate_id = str(observation.get("observation_id") or f"mobile-candidate-{index:04d}")
    weakness_id = str(observation.get("weakness_id") or "mobile-observation")
    return CandidateRecord(
        candidate_id=candidate_id,
        weakness_id=weakness_id,
        title=str(observation.get("title") or "Candidate mobile observation"),
        component=(str(observation["component"]) if observation.get("component") else None),
        severity=str(observation.get("severity") or "unknown"),
        evidence_receipts=(observation_receipt,),
    )


def _judge_candidate(
    candidate: CandidateRecord,
    observation: dict[str, object],
) -> CandidateRecord:
    observation_receipt = candidate.evidence_receipts[0]
    judge_payload = {
        "candidate": candidate.candidate_id,
        "evidence": observation_receipt,
        "source_status": str(observation.get("status") or "candidate"),
    }
    judge_receipt = f"judge:{sha256_json(judge_payload)}"
    judging = transition_candidate(
        candidate,
        new_state=CandidateState.JUDGING,
        disposition_reason="Independent deterministic judge opened the raw observation receipt.",
        judge_receipt=judge_receipt,
    )
    source_status = str(observation.get("status") or "candidate").casefold()
    title = candidate.title.casefold()
    if source_status in _REJECTED_STATUSES or "could not complete static inspection" in title:
        return transition_candidate(
            judging,
            new_state=CandidateState.REJECTED,
            disposition_reason=(
                "A tool execution failure is operational evidence, not a vulnerability finding."
            ),
            evidence_receipt=observation_receipt,
            judge_receipt=judge_receipt,
        )
    has_evidence = isinstance(observation.get("evidence"), dict) and bool(
        observation.get("evidence")
    )
    if source_status in _VERIFIED_STATUSES and observation.get("weakness_id") and has_evidence:
        return transition_candidate(
            judging,
            new_state=CandidateState.VERIFIED,
            disposition_reason=(
                "The evidence deterministically supports the reported content or configuration "
                "condition; exploitability and impact remain unconfirmed."
            ),
            evidence_receipt=observation_receipt,
            judge_receipt=judge_receipt,
        )
    return transition_candidate(
        judging,
        new_state=CandidateState.EVIDENCE_REQUIRED,
        disposition_reason=(
            "The observation is real, but its presence alone does not establish a security "
            "weakness, reachability or impact."
        ),
        evidence_receipt=observation_receipt,
        judge_receipt=judge_receipt,
    )


def _receipt(
    candidate: CandidateRecord,
    observation: dict[str, object],
) -> MobileHuntCandidateReceipt:
    raw_tools = observation.get("tool_ids")
    tools = (
        tuple(str(item) for item in raw_tools if isinstance(item, str))
        if isinstance(raw_tools, (list, tuple))
        else ()
    )
    return MobileHuntCandidateReceipt(
        candidate_id=candidate.candidate_id,
        weakness_id=candidate.weakness_id,
        title=candidate.title,
        severity=candidate.severity,
        state=candidate.state,
        confidence=str(observation.get("confidence") or observation.get("status") or "unknown"),
        source_status=str(observation.get("status") or "candidate"),
        component=candidate.component,
        tool_ids=tools,
        evidence_receipts=candidate.evidence_receipts,
        judge_receipts=candidate.judge_receipts,
        disposition_reason=candidate.disposition_reason or "No disposition was recorded.",
    )


def run_mobile_evidence_hunt(
    result: MobileStaticAnalysisResult,
) -> MobileHuntExecutionReceipt:
    """Run two bounded passes and stop when the variant sweep adds no candidates."""

    if result.intelligence is not None:
        observations = tuple(
            {
                **item.model_dump(mode="json"),
                "observation_id": item.record_id,
                "status": item.evidence_state.value,
                "evidence": dict(item.details.get("evidence_metadata", {}))
                if isinstance(item.details.get("evidence_metadata"), dict)
                else {},
                "tool_ids": list(item.evidence_references),
            }
            for item in result.intelligence.candidates
        )
    else:
        observations = tuple(result.candidate_observations)
    capture_receipts = tuple(f"tool:{item.tool}:{item.output_sha256}" for item in result.captures)
    candidates = tuple(
        _judge_candidate(_candidate_from_observation(item, index=index), item)
        for index, item in enumerate(observations, start=1)
    )
    candidate_receipts = tuple(
        _receipt(candidate, observation)
        for candidate, observation in zip(candidates, observations, strict=True)
    )

    variant_keys = {
        (item.weakness_id, item.component, item.title.casefold()) for item in candidate_receipts
    }
    net_new_variants = max(0, len(variant_keys) - len(candidate_receipts))
    rounds = (
        MobileHuntRoundReceipt(
            round_index=1,
            altitude=HuntAltitude.VERIFICATION,
            label="Generate, judge and verify raw static observations",
            input_count=len(observations),
            net_new_count=len(candidate_receipts),
            evidence_receipts=capture_receipts,
        ),
        MobileHuntRoundReceipt(
            round_index=2,
            altitude=HuntAltitude.VARIANT_SWEEP,
            label="Deduplicate weakness/component variants and check for net-new coverage",
            input_count=len(candidate_receipts),
            net_new_count=net_new_variants,
            evidence_receipts=tuple(
                receipt for item in candidate_receipts for receipt in item.evidence_receipts
            ),
        ),
    )
    verified_count = sum(item.state == CandidateState.VERIFIED for item in candidate_receipts)
    evidence_required_count = sum(
        item.state == CandidateState.EVIDENCE_REQUIRED for item in candidate_receipts
    )
    rejected_count = sum(item.state == CandidateState.REJECTED for item in candidate_receipts)
    if not observations:
        stop_reason = "No deterministic candidate observations were generated by the active tools."
    else:
        stop_reason = (
            "The variant sweep produced no net-new candidate identities; deeper code or runtime "
            "coverage requires an additional approved tool stage."
        )
    unsigned = {
        "iterations": 2,
        "rounds": [item.model_dump(mode="json") for item in rounds],
        "candidates": [item.model_dump(mode="json") for item in candidate_receipts],
        "verified_count": verified_count,
        "evidence_required_count": evidence_required_count,
        "rejected_count": rejected_count,
        "stop_reason": stop_reason,
    }
    return MobileHuntExecutionReceipt(
        **unsigned,
        receipt_sha256=sha256_json(unsigned),
    )


__all__ = [
    "MobileHuntCandidateReceipt",
    "MobileHuntExecutionReceipt",
    "MobileHuntRoundReceipt",
    "run_mobile_evidence_hunt",
]
