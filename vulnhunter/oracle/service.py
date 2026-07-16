"""Deterministic Machine Oracle verification service."""

from __future__ import annotations

from datetime import UTC, datetime

from vulnhunter.actions.models import sha256_json
from vulnhunter.oracle.models import (
    OracleResponse,
    OracleVerdict,
    ProofCapsule,
    VerificationStrategy,
)


class OracleVerificationError(RuntimeError):
    pass


class OracleVerifier:
    """Execute deterministic verification only over proof-capsule references."""

    def verify(
        self,
        capsule: ProofCapsule,
        *,
        verifier_identity: str,
        verifier_version: str = "internal-deterministic-1",
        strategy: VerificationStrategy | None = None,
        now: datetime | None = None,
    ) -> OracleResponse:
        instant = now or datetime.now(UTC)
        selected = strategy or self.preferred_strategy(capsule)
        if selected not in capsule.permitted_strategies:
            raise OracleVerificationError("verification strategy is not permitted by the capsule")
        if verifier_identity == capsule.claim_author:
            verdict = OracleVerdict.VERIFICATION_BLOCKED
        elif instant >= capsule.expires_at:
            verdict = OracleVerdict.EXPIRED
        elif (
            selected == VerificationStrategy.MODEL_ASSISTED_REVIEW
            and capsule.finding_claim.consequential
        ):
            verdict = OracleVerdict.INSUFFICIENT_EVIDENCE
        else:
            verdict = self._deterministic_verdict(capsule)

        draft = {
            "response_id": f"oracle-response-{capsule.capsule_id}",
            "capsule_sha256": capsule.capsule_hash(),
            "verdict": verdict,
            "strategy": selected,
            "verifier_identity": verifier_identity,
            "verifier_version": verifier_version,
            "independence_strength": self.independence_strength(selected),
            "evidence_hashes": capsule.evidence_hashes if verdict == OracleVerdict.VERIFIED else (),
            "response_hash": "0" * 64,
            "created_at": instant,
        }
        temporary = OracleResponse.model_validate(draft)
        return temporary.model_copy(update={"response_hash": temporary.expected_hash()})

    @staticmethod
    def preferred_strategy(capsule: ProofCapsule) -> VerificationStrategy:
        deterministic = (
            VerificationStrategy.DETERMINISTIC_REPLAY,
            VerificationStrategy.EVIDENCE_CONSISTENCY_CHECK,
            VerificationStrategy.INDEPENDENT_RULE_VALIDATION,
        )
        for strategy in deterministic:
            if strategy in capsule.permitted_strategies:
                return strategy
        return capsule.permitted_strategies[0]

    @staticmethod
    def independence_strength(strategy: VerificationStrategy) -> str:
        if strategy in {
            VerificationStrategy.DETERMINISTIC_REPLAY,
            VerificationStrategy.EVIDENCE_CONSISTENCY_CHECK,
            VerificationStrategy.INDEPENDENT_RULE_VALIDATION,
        }:
            return "deterministic"
        if strategy == VerificationStrategy.MODEL_ASSISTED_REVIEW:
            return "candidate_only"
        return "bounded_independent"

    @staticmethod
    def _deterministic_verdict(capsule: ProofCapsule) -> OracleVerdict:
        if not capsule.structured_observations:
            return OracleVerdict.INSUFFICIENT_EVIDENCE
        rule_payload = {
            "claim": capsule.finding_claim.model_dump(mode="json"),
            "observations": [
                item.model_dump(mode="json") for item in capsule.structured_observations
            ],
            "rule": capsule.expected_verification_rule,
        }
        if sha256_json(rule_payload) in capsule.evidence_hashes:
            return OracleVerdict.VERIFIED
        return OracleVerdict.INSUFFICIENT_EVIDENCE
