"""Read-only independent verifier for adaptive web-hunter hypotheses."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from vulnhunter.actions.models import sha256_json
from vulnhunter.web_hunters.models import HunterHypothesis, HunterRunResult
from vulnhunter.web_perception.models import WebPerceptionResult
from vulnhunter.web_verification.errors import WebVerificationContractError
from vulnhunter.web_verification.models import (
    IndependentVerificationResult,
    VerificationBatchResult,
    VerificationEvidenceReference,
    VerificationReason,
    VerificationVerdict,
    verification_batch_id_for,
    verification_id_for,
)
from vulnhunter.web_verification.policy import (
    structural_predicate_reproduced,
    validate_verification_source,
    verification_contract_matches,
)


class IndependentWebVerifier:
    """Re-evaluate advisory hypotheses without network or execution authority."""

    def __init__(
        self,
        *,
        verifier_id: str = "deterministic-passive-web-verifier-v1",
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.verifier_id = verifier_id
        self._clock = clock or (lambda: datetime.now(UTC))

    def verify(
        self,
        perception: WebPerceptionResult,
        hunter_run: HunterRunResult,
        *,
        hypothesis_ids: tuple[str, ...] | None = None,
    ) -> VerificationBatchResult:
        """Verify exact source bindings and reproduce passive structural predicates."""

        context = validate_verification_source(perception, hunter_run)
        selected = self._select_hypotheses(hunter_run, hypothesis_ids)
        started_at = self._clock().astimezone(UTC)
        decisions: list[tuple[HunterHypothesis, VerificationVerdict, VerificationReason, bool]] = []

        for hypothesis in selected:
            if not verification_contract_matches(hypothesis):
                decisions.append(
                    (
                        hypothesis,
                        VerificationVerdict.REJECTED,
                        VerificationReason.HUNTER_CONTRACT_MISMATCH,
                        False,
                    )
                )
                continue

            reproduced = structural_predicate_reproduced(context, hypothesis)
            if not reproduced:
                decisions.append(
                    (
                        hypothesis,
                        VerificationVerdict.REJECTED,
                        VerificationReason.STRUCTURAL_PREDICATE_NOT_REPRODUCED,
                        False,
                    )
                )
                continue

            decisions.append(
                (
                    hypothesis,
                    VerificationVerdict.INCONCLUSIVE,
                    VerificationReason.PASSIVE_EVIDENCE_INSUFFICIENT,
                    True,
                )
            )

        completed_at = self._clock().astimezone(UTC)
        target_reference_sha256 = sha256_json({"target_url": context.target_url})
        results = tuple(
            self._build_result(
                hunter_run=hunter_run,
                hypothesis=hypothesis,
                target_reference_sha256=target_reference_sha256,
                verdict=verdict,
                reason=reason,
                reproduced=reproduced,
                started_at=started_at,
                completed_at=completed_at,
            )
            for hypothesis, verdict, reason, reproduced in decisions
        )
        hypothesis_ids_in_batch = tuple(item.evidence.hypothesis_id for item in results)
        batch_id = verification_batch_id_for(
            verifier_id=self.verifier_id,
            hunter_result_sha256=hunter_run.result_sha256,
            hypothesis_ids=hypothesis_ids_in_batch,
        )
        payload = {
            "schema_version": 1,
            "batch_id": batch_id,
            "verifier_id": self.verifier_id,
            "hunter_result_sha256": hunter_run.result_sha256,
            "target_reference_sha256": target_reference_sha256,
            "started_at": _json_datetime(started_at),
            "completed_at": _json_datetime(completed_at),
            "results": [item.model_dump(mode="json") for item in results],
        }
        return VerificationBatchResult(
            batch_id=batch_id,
            verifier_id=self.verifier_id,
            hunter_result_sha256=hunter_run.result_sha256,
            target_reference_sha256=target_reference_sha256,
            started_at=started_at,
            completed_at=completed_at,
            results=results,
            batch_sha256=sha256_json(payload),
        )

    def _select_hypotheses(
        self,
        hunter_run: HunterRunResult,
        hypothesis_ids: tuple[str, ...] | None,
    ) -> tuple[HunterHypothesis, ...]:
        if hypothesis_ids is None:
            selected = hunter_run.hypotheses
        else:
            if not hypothesis_ids:
                raise WebVerificationContractError(
                    "verification selection must include at least one hypothesis"
                )
            if len(hypothesis_ids) != len(set(hypothesis_ids)):
                raise WebVerificationContractError(
                    "verification hypothesis selection must be unique"
                )
            by_id = {item.hypothesis_id: item for item in hunter_run.hypotheses}
            missing = [value for value in hypothesis_ids if value not in by_id]
            if missing:
                raise WebVerificationContractError(
                    "verification selection references an unknown hypothesis"
                )
            selected = tuple(by_id[value] for value in hypothesis_ids)

        if not selected:
            raise WebVerificationContractError("hunter result contains no hypothesis to verify")
        return tuple(sorted(selected, key=lambda item: item.hypothesis_id))

    def _build_result(
        self,
        *,
        hunter_run: HunterRunResult,
        hypothesis: HunterHypothesis,
        target_reference_sha256: str,
        verdict: VerificationVerdict,
        reason: VerificationReason,
        reproduced: bool,
        started_at: datetime,
        completed_at: datetime,
    ) -> IndependentVerificationResult:
        evidence = VerificationEvidenceReference(
            hunter_result_sha256=hunter_run.result_sha256,
            perception_plan_sha256=hunter_run.perception_plan_sha256,
            perception_evidence_sha256=hunter_run.perception_evidence_sha256,
            graph_sha256=hunter_run.graph_sha256,
            hypothesis_sha256=sha256_json(hypothesis.model_dump(mode="json")),
            verification_intent_sha256=sha256_json(
                hypothesis.verification_intent.model_dump(mode="json")
            ),
            target_reference_sha256=target_reference_sha256,
            hypothesis_id=hypothesis.hypothesis_id,
            intent_id=hypothesis.verification_intent.intent_id,
            target_node_id=hypothesis.target_node_id,
            node_ids=hypothesis.evidence.node_ids,
            edge_ids=hypothesis.evidence.edge_ids,
        )
        verification_id = verification_id_for(
            verifier_id=self.verifier_id,
            hunter_result_sha256=hunter_run.result_sha256,
            hypothesis_id=hypothesis.hypothesis_id,
            intent_id=hypothesis.verification_intent.intent_id,
        )
        payload = {
            "schema_version": 1,
            "verification_id": verification_id,
            "verifier_id": self.verifier_id,
            "hunter_id": hypothesis.hunter_id,
            "vulnerability_class": hypothesis.vulnerability_class,
            "strategy": hypothesis.verification_intent.strategy.value,
            "verdict": verdict.value,
            "reason": reason.value,
            "structural_predicate_reproduced": reproduced,
            "evidence": evidence.model_dump(mode="json"),
            "started_at": _json_datetime(started_at),
            "completed_at": _json_datetime(completed_at),
            "network_access_performed": False,
            "mutating_request_performed": False,
            "credential_use_performed": False,
            "authorization_bypass_performed": False,
            "shell_execution_performed": False,
            "external_evidence_accepted": False,
        }
        return IndependentVerificationResult(
            verification_id=verification_id,
            verifier_id=self.verifier_id,
            hunter_id=hypothesis.hunter_id,
            vulnerability_class=hypothesis.vulnerability_class,
            strategy=hypothesis.verification_intent.strategy,
            verdict=verdict,
            reason=reason,
            structural_predicate_reproduced=reproduced,
            evidence=evidence,
            started_at=started_at,
            completed_at=completed_at,
            result_sha256=sha256_json(payload),
        )


def _json_datetime(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
