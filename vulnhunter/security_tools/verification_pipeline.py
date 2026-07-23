"""Convert scanner candidates into one evidence-backed finding lifecycle."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from vulnhunter.actions.models import sha256_json
from vulnhunter.evidence.models import EvidenceRecord, FindingStatus
from vulnhunter.evidence.store import EvidenceStore
from vulnhunter.intelligence import (
    IntelligenceStore,
    IntelligenceStoreError,
    build_analysis_request,
)
from vulnhunter.oracle.models import (
    FindingClaim,
    OracleResponse,
    OracleVerdict,
    ProofCapsule,
    StructuredObservation,
    VerificationStrategy,
)
from vulnhunter.oracle.service import OracleVerifier
from vulnhunter.oracle.store import OracleStore
from vulnhunter.security import redact_mapping, redact_text
from vulnhunter.security_tools.scanner_protocol import (
    ScannerAdapterResult,
    ScannerCandidateObservation,
)


class UnifiedFindingOutcome(BaseModel):
    """One consolidated finding outcome; provider details remain provenance only."""

    model_config = ConfigDict(frozen=True, extra="forbid", arbitrary_types_allowed=True)

    finding: EvidenceRecord
    verification: OracleResponse
    capsule_path: Path
    analysis_id: str | None = None
    analysis_queued: bool = False


class EvidenceVerificationPipeline:
    """Normalize candidates, verify safe claims, and append one finding record."""

    def __init__(
        self,
        *,
        evidence_store: EvidenceStore,
        verification_store: OracleStore,
        verifier: OracleVerifier | None = None,
        intelligence_store: IntelligenceStore | None = None,
        clock=lambda: datetime.now(UTC),
    ) -> None:
        self.evidence_store = evidence_store
        self.verification_store = verification_store
        self.verifier = verifier or OracleVerifier()
        self.clock = clock
        self.intelligence_store = intelligence_store
        if self.intelligence_store is None:
            try:
                self.intelligence_store = IntelligenceStore.from_environment()
            except (OSError, IntelligenceStoreError):
                self.intelligence_store = None

    def process(
        self,
        result: ScannerAdapterResult,
        *,
        campaign_id: str,
        run_id: str,
        authorization_reference: str,
        approval_reference: str,
        action_manifest_sha256: str,
        target_reference: str,
        adapter_version: str,
        tool_version: str,
        recorded_by: str,
    ) -> tuple[UnifiedFindingOutcome, ...]:
        existing = {record.evidence_id: record for record in self.evidence_store.list()}
        artifact_path, artifact_hashes = self._artifact_context(result)
        outcomes: list[UnifiedFindingOutcome] = []
        for candidate in result.observations:
            evidence_id = f"finding-{candidate.observation_id}"
            if evidence_id in existing:
                continue
            capsule = self._capsule(
                candidate,
                result=result,
                campaign_id=campaign_id,
                run_id=run_id,
                authorization_reference=authorization_reference,
                approval_reference=approval_reference,
                action_manifest_sha256=action_manifest_sha256,
                target_reference=target_reference,
                adapter_version=adapter_version,
                tool_version=tool_version,
                artifact_hashes=artifact_hashes,
                recorded_by=recorded_by,
            )
            capsule_path = self.verification_store.save_capsule(capsule)
            response = self.verifier.verify(
                capsule,
                verifier_identity="deterministic-verifier",
                strategy=VerificationStrategy.EVIDENCE_CONSISTENCY_CHECK,
                now=self.clock(),
            )
            status = (
                FindingStatus.VALIDATED
                if response.verdict is OracleVerdict.VERIFIED
                else FindingStatus.CANDIDATE
            )
            metadata = redact_mapping(
                {
                    "scanner": "nuclei",
                    "execution_id": result.execution_id,
                    "observation_id": candidate.observation_id,
                    "template_id": candidate.template_id or "unknown",
                    "verification_status": response.verdict.value,
                    "verification_strategy": response.strategy.value,
                    "verification_response_sha256": response.response_hash,
                    "proof_capsule_sha256": capsule.capsule_hash(),
                    "provenance": ["scanner", "evidence", "deterministic_verification"],
                }
            )
            record = self.evidence_store.append(
                evidence_id=evidence_id,
                campaign_id=campaign_id,
                run_id=run_id,
                action_manifest_sha256=action_manifest_sha256,
                tool_id="nuclei",
                target_reference=target_reference,
                finding_status=status,
                title=redact_text(candidate.title),
                severity=redact_text(candidate.severity),
                confidence=(
                    "deterministically_validated"
                    if status is FindingStatus.VALIDATED
                    else redact_text(candidate.confidence)
                ),
                recorded_by=recorded_by,
                artifact_path=artifact_path,
                metadata=metadata,
            )
            analysis_id = None
            analysis_queued = False
            if self.intelligence_store is not None:
                request = build_analysis_request(
                    finding_id=record.evidence_id,
                    run_id=run_id,
                    campaign_id=campaign_id,
                    candidate=candidate,
                    verification=response,
                    capsule=capsule,
                )
                analysis_id = request.analysis_id
                try:
                    analysis_queued = self.intelligence_store.enqueue(request)
                    if not analysis_queued:
                        analysis_queued = (
                            self.intelligence_store.status_for_finding(record.evidence_id)
                            is not None
                        )
                except IntelligenceStoreError:
                    analysis_queued = False
            outcomes.append(
                UnifiedFindingOutcome(
                    finding=record,
                    verification=response,
                    capsule_path=capsule_path,
                    analysis_id=analysis_id,
                    analysis_queued=analysis_queued,
                )
            )
        return tuple(outcomes)

    def _artifact_context(
        self, result: ScannerAdapterResult
    ) -> tuple[Path | None, tuple[str, ...]]:
        if not result.evidence:
            return None, ()
        reference = result.evidence[0]
        path = self.evidence_store.root / reference.relative_path
        return path, tuple(item.sha256 for item in result.evidence)

    def _capsule(
        self,
        candidate: ScannerCandidateObservation,
        *,
        result: ScannerAdapterResult,
        campaign_id: str,
        run_id: str,
        authorization_reference: str,
        approval_reference: str,
        action_manifest_sha256: str,
        target_reference: str,
        adapter_version: str,
        tool_version: str,
        artifact_hashes: tuple[str, ...],
        recorded_by: str,
    ) -> ProofCapsule:
        now = self.clock()
        evidence_hash = (
            artifact_hashes[0]
            if artifact_hashes
            else hashlib.sha256(candidate.model_dump_json().encode()).hexdigest()
        )
        observation = StructuredObservation(
            observation_id=candidate.observation_id,
            evidence_sha256=evidence_hash,
            observation_type="scanner_candidate",
            value=f"{candidate.template_id or 'nuclei'}:{candidate.severity}",
        )
        claim = FindingClaim(
            claim_id=f"claim-{candidate.observation_id}",
            title=redact_text(candidate.title),
            claimed_severity=redact_text(candidate.severity),
            claimed_confidence=redact_text(candidate.confidence),
            preconditions=("authorized passive private-lab assessment",),
            consequential=False,
        )
        rule = "nuclei-passive-evidence-consistency-v1"
        rule_payload = {
            "claim": claim.model_dump(mode="json"),
            "observations": [observation.model_dump(mode="json")],
            "rule": rule,
        }
        rule_hash = sha256_json(rule_payload)
        target_identity = "target-" + hashlib.sha256(target_reference.encode()).hexdigest()[:24]
        return ProofCapsule(
            capsule_id=f"capsule-{candidate.observation_id}",
            candidate_finding_id=f"finding-{candidate.observation_id}",
            campaign_id=campaign_id,
            authorization_reference=authorization_reference,
            scope_reference=f"run-{run_id}",
            target_identity=target_identity,
            action_manifest_sha256=action_manifest_sha256,
            approval_reference=approval_reference,
            original_tool="nuclei",
            original_adapter_version=adapter_version,
            original_tool_version=tool_version,
            command_plan_sha256=action_manifest_sha256,
            evidence_hashes=tuple(dict.fromkeys((*artifact_hashes, evidence_hash, rule_hash))),
            structured_observations=(observation,),
            finding_claim=claim,
            claim_author=recorded_by,
            expected_verification_rule=rule,
            verification_limits={"maximum_attempts": 1, "timeout_seconds": 30},
            permitted_strategies=(VerificationStrategy.EVIDENCE_CONSISTENCY_CHECK,),
            created_at=now,
            expires_at=now + timedelta(hours=1),
            redaction_policy="central-redaction-v1",
            customer_boundary="private-lab",
            provenance_chain=(
                result.execution_id,
                candidate.observation_id,
                "deterministic-verifier",
            ),
        )


__all__ = ["EvidenceVerificationPipeline", "UnifiedFindingOutcome"]
