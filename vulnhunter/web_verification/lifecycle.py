"""Governed admission, adjudication, human review, and final decision service."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from vulnhunter.actions.models import sha256_json
from vulnhunter.assessment_graph import AssessmentStage
from vulnhunter.authorization.models import AuthorizationRecord
from vulnhunter.authorization.store import AuthorizationStore
from vulnhunter.exceptions import (
    AuthorizationError,
    GovernanceAuthenticationError,
    GovernancePolicyError,
)
from vulnhunter.governance.service import authenticate_identity
from vulnhunter.governance.store import GovernanceStore
from vulnhunter.taskgraph.models import NodeStatus
from vulnhunter.web_hunters.models import VerificationStrategy
from vulnhunter.web_verification.errors import WebVerificationContractError
from vulnhunter.web_verification.external_evidence import ExternalEvidenceAdmissionService
from vulnhunter.web_verification.external_models import (
    ExternalEvidenceClass,
    ExternalEvidenceOutcome,
    SignedExternalEvidenceSubmission,
)
from vulnhunter.web_verification.lifecycle_models import (
    AdjudicationReason,
    FinalVerificationDecision,
    HumanReviewRole,
    HumanVerificationReview,
    PersistedEvidenceAdmission,
    StrategyAdjudication,
    VerificationCaseSnapshot,
    VerificationCaseState,
    verification_case_id_for,
)
from vulnhunter.web_verification.lifecycle_store import VerificationLifecycleStore
from vulnhunter.web_verification.models import IndependentVerificationResult, VerificationVerdict

_STRATEGY_EVIDENCE_CLASSES: dict[VerificationStrategy, frozenset[ExternalEvidenceClass]] = {
    VerificationStrategy.OBJECT_AUTHORIZATION_REVIEW: frozenset(
        {ExternalEvidenceClass.OFFLINE_ARTIFACT_REVIEW}
    ),
    VerificationStrategy.REQUEST_INTEGRITY_REVIEW: frozenset(
        {
            ExternalEvidenceClass.OFFLINE_ARTIFACT_REVIEW,
            ExternalEvidenceClass.READ_ONLY_HTTP_METADATA,
        }
    ),
    VerificationStrategy.FILE_UPLOAD_REVIEW: frozenset(
        {
            ExternalEvidenceClass.OFFLINE_ARTIFACT_REVIEW,
            ExternalEvidenceClass.READ_ONLY_BROWSER_METADATA,
        }
    ),
    VerificationStrategy.AUTHENTICATION_REVIEW: frozenset(
        {
            ExternalEvidenceClass.OFFLINE_ARTIFACT_REVIEW,
            ExternalEvidenceClass.READ_ONLY_BROWSER_METADATA,
        }
    ),
    VerificationStrategy.API_ACCESS_REVIEW: frozenset(
        {
            ExternalEvidenceClass.OFFLINE_ARTIFACT_REVIEW,
            ExternalEvidenceClass.READ_ONLY_HTTP_METADATA,
        }
    ),
}


def authorization_reference_sha256(authorization_id: str) -> str:
    return sha256_json({"authorization_id": authorization_id})


def target_reference_sha256(target_url: str) -> str:
    return sha256_json({"target_url": target_url})


def _hashed_model(model_type, payload: dict[str, object], hash_field: str):
    provisional = model_type.model_construct(**payload, **{hash_field: "0" * 64})
    digest = sha256_json(provisional.model_dump(mode="json", exclude={hash_field}))
    return model_type.model_validate({**payload, hash_field: digest})


class VerificationLifecycleProjector:
    """Project durable lifecycle state into an existing Active Validation task graph."""

    def __init__(self, graph_service=None) -> None:
        self.graph_service = graph_service

    def evidence_admitted(self, run_id: str | None) -> None:
        if self.graph_service is not None and run_id:
            self.graph_service.project_state(run_id, state="evaluating")

    def adjudicated(self, run_id: str | None) -> None:
        if self.graph_service is not None and run_id:
            self.graph_service.project_state(run_id, state="completed")

    def finalized(self, run_id: str | None) -> None:
        if self.graph_service is None or not run_id:
            return
        self.graph_service.project_state(run_id, state="completed")
        core = self.graph_service.core
        graph = core._load_optional(run_id)
        if graph is None:
            return
        for stage in (AssessmentStage.REVIEW, AssessmentStage.REPORT):
            node = core._stage_node(graph, stage)
            if node.status == NodeStatus.COMPLETED:
                continue
            if node.status in {NodeStatus.PENDING, NodeStatus.READY, NodeStatus.PAUSED}:
                graph = core._transition(
                    graph,
                    node_id=node.node_id,
                    status=NodeStatus.RUNNING,
                    last_error=None,
                )
                node = core._stage_node(graph, stage)
            if node.status != NodeStatus.RUNNING:
                raise WebVerificationContractError(
                    f"assessment {stage.value} stage cannot accept final verification projection"
                )
            graph = core._transition(
                graph,
                node_id=node.node_id,
                status=NodeStatus.COMPLETED,
                last_error=None,
            )


class VerificationLifecycleService:
    """Single authoritative lifecycle above passive verification and signed receipts."""

    def __init__(
        self,
        *,
        lifecycle_store: VerificationLifecycleStore,
        authorization_store: AuthorizationStore,
        governance_store: GovernanceStore,
        evidence_admission: ExternalEvidenceAdmissionService,
        projector: VerificationLifecycleProjector | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.store = lifecycle_store
        self.authorization_store = authorization_store
        self.governance_store = governance_store
        self.evidence_admission = evidence_admission
        self.projector = projector or VerificationLifecycleProjector()
        self.clock = clock or (lambda: datetime.now(UTC))
        self.store.initialize()
        self.authorization_store.initialize()
        self.governance_store.initialize()

    def admit_evidence(
        self,
        *,
        authorization_id: str,
        passive_result: IndependentVerificationResult,
        submissions: tuple[SignedExternalEvidenceSubmission, ...],
        assessment_run_id: str | None = None,
        workspace_id: str | None = None,
    ) -> VerificationCaseSnapshot:
        """Verify signatures, live authorization, and persist receipts atomically."""
        now = self.clock().astimezone(UTC)
        record = self._revalidate_authorization(
            authorization_id=authorization_id,
            passive_result=passive_result,
            submissions=submissions,
            now=now,
        )
        admission = self.evidence_admission.admit(passive_result, submissions)
        receipt_ids = tuple(item.receipt.receipt_id for item in admission.receipts)
        case_id = verification_case_id_for(
            passive_verification_result_sha256=passive_result.result_sha256,
            authorization_record_sha256=record.record_sha256,
        )
        persisted = _hashed_model(
            PersistedEvidenceAdmission,
            {
                "schema_version": 1,
                "case_id": case_id,
                "authorization_id": record.authorization_id,
                "authorization_record_sha256": record.record_sha256,
                "admission": admission,
                "receipt_ids": receipt_ids,
                "persisted_at": now,
                "durable_replay_protection_established": True,
                "live_authorization_revalidated": True,
                "finding_validation_permitted": False,
            },
            "ledger_sha256",
        )
        snapshot = _hashed_model(
            VerificationCaseSnapshot,
            {
                "schema_version": 1,
                "case_id": case_id,
                "passive_verification_id": passive_result.verification_id,
                "passive_verification_result_sha256": passive_result.result_sha256,
                "authorization_id": record.authorization_id,
                "authorization_record_sha256": record.record_sha256,
                "target_reference_sha256": passive_result.evidence.target_reference_sha256,
                "strategy": passive_result.strategy,
                "state": VerificationCaseState.EVIDENCE_ADMITTED,
                "revision": 0,
                "assessment_run_id": assessment_run_id,
                "workspace_id": workspace_id,
                "admission_sha256": persisted.ledger_sha256,
                "adjudication_sha256": None,
                "final_decision_sha256": None,
                "created_at": now,
                "updated_at": now,
            },
            "case_sha256",
        )
        result = self.store.persist_admission(
            snapshot=snapshot,
            persisted=persisted,
            submissions=submissions,
        )
        self.projector.evidence_admitted(assessment_run_id)
        return result

    def adjudicate(self, case_id: str, *, expected_revision: int) -> VerificationCaseSnapshot:
        current = self.store.get_case(case_id)
        if current.revision != expected_revision:
            raise WebVerificationContractError("verification case revision is stale")
        admission = self.store.get_admission(case_id)
        receipts = admission.admission.receipts
        allowed_classes = _STRATEGY_EVIDENCE_CLASSES[current.strategy]
        relevant = tuple(
            item for item in receipts if item.receipt.evidence_class in allowed_classes
        )
        supports = tuple(
            item
            for item in relevant
            if item.receipt.outcome is ExternalEvidenceOutcome.SUPPORTS_HYPOTHESIS
        )
        refutes = tuple(
            item
            for item in relevant
            if item.receipt.outcome is ExternalEvidenceOutcome.REFUTES_HYPOTHESIS
        )
        validation_support = tuple(
            item
            for item in supports
            if item.receipt.evidence_class is ExternalEvidenceClass.OFFLINE_ARTIFACT_REVIEW
        )
        if supports and refutes:
            candidate = VerificationVerdict.INCONCLUSIVE
            reason = AdjudicationReason.CONFLICTING_EVIDENCE
            allowed = (VerificationVerdict.INCONCLUSIVE,)
        elif refutes:
            candidate = VerificationVerdict.REJECTED
            reason = AdjudicationReason.EVIDENCE_REFUTATION
            allowed = tuple(
                sorted(
                    (VerificationVerdict.INCONCLUSIVE, VerificationVerdict.REJECTED),
                    key=lambda item: item.value,
                )
            )
        elif validation_support:
            candidate = VerificationVerdict.VALIDATED
            reason = AdjudicationReason.VALIDATION_GRADE_SUPPORT
            allowed = tuple(
                sorted(
                    (VerificationVerdict.INCONCLUSIVE, VerificationVerdict.VALIDATED),
                    key=lambda item: item.value,
                )
            )
        else:
            candidate = VerificationVerdict.INCONCLUSIVE
            reason = AdjudicationReason.INSUFFICIENT_EVIDENCE
            allowed = (VerificationVerdict.INCONCLUSIVE,)
        now = self.clock().astimezone(UTC)
        adjudication = _hashed_model(
            StrategyAdjudication,
            {
                "schema_version": 1,
                "case_id": current.case_id,
                "strategy": current.strategy,
                "candidate_verdict": candidate,
                "reason": reason,
                "allowed_human_verdicts": allowed,
                "receipt_ids": admission.receipt_ids,
                "created_at": now,
                "human_review_required": True,
            },
            "adjudication_sha256",
        )
        replacement = self.store.save_adjudication(
            adjudication,
            expected_revision=expected_revision,
            now=now,
        )
        self.projector.adjudicated(current.assessment_run_id)
        return replacement

    def record_primary_review(
        self,
        case_id: str,
        *,
        expected_revision: int,
        reviewer_id: str,
        reviewer_secret: str,
        verdict: VerificationVerdict,
    ) -> VerificationCaseSnapshot:
        return self._record_review(
            case_id,
            expected_revision=expected_revision,
            reviewer_id=reviewer_id,
            reviewer_secret=reviewer_secret,
            verdict=verdict,
            role=HumanReviewRole.PRIMARY,
        )

    def record_adjudicator_review(
        self,
        case_id: str,
        *,
        expected_revision: int,
        reviewer_id: str,
        reviewer_secret: str,
        verdict: VerificationVerdict,
    ) -> VerificationCaseSnapshot:
        primaries = tuple(
            item
            for item in self.store.list_reviews(case_id)
            if item.role is HumanReviewRole.PRIMARY
        )
        if len(primaries) != 2 or primaries[0].verdict == primaries[1].verdict:
            raise WebVerificationContractError(
                "adjudicator review is allowed only after two primary reviewers disagree"
            )
        return self._record_review(
            case_id,
            expected_revision=expected_revision,
            reviewer_id=reviewer_id,
            reviewer_secret=reviewer_secret,
            verdict=verdict,
            role=HumanReviewRole.ADJUDICATOR,
        )

    def finalize(self, case_id: str, *, expected_revision: int) -> FinalVerificationDecision:
        current = self.store.get_case(case_id)
        if current.revision != expected_revision:
            raise WebVerificationContractError("verification case revision is stale")
        existing = self.store.get_decision(case_id)
        if existing is not None:
            return existing
        adjudication = self.store.get_adjudication(case_id)
        admission = self.store.get_admission(case_id)
        reviews = self.store.list_reviews(case_id)
        primaries = tuple(item for item in reviews if item.role is HumanReviewRole.PRIMARY)
        adjudicators = tuple(item for item in reviews if item.role is HumanReviewRole.ADJUDICATOR)
        if len(primaries) != 2:
            raise WebVerificationContractError("two distinct primary reviews are required")
        if primaries[0].verdict == primaries[1].verdict:
            if adjudicators:
                raise WebVerificationContractError(
                    "consensus cases must not add adjudicator authority"
                )
            final_verdict = primaries[0].verdict
            adjudicator_review_id = None
        else:
            if len(adjudicators) != 1:
                raise WebVerificationContractError(
                    "disputed primary reviews require exactly one distinct adjudicator"
                )
            final_verdict = adjudicators[0].verdict
            adjudicator_review_id = adjudicators[0].review_id
        if final_verdict not in adjudication.allowed_human_verdicts:
            raise WebVerificationContractError(
                "human review cannot promote evidence above the strategy adjudication ceiling"
            )
        now = self.clock().astimezone(UTC)
        primary_ids = tuple(sorted(item.review_id for item in primaries))
        decision_id = sha256_json(
            {
                "case_id": current.case_id,
                "adjudication_sha256": adjudication.adjudication_sha256,
                "primary_review_ids": list(primary_ids),
                "adjudicator_review_id": adjudicator_review_id,
            }
        )
        decision = _hashed_model(
            FinalVerificationDecision,
            {
                "schema_version": 1,
                "decision_id": decision_id,
                "case_id": current.case_id,
                "adjudication_sha256": adjudication.adjudication_sha256,
                "verdict": final_verdict,
                "authorization_id": current.authorization_id,
                "authorization_record_sha256": current.authorization_record_sha256,
                "receipt_ids": admission.receipt_ids,
                "primary_review_ids": primary_ids,
                "adjudicator_review_id": adjudicator_review_id,
                "decided_at": now,
                "human_review_completed": True,
                "finding_confirmation_authority": "governed_human_review",
                "severity_assignment_permitted": False,
                "publication_permitted": False,
                "automatic_remediation_permitted": False,
            },
            "decision_sha256",
        )
        self.store.finalize(decision, expected_revision=expected_revision)
        self.projector.finalized(current.assessment_run_id)
        return decision

    def status(self, case_id: str) -> dict[str, object]:
        snapshot = self.store.get_case(case_id)
        decision = self.store.get_decision(case_id)
        return {
            "case_id": snapshot.case_id,
            "state": snapshot.state.value,
            "revision": snapshot.revision,
            "strategy": snapshot.strategy.value,
            "assessment_run_id": snapshot.assessment_run_id,
            "workspace_id": snapshot.workspace_id,
            "durable_replay_protection": True,
            "live_authorization_revalidated": True,
            "final_verdict": decision.verdict.value if decision else None,
        }

    def _record_review(
        self,
        case_id: str,
        *,
        expected_revision: int,
        reviewer_id: str,
        reviewer_secret: str,
        verdict: VerificationVerdict,
        role: HumanReviewRole,
    ) -> VerificationCaseSnapshot:
        current = self.store.get_case(case_id)
        adjudication = self.store.get_adjudication(case_id)
        if verdict not in adjudication.allowed_human_verdicts:
            raise WebVerificationContractError(
                "human review cannot promote evidence above the strategy adjudication ceiling"
            )
        required_role = "reviewer" if role is HumanReviewRole.PRIMARY else "adjudicator"
        try:
            identity = authenticate_identity(
                self.governance_store,
                reviewer_id,
                reviewer_secret,
                required_role=required_role,
            )
        except (GovernanceAuthenticationError, GovernancePolicyError) as exc:
            raise WebVerificationContractError(
                "verification reviewer authentication failed"
            ) from exc
        existing = self.store.list_reviews(case_id)
        if identity.reviewer_id in {item.reviewer_id for item in existing}:
            raise WebVerificationContractError("verification reviewers must be distinct")
        collector_ids = {
            item.receipt.collector_id
            for item in self.store.get_admission(case_id).admission.receipts
        }
        if identity.reviewer_id in collector_ids:
            raise WebVerificationContractError(
                "external evidence collectors cannot review their own verification case"
            )
        record = self.authorization_store.get(current.authorization_id)
        conflicts = {record.owner.strip().casefold(), record.approved_by.strip().casefold()}
        if identity.reviewer_id in conflicts:
            raise WebVerificationContractError(
                "authorization owner or approver cannot review the same verification case"
            )
        if role is HumanReviewRole.ADJUDICATOR:
            primary_ids = {
                item.reviewer_id for item in existing if item.role is HumanReviewRole.PRIMARY
            }
            if identity.reviewer_id in primary_ids:
                raise WebVerificationContractError(
                    "adjudicator must be distinct from primary reviewers"
                )
        now = self.clock().astimezone(UTC)
        review_id = sha256_json(
            {
                "case_id": current.case_id,
                "adjudication_sha256": adjudication.adjudication_sha256,
                "reviewer_id": identity.reviewer_id,
                "role": role.value,
            }
        )
        review = _hashed_model(
            HumanVerificationReview,
            {
                "schema_version": 1,
                "review_id": review_id,
                "case_id": current.case_id,
                "adjudication_sha256": adjudication.adjudication_sha256,
                "reviewer_id": identity.reviewer_id,
                "role": role,
                "verdict": verdict,
                "submitted_at": now,
            },
            "review_sha256",
        )
        return self.store.add_review(review, expected_revision=expected_revision)

    def _revalidate_authorization(
        self,
        *,
        authorization_id: str,
        passive_result: IndependentVerificationResult,
        submissions: tuple[SignedExternalEvidenceSubmission, ...],
        now: datetime,
    ) -> AuthorizationRecord:
        try:
            record = self.authorization_store.get(authorization_id)
        except AuthorizationError as exc:
            raise WebVerificationContractError(
                "verification authorization could not be loaded"
            ) from exc
        if record.status != "active":
            raise WebVerificationContractError("verification authorization is revoked")
        if now < record.valid_from or now >= record.expires_at:
            raise WebVerificationContractError("verification authorization is not currently active")
        expected_authorization_reference = authorization_reference_sha256(record.authorization_id)
        expected_target_reference = target_reference_sha256(record.target_url)
        if passive_result.evidence.target_reference_sha256 != expected_target_reference:
            raise WebVerificationContractError(
                "passive verification target does not match the live authorization"
            )
        if not submissions:
            raise WebVerificationContractError("verification evidence submissions are required")
        for submission in submissions:
            receipt = submission.receipt
            if receipt.authorization_reference_sha256 != expected_authorization_reference:
                raise WebVerificationContractError(
                    "external evidence authorization reference does not match the live record"
                )
            if receipt.authorization_snapshot_sha256 != record.record_sha256:
                raise WebVerificationContractError(
                    "external evidence authorization snapshot is stale or mismatched"
                )
            if receipt.target_reference_sha256 != expected_target_reference:
                raise WebVerificationContractError(
                    "external evidence target does not match the live authorization"
                )
            if receipt.started_at < record.valid_from or receipt.completed_at >= record.expires_at:
                raise WebVerificationContractError(
                    "external evidence was collected outside the authorization validity window"
                )
            if receipt.completed_at > now:
                raise WebVerificationContractError(
                    "external evidence cannot be dated in the future"
                )
        return record
