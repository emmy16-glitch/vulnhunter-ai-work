"""Independent and human-governed verification for adaptive web-hunter hypotheses."""

from vulnhunter.web_verification.errors import (
    WebVerificationContractError,
    WebVerificationError,
)
from vulnhunter.web_verification.external_evidence import (
    ExternalEvidenceAdmissionService,
    TrustedExternalEvidenceCollector,
    build_external_evidence_receipt,
    build_external_evidence_trust_policy,
    external_evidence_signing_bytes,
)
from vulnhunter.web_verification.external_models import (
    ExternalEvidenceAdmissionBatch,
    ExternalEvidenceClass,
    ExternalEvidenceOutcome,
    ExternalEvidenceSignature,
    ExternalEvidenceTrustPolicy,
    ExternalVerificationEvidenceReceipt,
    SignedExternalEvidenceSubmission,
    VerifiedExternalEvidenceReceipt,
    external_evidence_admission_id_for,
    external_evidence_receipt_id_for,
)
from vulnhunter.web_verification.lifecycle import (
    VerificationLifecycleProjector,
    VerificationLifecycleService,
    authorization_reference_sha256,
    target_reference_sha256,
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
    VerificationCollectionPlan,
    VerificationWorkerCapability,
    verification_case_id_for,
)
from vulnhunter.web_verification.lifecycle_store import VerificationLifecycleStore
from vulnhunter.web_verification.models import (
    IndependentVerificationResult,
    VerificationBatchResult,
    VerificationEvidenceReference,
    VerificationReason,
    VerificationVerdict,
    verification_batch_id_for,
    verification_id_for,
)
from vulnhunter.web_verification.verifier import IndependentWebVerifier
from vulnhunter.web_verification.workers import (
    VerificationWorkerRegistry,
    build_worker_capability,
    default_verification_worker_capabilities,
)

__all__ = [
    "AdjudicationReason",
    "ExternalEvidenceAdmissionBatch",
    "ExternalEvidenceAdmissionService",
    "ExternalEvidenceClass",
    "ExternalEvidenceOutcome",
    "ExternalEvidenceSignature",
    "ExternalEvidenceTrustPolicy",
    "ExternalVerificationEvidenceReceipt",
    "FinalVerificationDecision",
    "HumanReviewRole",
    "HumanVerificationReview",
    "IndependentVerificationResult",
    "IndependentWebVerifier",
    "PersistedEvidenceAdmission",
    "SignedExternalEvidenceSubmission",
    "StrategyAdjudication",
    "TrustedExternalEvidenceCollector",
    "VerificationBatchResult",
    "VerificationCaseSnapshot",
    "VerificationCaseState",
    "VerificationCollectionPlan",
    "VerificationEvidenceReference",
    "VerificationLifecycleProjector",
    "VerificationLifecycleService",
    "VerificationLifecycleStore",
    "VerificationReason",
    "VerificationVerdict",
    "VerificationWorkerCapability",
    "VerificationWorkerRegistry",
    "VerifiedExternalEvidenceReceipt",
    "WebVerificationContractError",
    "WebVerificationError",
    "authorization_reference_sha256",
    "build_external_evidence_receipt",
    "build_external_evidence_trust_policy",
    "build_worker_capability",
    "default_verification_worker_capabilities",
    "external_evidence_admission_id_for",
    "external_evidence_receipt_id_for",
    "external_evidence_signing_bytes",
    "target_reference_sha256",
    "verification_batch_id_for",
    "verification_case_id_for",
    "verification_id_for",
]
