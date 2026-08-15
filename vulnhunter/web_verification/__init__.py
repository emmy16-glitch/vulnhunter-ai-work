"""Independent, read-only verification for adaptive web-hunter hypotheses."""

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

__all__ = [
    "ExternalEvidenceAdmissionBatch",
    "ExternalEvidenceAdmissionService",
    "ExternalEvidenceClass",
    "ExternalEvidenceOutcome",
    "ExternalEvidenceSignature",
    "ExternalEvidenceTrustPolicy",
    "ExternalVerificationEvidenceReceipt",
    "IndependentVerificationResult",
    "IndependentWebVerifier",
    "SignedExternalEvidenceSubmission",
    "TrustedExternalEvidenceCollector",
    "VerificationBatchResult",
    "VerificationEvidenceReference",
    "VerificationReason",
    "VerificationVerdict",
    "VerifiedExternalEvidenceReceipt",
    "WebVerificationContractError",
    "WebVerificationError",
    "build_external_evidence_receipt",
    "build_external_evidence_trust_policy",
    "external_evidence_admission_id_for",
    "external_evidence_receipt_id_for",
    "external_evidence_signing_bytes",
    "verification_batch_id_for",
    "verification_id_for",
]
