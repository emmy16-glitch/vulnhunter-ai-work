from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from vulnhunter.actions.models import sha256_json
from vulnhunter.security_tools.opensandbox_supply_chain import public_key_id
from vulnhunter.web_hunters.models import VerificationStrategy
from vulnhunter.web_verification import (
    ExternalEvidenceAdmissionService,
    ExternalEvidenceClass,
    ExternalEvidenceOutcome,
    ExternalEvidenceSignature,
    IndependentVerificationResult,
    SignedExternalEvidenceSubmission,
    TrustedExternalEvidenceCollector,
    VerificationEvidenceReference,
    VerificationReason,
    VerificationVerdict,
    WebVerificationContractError,
    build_external_evidence_receipt,
    build_external_evidence_trust_policy,
    external_evidence_signing_bytes,
    verification_id_for,
)

_FIXED_TIME = datetime(2026, 8, 15, 14, 0, tzinfo=UTC)
_EXTERNAL_TIME = _FIXED_TIME + timedelta(minutes=1)


def _passive_result() -> IndependentVerificationResult:
    evidence = VerificationEvidenceReference(
        hunter_result_sha256="1" * 64,
        perception_plan_sha256="2" * 64,
        perception_evidence_sha256="3" * 64,
        graph_sha256="4" * 64,
        hypothesis_sha256="5" * 64,
        verification_intent_sha256="6" * 64,
        target_reference_sha256="7" * 64,
        hypothesis_id="8" * 64,
        intent_id="9" * 64,
        target_node_id="a" * 64,
        node_ids=("a" * 64,),
    )
    verifier_id = "deterministic-passive-web-verifier-v1"
    verification_id = verification_id_for(
        verifier_id=verifier_id,
        hunter_result_sha256=evidence.hunter_result_sha256,
        hypothesis_id=evidence.hypothesis_id,
        intent_id=evidence.intent_id,
    )
    payload = {
        "schema_version": 1,
        "verification_id": verification_id,
        "verifier_id": verifier_id,
        "hunter_id": "api-access",
        "vulnerability_class": "api_access_control_candidate",
        "strategy": VerificationStrategy.API_ACCESS_REVIEW.value,
        "verdict": VerificationVerdict.INCONCLUSIVE.value,
        "reason": VerificationReason.PASSIVE_EVIDENCE_INSUFFICIENT.value,
        "structural_predicate_reproduced": True,
        "evidence": evidence.model_dump(mode="json"),
        "started_at": "2026-08-15T14:00:00Z",
        "completed_at": "2026-08-15T14:00:00Z",
        "network_access_performed": False,
        "mutating_request_performed": False,
        "credential_use_performed": False,
        "authorization_bypass_performed": False,
        "shell_execution_performed": False,
        "external_evidence_accepted": False,
    }
    return IndependentVerificationResult(
        verification_id=verification_id,
        verifier_id=verifier_id,
        hunter_id="api-access",
        vulnerability_class="api_access_control_candidate",
        strategy=VerificationStrategy.API_ACCESS_REVIEW,
        verdict=VerificationVerdict.INCONCLUSIVE,
        reason=VerificationReason.PASSIVE_EVIDENCE_INSUFFICIENT,
        structural_predicate_reproduced=True,
        evidence=evidence,
        started_at=_FIXED_TIME,
        completed_at=_FIXED_TIME,
        result_sha256=sha256_json(payload),
    )


def _keypair():
    private_key = Ed25519PrivateKey.generate()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, public_pem, public_key_id(public_pem)


def _trusted_collector(
    *,
    allow_network: bool = False,
    collector_id: str = "lab-read-only-evidence-collector-v1",
):
    private_key, public_pem, key_id = _keypair()
    policy = build_external_evidence_trust_policy(
        collector_id=collector_id,
        collector_key_id=key_id,
        allowed_strategies=(VerificationStrategy.API_ACCESS_REVIEW,),
        allow_read_only_network=allow_network,
        maximum_evidence_bytes=4096,
    )
    return private_key, TrustedExternalEvidenceCollector(policy=policy, public_key_pem=public_pem)


def _submission(
    passive_result: IndependentVerificationResult,
    private_key: Ed25519PrivateKey,
    collector: TrustedExternalEvidenceCollector,
    *,
    network: bool = False,
    evidence_sha256: str = "b" * 64,
) -> SignedExternalEvidenceSubmission:
    receipt = build_external_evidence_receipt(
        passive_result=passive_result,
        collector_id=collector.policy.collector_id,
        collector_key_id=collector.policy.collector_key_id,
        authorization_reference_sha256="c" * 64,
        authorization_snapshot_sha256="d" * 64,
        collection_plan_sha256="e" * 64,
        collector_runtime_sha256="f" * 64,
        evidence_sha256=evidence_sha256,
        evidence_bytes=512,
        evidence_class=ExternalEvidenceClass.READ_ONLY_HTTP_METADATA,
        outcome=ExternalEvidenceOutcome.SUPPORTS_HYPOTHESIS,
        started_at=_EXTERNAL_TIME,
        completed_at=_EXTERNAL_TIME,
        network_access_performed=network,
        network_methods=("GET",) if network else (),
    )
    signature = ExternalEvidenceSignature(
        key_id=collector.policy.collector_key_id,
        signature=base64.b64encode(
            private_key.sign(external_evidence_signing_bytes(receipt))
        ).decode("ascii"),
    )
    return SignedExternalEvidenceSubmission(receipt=receipt, signature=signature)


def test_signed_external_receipt_is_admitted_without_granting_validation_authority() -> None:
    passive = _passive_result()
    private_key, collector = _trusted_collector(allow_network=True)
    submission = _submission(passive, private_key, collector, network=True)
    service = ExternalEvidenceAdmissionService((collector,), clock=lambda: _EXTERNAL_TIME)

    result = service.admit(passive, (submission,))

    assert len(result.receipts) == 1
    assert result.finding_validation_permitted is False
    assert result.durable_replay_protection_established is False
    assert result.receipts[0].finding_validation_permitted is False
    assert result.receipts[0].verification_adjudication_permitted is False
    assert result.receipts[0].receipt.outcome is ExternalEvidenceOutcome.SUPPORTS_HYPOTHESIS
    assert result.receipts[0].receipt.network_methods == ("GET",)


def test_invalid_signature_fails_closed() -> None:
    passive = _passive_result()
    private_key, collector = _trusted_collector()
    submission = _submission(passive, private_key, collector)
    attacker_key = Ed25519PrivateKey.generate()
    bad_signature = submission.signature.model_copy(
        update={
            "signature": base64.b64encode(
                attacker_key.sign(external_evidence_signing_bytes(submission.receipt))
            ).decode("ascii"),
        }
    )
    tampered = submission.model_copy(update={"signature": bad_signature})

    with pytest.raises(WebVerificationContractError, match="signature verification failed"):
        ExternalEvidenceAdmissionService((collector,), clock=lambda: _EXTERNAL_TIME).admit(
            passive, (tampered,)
        )


def test_untrusted_collector_and_wrong_trust_key_fail_closed() -> None:
    passive = _passive_result()
    private_key, collector = _trusted_collector()
    submission = _submission(passive, private_key, collector)
    _, other_collector = _trusted_collector(
        collector_id="different-lab-read-only-evidence-collector-v1"
    )

    with pytest.raises(WebVerificationContractError, match="not trusted"):
        ExternalEvidenceAdmissionService((other_collector,), clock=lambda: _EXTERNAL_TIME).admit(
            passive, (submission,)
        )

    _, wrong_public_pem, _ = _keypair()
    with pytest.raises(WebVerificationContractError, match="pinned key ID"):
        ExternalEvidenceAdmissionService(
            (
                TrustedExternalEvidenceCollector(
                    policy=collector.policy,
                    public_key_pem=wrong_public_pem,
                ),
            )
        )


def test_receipt_must_bind_exact_passive_verification() -> None:
    passive = _passive_result()
    private_key, collector = _trusted_collector()
    submission = _submission(passive, private_key, collector)
    payload = submission.receipt.model_dump(mode="json")
    payload["hunter_result_sha256"] = "0" * 64
    payload["receipt_sha256"] = sha256_json(
        {key: value for key, value in payload.items() if key != "receipt_sha256"}
    )
    rebound = submission.receipt.model_validate(payload)
    signature = ExternalEvidenceSignature(
        key_id=collector.policy.collector_key_id,
        signature=base64.b64encode(
            private_key.sign(external_evidence_signing_bytes(rebound))
        ).decode("ascii"),
    )

    with pytest.raises(WebVerificationContractError, match="exact passive verification source"):
        ExternalEvidenceAdmissionService((collector,), clock=lambda: _EXTERNAL_TIME).admit(
            passive,
            (SignedExternalEvidenceSubmission(receipt=rebound, signature=signature),),
        )


def test_receipt_schema_blocks_mutation_credentials_bypass_shell_and_payload_execution() -> None:
    passive = _passive_result()
    private_key, collector = _trusted_collector()
    submission = _submission(passive, private_key, collector)

    for field in (
        "mutating_request_performed",
        "credential_use_performed",
        "authorization_bypass_performed",
        "shell_execution_performed",
        "payload_execution_performed",
    ):
        payload = submission.receipt.model_dump(mode="json")
        payload[field] = True
        payload["receipt_sha256"] = "0" * 64
        with pytest.raises(ValidationError):
            submission.receipt.model_validate(payload)


def test_read_only_network_evidence_requires_explicit_collector_policy() -> None:
    passive = _passive_result()
    private_key, collector = _trusted_collector(allow_network=False)
    submission = _submission(passive, private_key, collector, network=True)

    with pytest.raises(WebVerificationContractError, match="not trusted for network evidence"):
        ExternalEvidenceAdmissionService((collector,), clock=lambda: _EXTERNAL_TIME).admit(
            passive, (submission,)
        )


def test_receipt_schema_rejects_non_read_only_network_method_and_raw_extra_content() -> None:
    passive = _passive_result()
    private_key, collector = _trusted_collector(allow_network=True)
    submission = _submission(passive, private_key, collector, network=True)
    payload = submission.receipt.model_dump(mode="json")
    payload["network_methods"] = ["POST"]
    payload["receipt_sha256"] = "0" * 64
    with pytest.raises(ValidationError):
        submission.receipt.model_validate(payload)

    payload = submission.receipt.model_dump(mode="json")
    payload["raw_response_body"] = "target-controlled content must never cross this boundary"
    with pytest.raises(ValidationError):
        submission.receipt.model_validate(payload)


def test_duplicate_receipts_are_rejected_before_admission() -> None:
    passive = _passive_result()
    private_key, collector = _trusted_collector()
    submission = _submission(passive, private_key, collector)

    with pytest.raises(WebVerificationContractError, match="duplicate external evidence receipts"):
        ExternalEvidenceAdmissionService((collector,), clock=lambda: _EXTERNAL_TIME).admit(
            passive, (submission, submission)
        )


def test_forged_receipt_id_fails_even_when_outer_hash_is_recomputed() -> None:
    passive = _passive_result()
    private_key, collector = _trusted_collector()
    submission = _submission(passive, private_key, collector)
    payload = submission.receipt.model_dump(mode="json")
    payload["receipt_id"] = "0" * 64
    payload["receipt_sha256"] = sha256_json(
        {key: value for key, value in payload.items() if key != "receipt_sha256"}
    )

    with pytest.raises(ValidationError, match="receipt ID"):
        submission.receipt.model_validate(payload)


def test_evidence_cannot_predate_the_passive_verification_result() -> None:
    passive = _passive_result()
    private_key, collector = _trusted_collector()
    receipt = build_external_evidence_receipt(
        passive_result=passive,
        collector_id=collector.policy.collector_id,
        collector_key_id=collector.policy.collector_key_id,
        authorization_reference_sha256="c" * 64,
        authorization_snapshot_sha256="d" * 64,
        collection_plan_sha256="e" * 64,
        collector_runtime_sha256="f" * 64,
        evidence_sha256="b" * 64,
        evidence_bytes=100,
        evidence_class=ExternalEvidenceClass.OFFLINE_ARTIFACT_REVIEW,
        outcome=ExternalEvidenceOutcome.INCONCLUSIVE,
        started_at=_FIXED_TIME - timedelta(seconds=1),
        completed_at=_FIXED_TIME,
    )
    signature = ExternalEvidenceSignature(
        key_id=collector.policy.collector_key_id,
        signature=base64.b64encode(
            private_key.sign(external_evidence_signing_bytes(receipt))
        ).decode("ascii"),
    )

    with pytest.raises(WebVerificationContractError, match="cannot predate"):
        ExternalEvidenceAdmissionService((collector,), clock=lambda: _EXTERNAL_TIME).admit(
            passive,
            (SignedExternalEvidenceSubmission(receipt=receipt, signature=signature),),
        )
