"""Signature verification and admission for governed external web evidence."""

from __future__ import annotations

import base64
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

from pydantic import ValidationError

from vulnhunter.actions.models import sha256_json
from vulnhunter.security_tools.opensandbox_supply_chain import (
    canonical_json_bytes,
    public_key_id,
)
from vulnhunter.web_hunters.models import VerificationStrategy
from vulnhunter.web_verification.errors import WebVerificationContractError
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
from vulnhunter.web_verification.models import IndependentVerificationResult


@dataclass(frozen=True)
class TrustedExternalEvidenceCollector:
    """Deployment-supplied trust anchor; private signing keys never enter VulnHunter."""

    policy: ExternalEvidenceTrustPolicy
    public_key_pem: bytes


class ExternalEvidenceAdmissionService:
    """Verify signed receipts without executing collection or adjudicating findings."""

    def __init__(
        self,
        collectors: tuple[TrustedExternalEvidenceCollector, ...],
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not collectors:
            raise WebVerificationContractError(
                "at least one trusted evidence collector is required"
            )
        self._clock = clock or (lambda: datetime.now(UTC))
        self._collectors: dict[str, TrustedExternalEvidenceCollector] = {}
        for collector in collectors:
            if collector.policy.collector_id in self._collectors:
                raise WebVerificationContractError("trusted evidence collector IDs must be unique")
            actual_key_id = _validate_public_key(collector.public_key_pem)
            if actual_key_id != collector.policy.collector_key_id:
                raise WebVerificationContractError(
                    "trusted evidence collector public key does not match its pinned key ID"
                )
            self._collectors[collector.policy.collector_id] = collector

    def admit(
        self,
        passive_result: IndependentVerificationResult,
        submissions: tuple[SignedExternalEvidenceSubmission, ...],
    ) -> ExternalEvidenceAdmissionBatch:
        """Verify exact receipt bindings and signatures without promoting a verdict."""

        try:
            source = IndependentVerificationResult.model_validate(
                passive_result.model_dump(mode="json")
            )
        except ValidationError as exc:
            raise WebVerificationContractError(
                "external evidence admission requires an intact passive verification result"
            ) from exc
        if not submissions:
            raise WebVerificationContractError(
                "external evidence admission requires at least one receipt"
            )

        receipt_ids = [item.receipt.receipt_id for item in submissions]
        if len(receipt_ids) != len(set(receipt_ids)):
            raise WebVerificationContractError("duplicate external evidence receipts are rejected")

        verified = tuple(
            self._verify_submission(source, submission)
            for submission in sorted(submissions, key=lambda item: item.receipt.receipt_id)
        )
        admitted_at = self._clock().astimezone(UTC)
        canonical_receipt_ids = tuple(item.receipt.receipt_id for item in verified)
        admission_id = external_evidence_admission_id_for(
            passive_verification_result_sha256=source.result_sha256,
            receipt_ids=canonical_receipt_ids,
        )
        payload = {
            "schema_version": 1,
            "admission_id": admission_id,
            "passive_verification_id": source.verification_id,
            "passive_verification_result_sha256": source.result_sha256,
            "receipts": [item.model_dump(mode="json") for item in verified],
            "admitted_at": _json_datetime(admitted_at),
            "duplicate_receipts_rejected": True,
            "durable_replay_protection_established": False,
            "finding_validation_permitted": False,
        }
        return ExternalEvidenceAdmissionBatch(
            admission_id=admission_id,
            passive_verification_id=source.verification_id,
            passive_verification_result_sha256=source.result_sha256,
            receipts=verified,
            admitted_at=admitted_at,
            admission_sha256=sha256_json(payload),
        )

    def _verify_submission(
        self,
        passive_result: IndependentVerificationResult,
        submission: SignedExternalEvidenceSubmission,
    ) -> VerifiedExternalEvidenceReceipt:
        receipt = submission.receipt
        trusted = self._collectors.get(receipt.collector_id)
        if trusted is None:
            raise WebVerificationContractError("external evidence collector is not trusted")
        policy = trusted.policy

        if receipt.collector_key_id != policy.collector_key_id:
            raise WebVerificationContractError(
                "external evidence receipt uses an untrusted collector key"
            )
        if receipt.strategy not in policy.allowed_strategies:
            raise WebVerificationContractError(
                "external evidence strategy is not allowed for this collector"
            )
        if receipt.evidence_bytes > policy.maximum_evidence_bytes:
            raise WebVerificationContractError(
                "external evidence exceeds the collector policy byte limit"
            )
        if receipt.network_access_performed and not policy.allow_read_only_network:
            raise WebVerificationContractError(
                "external evidence collector is not trusted for network evidence"
            )

        evidence = passive_result.evidence
        exact_bindings = (
            receipt.passive_verification_id == passive_result.verification_id,
            receipt.passive_verification_result_sha256 == passive_result.result_sha256,
            receipt.hunter_result_sha256 == evidence.hunter_result_sha256,
            receipt.hypothesis_id == evidence.hypothesis_id,
            receipt.intent_id == evidence.intent_id,
            receipt.strategy is passive_result.strategy,
            receipt.target_reference_sha256 == evidence.target_reference_sha256,
        )
        if not all(exact_bindings):
            raise WebVerificationContractError(
                "external evidence receipt does not bind the exact passive verification source"
            )
        if receipt.started_at < passive_result.completed_at:
            raise WebVerificationContractError(
                "external verification evidence cannot predate the passive verification result"
            )

        _verify_detached_signature(
            receipt=receipt,
            signature=submission.signature,
            public_key_pem=trusted.public_key_pem,
            expected_key_id=policy.collector_key_id,
        )

        verified_at = self._clock().astimezone(UTC)
        payload = {
            "schema_version": 1,
            "receipt": receipt.model_dump(mode="json"),
            "trust_policy_sha256": policy.policy_sha256,
            "signature_key_id": policy.collector_key_id,
            "verified_at": _json_datetime(verified_at),
            "finding_validation_permitted": False,
            "verification_adjudication_permitted": False,
        }
        return VerifiedExternalEvidenceReceipt(
            receipt=receipt,
            trust_policy_sha256=policy.policy_sha256,
            signature_key_id=policy.collector_key_id,
            verified_at=verified_at,
            verification_sha256=sha256_json(payload),
        )


def build_external_evidence_trust_policy(
    *,
    collector_id: str,
    collector_key_id: str,
    allowed_strategies: tuple[VerificationStrategy, ...],
    allow_read_only_network: bool = False,
    maximum_evidence_bytes: int = 5_000_000,
) -> ExternalEvidenceTrustPolicy:
    """Create a canonical deployment-pinned collector trust policy."""

    canonical_strategies = tuple(sorted(allowed_strategies, key=lambda item: item.value))
    payload = {
        "schema_version": 1,
        "collector_id": collector_id,
        "collector_key_id": collector_key_id,
        "allowed_strategies": [item.value for item in canonical_strategies],
        "allow_read_only_network": allow_read_only_network,
        "maximum_evidence_bytes": maximum_evidence_bytes,
        "finding_validation_permitted": False,
    }
    return ExternalEvidenceTrustPolicy(
        collector_id=collector_id,
        collector_key_id=collector_key_id,
        allowed_strategies=canonical_strategies,
        allow_read_only_network=allow_read_only_network,
        maximum_evidence_bytes=maximum_evidence_bytes,
        policy_sha256=sha256_json(payload),
    )


def build_external_evidence_receipt(
    *,
    passive_result: IndependentVerificationResult,
    collector_id: str,
    collector_key_id: str,
    authorization_reference_sha256: str,
    authorization_snapshot_sha256: str,
    collection_plan_sha256: str,
    collector_runtime_sha256: str,
    evidence_sha256: str,
    evidence_bytes: int,
    evidence_class: ExternalEvidenceClass,
    outcome: ExternalEvidenceOutcome,
    started_at: datetime,
    completed_at: datetime,
    network_access_performed: bool = False,
    network_methods: tuple[Literal["GET", "HEAD"], ...] = (),
) -> ExternalVerificationEvidenceReceipt:
    """Build an unsigned, hash-bound receipt; signing stays outside product runtime."""

    receipt_id = external_evidence_receipt_id_for(
        collector_id=collector_id,
        collector_key_id=collector_key_id,
        passive_verification_id=passive_result.verification_id,
        passive_verification_result_sha256=passive_result.result_sha256,
        authorization_snapshot_sha256=authorization_snapshot_sha256,
        collection_plan_sha256=collection_plan_sha256,
        evidence_sha256=evidence_sha256,
        evidence_class=evidence_class,
        outcome=outcome,
    )
    payload = {
        "schema_version": 1,
        "receipt_id": receipt_id,
        "collector_id": collector_id,
        "collector_key_id": collector_key_id,
        "passive_verification_id": passive_result.verification_id,
        "passive_verification_result_sha256": passive_result.result_sha256,
        "hunter_result_sha256": passive_result.evidence.hunter_result_sha256,
        "hypothesis_id": passive_result.evidence.hypothesis_id,
        "intent_id": passive_result.evidence.intent_id,
        "strategy": passive_result.strategy.value,
        "target_reference_sha256": passive_result.evidence.target_reference_sha256,
        "authorization_reference_sha256": authorization_reference_sha256,
        "authorization_snapshot_sha256": authorization_snapshot_sha256,
        "collection_plan_sha256": collection_plan_sha256,
        "collector_runtime_sha256": collector_runtime_sha256,
        "evidence_sha256": evidence_sha256,
        "evidence_bytes": evidence_bytes,
        "evidence_class": evidence_class.value,
        "outcome": outcome.value,
        "started_at": _json_datetime(started_at),
        "completed_at": _json_datetime(completed_at),
        "network_access_performed": network_access_performed,
        "network_methods": list(network_methods),
        "mutating_request_performed": False,
        "credential_use_performed": False,
        "authorization_bypass_performed": False,
        "shell_execution_performed": False,
        "payload_execution_performed": False,
        "evidence_redacted": True,
        "raw_target_content_included": False,
        "raw_secrets_included": False,
    }
    return ExternalVerificationEvidenceReceipt(
        receipt_id=receipt_id,
        collector_id=collector_id,
        collector_key_id=collector_key_id,
        passive_verification_id=passive_result.verification_id,
        passive_verification_result_sha256=passive_result.result_sha256,
        hunter_result_sha256=passive_result.evidence.hunter_result_sha256,
        hypothesis_id=passive_result.evidence.hypothesis_id,
        intent_id=passive_result.evidence.intent_id,
        strategy=passive_result.strategy,
        target_reference_sha256=passive_result.evidence.target_reference_sha256,
        authorization_reference_sha256=authorization_reference_sha256,
        authorization_snapshot_sha256=authorization_snapshot_sha256,
        collection_plan_sha256=collection_plan_sha256,
        collector_runtime_sha256=collector_runtime_sha256,
        evidence_sha256=evidence_sha256,
        evidence_bytes=evidence_bytes,
        evidence_class=evidence_class,
        outcome=outcome,
        started_at=started_at,
        completed_at=completed_at,
        network_access_performed=network_access_performed,
        network_methods=network_methods,
        receipt_sha256=sha256_json(payload),
    )


def external_evidence_signing_bytes(receipt: ExternalVerificationEvidenceReceipt) -> bytes:
    """Return the exact canonical bytes an external collector must sign."""

    return canonical_json_bytes(receipt.model_dump(mode="json"))


def _verify_detached_signature(
    *,
    receipt: ExternalVerificationEvidenceReceipt,
    signature: ExternalEvidenceSignature,
    public_key_pem: bytes,
    expected_key_id: str,
) -> None:
    actual_key_id = _validate_public_key(public_key_pem)
    if actual_key_id != expected_key_id or signature.key_id != expected_key_id:
        raise WebVerificationContractError("external evidence signature key is not trusted")
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        public_key = serialization.load_pem_public_key(public_key_pem)
        if not isinstance(public_key, Ed25519PublicKey):
            raise WebVerificationContractError("external evidence public key must be Ed25519")
        public_key.verify(
            base64.b64decode(signature.signature, validate=True),
            external_evidence_signing_bytes(receipt),
        )
    except InvalidSignature as exc:
        raise WebVerificationContractError(
            "external evidence signature verification failed"
        ) from exc


def _validate_public_key(public_key_pem: bytes) -> str:
    if len(public_key_pem) > 65_536:
        raise WebVerificationContractError("external evidence public key exceeds its size limit")
    try:
        return public_key_id(public_key_pem)
    except (TypeError, ValueError) as exc:
        raise WebVerificationContractError("external evidence public key is invalid") from exc


def _json_datetime(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise WebVerificationContractError("external evidence timestamps must include a timezone")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
