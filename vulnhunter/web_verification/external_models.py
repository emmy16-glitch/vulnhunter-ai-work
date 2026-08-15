"""Immutable contracts for governed external web-verification evidence."""

from __future__ import annotations

import base64
import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from vulnhunter.actions.models import sha256_json
from vulnhunter.web_hunters.models import VerificationStrategy

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")


class ExternalEvidenceClass(StrEnum):
    """Sanitized evidence families that may be attested by an external collector."""

    READ_ONLY_HTTP_METADATA = "read_only_http_metadata"
    READ_ONLY_BROWSER_METADATA = "read_only_browser_metadata"
    OFFLINE_ARTIFACT_REVIEW = "offline_artifact_review"


class ExternalEvidenceOutcome(StrEnum):
    """Collector assertion carried by a receipt; it is not a vulnerability verdict."""

    SUPPORTS_HYPOTHESIS = "supports_hypothesis"
    REFUTES_HYPOTHESIS = "refutes_hypothesis"
    INCONCLUSIVE = "inconclusive"


class ExternalEvidenceTrustPolicy(BaseModel):
    """Deployment-pinned trust policy for one external evidence collector."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: int = 1
    collector_id: str
    collector_key_id: str
    allowed_strategies: tuple[VerificationStrategy, ...] = Field(min_length=1, max_length=12)
    allow_read_only_network: bool = False
    maximum_evidence_bytes: int = Field(default=5_000_000, ge=1, le=50_000_000)
    finding_validation_permitted: Literal[False] = False
    policy_sha256: str

    @field_validator("collector_id")
    @classmethod
    def validate_collector_id(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("external evidence collector_id must be a stable lowercase identifier")
        return value

    @field_validator("collector_key_id")
    @classmethod
    def validate_key_id(cls, value: str) -> str:
        if _KEY_ID.fullmatch(value) is None:
            raise ValueError("external evidence collector key ID must be a SHA-256 key identifier")
        return value

    @field_validator("policy_sha256")
    @classmethod
    def validate_hash(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("external evidence trust policy hash must be SHA-256")
        return value

    @model_validator(mode="after")
    def validate_policy(self):
        if self.schema_version != 1:
            raise ValueError("external evidence trust policy schema is unsupported")
        if len(self.allowed_strategies) != len(set(self.allowed_strategies)):
            raise ValueError("external evidence allowed strategies must be unique")
        canonical_strategies = tuple(sorted(self.allowed_strategies, key=lambda item: item.value))
        if canonical_strategies != self.allowed_strategies:
            raise ValueError("external evidence allowed strategies must use canonical order")
        expected = sha256_json(self.model_dump(mode="json", exclude={"policy_sha256"}))
        if expected != self.policy_sha256:
            raise ValueError("external evidence trust policy hash does not match its contents")
        return self


class ExternalVerificationEvidenceReceipt(BaseModel):
    """Hash-only, unsigned receipt body emitted by a separate evidence collector."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: int = 1
    receipt_id: str
    collector_id: str
    collector_key_id: str
    passive_verification_id: str
    passive_verification_result_sha256: str
    hunter_result_sha256: str
    hypothesis_id: str
    intent_id: str
    strategy: VerificationStrategy
    target_reference_sha256: str
    authorization_reference_sha256: str
    authorization_snapshot_sha256: str
    collection_plan_sha256: str
    collector_runtime_sha256: str
    evidence_sha256: str
    evidence_bytes: int = Field(ge=0, le=50_000_000)
    evidence_class: ExternalEvidenceClass
    outcome: ExternalEvidenceOutcome
    started_at: datetime
    completed_at: datetime
    network_access_performed: bool = False
    network_methods: tuple[Literal["GET", "HEAD"], ...] = Field(default=(), max_length=2)
    mutating_request_performed: Literal[False] = False
    credential_use_performed: Literal[False] = False
    authorization_bypass_performed: Literal[False] = False
    shell_execution_performed: Literal[False] = False
    payload_execution_performed: Literal[False] = False
    evidence_redacted: Literal[True] = True
    raw_target_content_included: Literal[False] = False
    raw_secrets_included: Literal[False] = False
    receipt_sha256: str

    @field_validator(
        "receipt_id",
        "passive_verification_id",
        "passive_verification_result_sha256",
        "hunter_result_sha256",
        "hypothesis_id",
        "intent_id",
        "target_reference_sha256",
        "authorization_reference_sha256",
        "authorization_snapshot_sha256",
        "collection_plan_sha256",
        "collector_runtime_sha256",
        "evidence_sha256",
        "receipt_sha256",
    )
    @classmethod
    def validate_hash(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("external evidence identities must be SHA-256 digests")
        return value

    @field_validator("collector_id")
    @classmethod
    def validate_collector_id(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("external evidence collector_id must be a stable lowercase identifier")
        return value

    @field_validator("collector_key_id")
    @classmethod
    def validate_key_id(cls, value: str) -> str:
        if _KEY_ID.fullmatch(value) is None:
            raise ValueError("external evidence collector key ID must be a SHA-256 key identifier")
        return value

    @field_validator("started_at", "completed_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("external evidence timestamps must include a timezone")
        return value.astimezone(UTC)

    @field_validator("network_methods")
    @classmethod
    def validate_methods(
        cls,
        values: tuple[Literal["GET", "HEAD"], ...],
    ) -> tuple[Literal["GET", "HEAD"], ...]:
        if len(values) != len(set(values)):
            raise ValueError("external evidence network methods must be unique")
        if tuple(sorted(values)) != values:
            raise ValueError("external evidence network methods must use canonical order")
        return values

    @model_validator(mode="after")
    def validate_receipt(self):
        if self.schema_version != 1:
            raise ValueError("external evidence receipt schema is unsupported")
        if self.completed_at < self.started_at:
            raise ValueError("external evidence collection cannot complete before it starts")
        if self.network_access_performed and not self.network_methods:
            raise ValueError("network evidence must declare its read-only request methods")
        if not self.network_access_performed and self.network_methods:
            raise ValueError("offline evidence cannot declare network request methods")
        if (
            self.evidence_class is ExternalEvidenceClass.OFFLINE_ARTIFACT_REVIEW
            and self.network_access_performed
        ):
            raise ValueError("offline artifact evidence cannot claim network access")

        expected_receipt_id = external_evidence_receipt_id_for(
            collector_id=self.collector_id,
            collector_key_id=self.collector_key_id,
            passive_verification_id=self.passive_verification_id,
            passive_verification_result_sha256=self.passive_verification_result_sha256,
            authorization_snapshot_sha256=self.authorization_snapshot_sha256,
            collection_plan_sha256=self.collection_plan_sha256,
            evidence_sha256=self.evidence_sha256,
            evidence_class=self.evidence_class,
            outcome=self.outcome,
        )
        if self.receipt_id != expected_receipt_id:
            raise ValueError("external evidence receipt ID does not match its bound identities")
        expected = sha256_json(self.model_dump(mode="json", exclude={"receipt_sha256"}))
        if expected != self.receipt_sha256:
            raise ValueError("external evidence receipt hash does not match its contents")
        return self


class ExternalEvidenceSignature(BaseModel):
    """Detached Ed25519 signature over canonical receipt JSON."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: int = 1
    algorithm: Literal["ed25519"] = "ed25519"
    key_id: str
    signature: str

    @field_validator("key_id")
    @classmethod
    def validate_key_id(cls, value: str) -> str:
        if _KEY_ID.fullmatch(value) is None:
            raise ValueError("external evidence signature key ID must be a SHA-256 key identifier")
        return value

    @field_validator("signature")
    @classmethod
    def validate_signature(cls, value: str) -> str:
        try:
            decoded = base64.b64decode(value, validate=True)
        except ValueError as exc:
            raise ValueError("external evidence signature must be valid base64") from exc
        if len(decoded) != 64:
            raise ValueError("external evidence Ed25519 signature must be 64 bytes")
        return value

    @model_validator(mode="after")
    def validate_schema(self):
        if self.schema_version != 1:
            raise ValueError("external evidence signature schema is unsupported")
        return self


class SignedExternalEvidenceSubmission(BaseModel):
    """One signed receipt submitted to the read-only admission boundary."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    receipt: ExternalVerificationEvidenceReceipt
    signature: ExternalEvidenceSignature

    @model_validator(mode="after")
    def validate_key_binding(self):
        if self.signature.key_id != self.receipt.collector_key_id:
            raise ValueError("external evidence signature must bind the receipt collector key")
        return self


class VerifiedExternalEvidenceReceipt(BaseModel):
    """Receipt whose signature, trust policy, and passive-result bindings were verified."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: int = 1
    receipt: ExternalVerificationEvidenceReceipt
    trust_policy_sha256: str
    signature_key_id: str
    verified_at: datetime
    finding_validation_permitted: Literal[False] = False
    verification_adjudication_permitted: Literal[False] = False
    verification_sha256: str

    @field_validator("trust_policy_sha256", "verification_sha256")
    @classmethod
    def validate_hash(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("verified external evidence identities must be SHA-256 digests")
        return value

    @field_validator("signature_key_id")
    @classmethod
    def validate_key_id(cls, value: str) -> str:
        if _KEY_ID.fullmatch(value) is None:
            raise ValueError("verified external evidence key ID must be a SHA-256 key identifier")
        return value

    @field_validator("verified_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("external evidence verification timestamp must include a timezone")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_verified_receipt(self):
        if self.schema_version != 1:
            raise ValueError("verified external evidence schema is unsupported")
        if self.signature_key_id != self.receipt.collector_key_id:
            raise ValueError("verified external evidence key must match the receipt")
        expected = sha256_json(self.model_dump(mode="json", exclude={"verification_sha256"}))
        if expected != self.verification_sha256:
            raise ValueError("verified external evidence hash does not match its contents")
        return self


class ExternalEvidenceAdmissionBatch(BaseModel):
    """Deterministic admission of signed receipts for one passive verification result."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: int = 1
    admission_id: str
    passive_verification_id: str
    passive_verification_result_sha256: str
    receipts: tuple[VerifiedExternalEvidenceReceipt, ...] = Field(min_length=1, max_length=50)
    admitted_at: datetime
    duplicate_receipts_rejected: Literal[True] = True
    durable_replay_protection_established: Literal[False] = False
    finding_validation_permitted: Literal[False] = False
    admission_sha256: str

    @field_validator(
        "admission_id",
        "passive_verification_id",
        "passive_verification_result_sha256",
        "admission_sha256",
    )
    @classmethod
    def validate_hash(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("external evidence admission identities must be SHA-256 digests")
        return value

    @field_validator("admitted_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("external evidence admission timestamp must include a timezone")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_admission(self):
        if self.schema_version != 1:
            raise ValueError("external evidence admission schema is unsupported")
        receipt_ids = [item.receipt.receipt_id for item in self.receipts]
        if len(receipt_ids) != len(set(receipt_ids)):
            raise ValueError("external evidence admission receipt IDs must be unique")
        if receipt_ids != sorted(receipt_ids):
            raise ValueError("external evidence admission receipts must use canonical order")
        if any(
            item.receipt.passive_verification_id != self.passive_verification_id
            or item.receipt.passive_verification_result_sha256
            != self.passive_verification_result_sha256
            for item in self.receipts
        ):
            raise ValueError("external evidence receipts must bind the exact passive verification")
        expected_id = external_evidence_admission_id_for(
            passive_verification_result_sha256=self.passive_verification_result_sha256,
            receipt_ids=tuple(receipt_ids),
        )
        if self.admission_id != expected_id:
            raise ValueError("external evidence admission ID does not match its receipts")
        expected = sha256_json(self.model_dump(mode="json", exclude={"admission_sha256"}))
        if expected != self.admission_sha256:
            raise ValueError("external evidence admission hash does not match its contents")
        return self


def external_evidence_receipt_id_for(
    *,
    collector_id: str,
    collector_key_id: str,
    passive_verification_id: str,
    passive_verification_result_sha256: str,
    authorization_snapshot_sha256: str,
    collection_plan_sha256: str,
    evidence_sha256: str,
    evidence_class: ExternalEvidenceClass,
    outcome: ExternalEvidenceOutcome,
) -> str:
    return sha256_json(
        {
            "collector_id": collector_id,
            "collector_key_id": collector_key_id,
            "passive_verification_id": passive_verification_id,
            "passive_verification_result_sha256": passive_verification_result_sha256,
            "authorization_snapshot_sha256": authorization_snapshot_sha256,
            "collection_plan_sha256": collection_plan_sha256,
            "evidence_sha256": evidence_sha256,
            "evidence_class": evidence_class.value,
            "outcome": outcome.value,
        }
    )


def external_evidence_admission_id_for(
    *,
    passive_verification_result_sha256: str,
    receipt_ids: tuple[str, ...],
) -> str:
    return sha256_json(
        {
            "passive_verification_result_sha256": passive_verification_result_sha256,
            "receipt_ids": list(receipt_ids),
        }
    )
