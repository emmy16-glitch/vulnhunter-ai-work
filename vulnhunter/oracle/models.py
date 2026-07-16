"""Typed Machine Oracle proof-capsule and verdict models."""

from __future__ import annotations

import re
import unicodedata
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from vulnhunter.actions.models import sha256_json

_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$")


def utc_now() -> datetime:
    return datetime.now(UTC)


def _safe_text(value: str, *, field_name: str) -> str:
    if value != unicodedata.normalize("NFKC", value):
        raise ValueError(f"{field_name} must not use ambiguous Unicode normalization")
    if any(ord(character) < 32 for character in value):
        raise ValueError(f"{field_name} must not contain control characters")
    return value


def _validate_identifier(value: str) -> str:
    value = _safe_text(value.strip(), field_name="identifier")
    if _IDENTIFIER.fullmatch(value) is None:
        raise ValueError("identifier must be a stable lowercase value")
    return value


def _validate_reference(value: str) -> str:
    value = _safe_text(value.strip(), field_name="reference")
    if ".." in value.split("/"):
        raise ValueError("reference must not contain path traversal")
    if _REFERENCE.fullmatch(value) is None:
        raise ValueError("reference contains unsupported characters")
    return value


def _validate_sha(value: str) -> str:
    if _SHA256.fullmatch(value) is None:
        raise ValueError("value must be a SHA-256 digest")
    return value


class OracleVerdict(StrEnum):
    VERIFIED = "verified"
    NOT_VERIFIED = "not_verified"
    CONFLICTING_EVIDENCE = "conflicting_evidence"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    VERIFICATION_BLOCKED = "verification_blocked"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class VerificationStrategy(StrEnum):
    DETERMINISTIC_REPLAY = "deterministic_replay"
    EVIDENCE_CONSISTENCY_CHECK = "evidence_consistency_check"
    INDEPENDENT_STATIC_ANALYSIS = "independent_static_analysis"
    INDEPENDENT_RULE_VALIDATION = "independent_rule_validation"
    SECOND_TOOL_CORROBORATION = "second_tool_corroboration"
    SAFE_SIMULATION = "safe_simulation"
    MODEL_ASSISTED_REVIEW = "model_assisted_review"
    HUMAN_REQUIRED = "human_required"


class OracleSessionStatus(StrEnum):
    QUEUED = "queued"
    PREPARING = "preparing"
    VERIFYING = "verifying"
    AWAITING_APPROVAL = "awaiting_approval"
    AWAITING_EVIDENCE = "awaiting_evidence"
    PAUSED = "paused"
    CANCELLATION_REQUESTED = "cancellation_requested"
    CANCELLED = "cancelled"
    BLOCKED = "blocked"
    FAILED = "failed"
    COMPLETED = "completed"


class StructuredObservation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    observation_id: str
    evidence_sha256: str
    observation_type: str
    value: str = Field(min_length=1, max_length=2_000)

    @field_validator("observation_id", "observation_type")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        return _validate_identifier(value)

    @field_validator("evidence_sha256")
    @classmethod
    def validate_digest(cls, value: str) -> str:
        return _validate_sha(value)

    @field_validator("value")
    @classmethod
    def validate_value(cls, value: str) -> str:
        return _safe_text(value, field_name="observation value")


class FindingClaim(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    claim_id: str
    title: str = Field(min_length=3, max_length=300)
    claimed_severity: str
    claimed_confidence: str
    preconditions: tuple[str, ...] = ()
    consequential: bool = False

    @field_validator("claim_id")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        return _validate_identifier(value)

    @field_validator("title", "claimed_severity", "claimed_confidence")
    @classmethod
    def validate_safe_text(cls, value: str) -> str:
        return _safe_text(value.strip(), field_name="claim text")

    @field_validator("preconditions")
    @classmethod
    def validate_preconditions(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(_safe_text(value.strip(), field_name="precondition") for value in values)


class ProofCapsule(BaseModel):
    """Immutable safe reference bundle for independent verification."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    capsule_id: str
    candidate_finding_id: str
    campaign_id: str
    authorization_reference: str
    scope_reference: str
    target_identity: str
    action_manifest_sha256: str
    approval_reference: str | None = None
    original_tool: str
    original_adapter_version: str
    original_tool_version: str
    command_plan_sha256: str | None = None
    input_artifact_hashes: tuple[str, ...] = ()
    evidence_hashes: tuple[str, ...] = Field(min_length=1)
    structured_observations: tuple[StructuredObservation, ...] = ()
    finding_claim: FindingClaim
    claim_author: str
    expected_verification_rule: str
    verification_limits: dict[str, int] = Field(default_factory=dict)
    permitted_strategies: tuple[VerificationStrategy, ...] = Field(min_length=1)
    created_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime
    redaction_policy: str
    customer_boundary: str
    provenance_chain: tuple[str, ...] = Field(min_length=1)

    @field_validator(
        "capsule_id", "candidate_finding_id", "campaign_id", "original_tool", "claim_author"
    )
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        return _validate_identifier(value)

    @field_validator(
        "authorization_reference",
        "scope_reference",
        "target_identity",
        "approval_reference",
        "original_adapter_version",
        "original_tool_version",
        "expected_verification_rule",
        "redaction_policy",
        "customer_boundary",
    )
    @classmethod
    def validate_reference(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _validate_reference(value)

    @field_validator("action_manifest_sha256", "command_plan_sha256")
    @classmethod
    def validate_optional_digest(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _validate_sha(value)

    @field_validator("input_artifact_hashes", "evidence_hashes")
    @classmethod
    def validate_digests(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(_validate_sha(value) for value in values)
        if len(set(normalized)) != len(normalized):
            raise ValueError("hashes must be unique")
        return normalized

    @field_validator("provenance_chain")
    @classmethod
    def validate_provenance(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(_validate_reference(value) for value in values)

    @model_validator(mode="after")
    def validate_capsule(self) -> Self:
        if self.expires_at <= self.created_at:
            raise ValueError("expires_at must be later than created_at")
        if any(limit <= 0 for limit in self.verification_limits.values()):
            raise ValueError("verification limits must be positive")
        observed_hashes = {item.evidence_sha256 for item in self.structured_observations}
        if not observed_hashes.issubset(set(self.evidence_hashes)):
            raise ValueError("structured observations must reference capsule evidence hashes")
        return self

    def capsule_hash(self) -> str:
        return sha256_json(self.model_dump(mode="json"))


class OracleResponse(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    response_id: str
    capsule_sha256: str
    verdict: OracleVerdict
    strategy: VerificationStrategy
    verifier_identity: str
    verifier_version: str
    independence_strength: str
    evidence_hashes: tuple[str, ...] = ()
    response_hash: str
    created_at: datetime = Field(default_factory=utc_now)

    @field_validator("response_id", "verifier_identity")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        return _validate_identifier(value)

    @field_validator("capsule_sha256", "response_hash")
    @classmethod
    def validate_digest(cls, value: str) -> str:
        return _validate_sha(value)

    @field_validator("evidence_hashes")
    @classmethod
    def validate_digests(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(_validate_sha(value) for value in values)

    def unsigned_payload(self) -> dict[str, object]:
        return self.model_dump(mode="json", exclude={"response_hash"})

    def expected_hash(self) -> str:
        return sha256_json(self.unsigned_payload())


class OracleConflict(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    conflict_id: str
    capsule_sha256: str
    original_claim_id: str
    response_id: str
    disputed_claim: str
    evidence_references: tuple[str, ...]
    independence_strength: str
    created_at: datetime = Field(default_factory=utc_now)

    @field_validator("conflict_id", "original_claim_id", "response_id")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        return _validate_identifier(value)

    @field_validator("capsule_sha256")
    @classmethod
    def validate_digest(cls, value: str) -> str:
        return _validate_sha(value)

    @field_validator("evidence_references")
    @classmethod
    def validate_references(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(_validate_reference(value) for value in values)


class OracleSession(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    session_id: str
    capsule_sha256: str
    strategy: VerificationStrategy
    verifier_identity: str
    provider_identity: str | None = None
    connector_identity: str | None = None
    authorization_reference: str | None = None
    scope_reference: str | None = None
    status: OracleSessionStatus = OracleSessionStatus.QUEUED
    step: str = "queued"
    attempt: int = Field(default=0, ge=0, le=20)
    limits: dict[str, int] = Field(default_factory=dict)
    produced_evidence_hashes: tuple[str, ...] = ()
    created_at: datetime = Field(default_factory=utc_now)
    last_heartbeat_at: datetime = Field(default_factory=utc_now)
    safe_error_category: str | None = None
    final_verdict: OracleVerdict | None = None

    @field_validator("session_id", "verifier_identity", "provider_identity", "connector_identity")
    @classmethod
    def validate_identifier(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _validate_identifier(value)

    @field_validator("authorization_reference", "scope_reference")
    @classmethod
    def validate_reference(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _validate_reference(value)

    @field_validator("capsule_sha256")
    @classmethod
    def validate_digest(cls, value: str) -> str:
        return _validate_sha(value)

    @field_validator("produced_evidence_hashes")
    @classmethod
    def validate_digests(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(_validate_sha(value) for value in values)
        if len(set(normalized)) != len(normalized):
            raise ValueError("produced evidence hashes must be unique")
        return normalized

    @field_validator("created_at", "last_heartbeat_at")
    @classmethod
    def validate_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Oracle session timestamps must be timezone-aware")
        return value

    @model_validator(mode="after")
    def validate_terminal_state(self) -> Self:
        if self.last_heartbeat_at < self.created_at:
            raise ValueError("Oracle session heartbeat cannot precede creation")
        if any(limit <= 0 for limit in self.limits.values()):
            raise ValueError("Oracle session limits must be positive")
        if self.status == OracleSessionStatus.COMPLETED and self.final_verdict is None:
            raise ValueError("completed Oracle sessions require a final verdict")
        if self.status in {OracleSessionStatus.FAILED, OracleSessionStatus.BLOCKED}:
            if not self.safe_error_category:
                raise ValueError("failed or blocked sessions require a safe error category")
        if self.status != OracleSessionStatus.COMPLETED and self.final_verdict is not None:
            raise ValueError("only completed Oracle sessions may carry a final verdict")
        if (
            self.status
            not in {
                OracleSessionStatus.FAILED,
                OracleSessionStatus.BLOCKED,
                OracleSessionStatus.CANCELLED,
            }
            and self.safe_error_category is not None
        ):
            raise ValueError(
                "safe errors are allowed only for failed, blocked, or cancelled sessions"
            )
        return self


class OracleSessionEvent(BaseModel):
    """Hash-chained full snapshot used to replay and validate a session."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    sequence: int = Field(ge=1)
    session_id: str
    previous_status: OracleSessionStatus | None
    status: OracleSessionStatus
    snapshot: OracleSession
    snapshot_sha256: str
    occurred_at: datetime
    previous_sha256: str
    event_sha256: str

    @field_validator("session_id")
    @classmethod
    def validate_session_identifier(cls, value: str) -> str:
        return _validate_identifier(value)

    @field_validator("snapshot_sha256", "previous_sha256", "event_sha256")
    @classmethod
    def validate_event_digest(cls, value: str) -> str:
        return _validate_sha(value)

    @field_validator("occurred_at")
    @classmethod
    def validate_event_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Oracle event timestamps must be timezone-aware")
        return value

    def unsigned_payload(self) -> dict[str, object]:
        return self.model_dump(mode="json", exclude={"event_sha256"})

    def expected_hash(self) -> str:
        return sha256_json(self.unsigned_payload())
