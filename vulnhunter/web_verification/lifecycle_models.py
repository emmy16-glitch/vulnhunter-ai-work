"""Immutable contracts for the governed web-verification lifecycle."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from vulnhunter.actions.models import sha256_json
from vulnhunter.web_hunters.models import VerificationStrategy
from vulnhunter.web_verification.external_models import (
    ExternalEvidenceAdmissionBatch,
    ExternalEvidenceClass,
)
from vulnhunter.web_verification.models import VerificationVerdict

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
_KEY_ID = re.compile(r"^sha256:[0-9a-f]{64}$")


class VerificationCaseState(StrEnum):
    EVIDENCE_ADMITTED = "evidence_admitted"
    ADJUDICATED = "adjudicated"
    AWAITING_HUMAN_REVIEW = "awaiting_human_review"
    FINALIZED = "finalized"


class AdjudicationReason(StrEnum):
    PASSIVE_REJECTION = "passive_rejection"
    VALIDATION_GRADE_SUPPORT = "validation_grade_support"
    EVIDENCE_REFUTATION = "evidence_refutation"
    CONFLICTING_EVIDENCE = "conflicting_evidence"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


class HumanReviewRole(StrEnum):
    PRIMARY = "primary"
    ADJUDICATOR = "adjudicator"


class VerificationCaseSnapshot(BaseModel):
    """Current integrity-linked state for one exact verification hypothesis."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: int = 1
    case_id: str
    passive_verification_id: str
    passive_verification_result_sha256: str
    authorization_id: str
    authorization_record_sha256: str
    target_reference_sha256: str
    strategy: VerificationStrategy
    state: VerificationCaseState
    revision: int = Field(ge=0)
    assessment_run_id: str | None = Field(default=None, max_length=160)
    workspace_id: str | None = Field(default=None, max_length=160)
    admission_sha256: str
    adjudication_sha256: str | None = None
    final_decision_sha256: str | None = None
    created_at: datetime
    updated_at: datetime
    case_sha256: str

    @field_validator(
        "case_id",
        "passive_verification_id",
        "passive_verification_result_sha256",
        "authorization_record_sha256",
        "target_reference_sha256",
        "admission_sha256",
        "adjudication_sha256",
        "final_decision_sha256",
        "case_sha256",
    )
    @classmethod
    def validate_hash(cls, value: str | None) -> str | None:
        if value is not None and _SHA256.fullmatch(value) is None:
            raise ValueError("verification lifecycle identities must be SHA-256 digests")
        return value

    @field_validator("authorization_id")
    @classmethod
    def validate_authorization_id(cls, value: str) -> str:
        if not value.strip() or len(value) > 80:
            raise ValueError("verification authorization ID is invalid")
        return value

    @field_validator("created_at", "updated_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("verification lifecycle timestamps must include a timezone")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_snapshot(self):
        if self.schema_version != 1:
            raise ValueError("verification lifecycle case schema is unsupported")
        if self.updated_at < self.created_at:
            raise ValueError("verification case update cannot predate creation")
        if self.state is VerificationCaseState.EVIDENCE_ADMITTED and self.adjudication_sha256:
            raise ValueError("an evidence-only case cannot already bind adjudication")
        if self.state is VerificationCaseState.FINALIZED and not self.final_decision_sha256:
            raise ValueError("a finalized case must bind its final decision")
        expected = sha256_json(self.model_dump(mode="json", exclude={"case_sha256"}))
        if expected != self.case_sha256:
            raise ValueError("verification case integrity hash does not match its contents")
        return self


class PersistedEvidenceAdmission(BaseModel):
    """Receipt admission after atomic ledger persistence and live authorization checks."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: int = 1
    case_id: str
    authorization_id: str
    authorization_record_sha256: str
    admission: ExternalEvidenceAdmissionBatch
    receipt_ids: tuple[str, ...] = Field(min_length=1, max_length=50)
    persisted_at: datetime
    durable_replay_protection_established: Literal[True] = True
    live_authorization_revalidated: Literal[True] = True
    finding_validation_permitted: Literal[False] = False
    ledger_sha256: str

    @field_validator("case_id", "authorization_record_sha256", "ledger_sha256")
    @classmethod
    def validate_hash(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("persisted evidence identities must be SHA-256 digests")
        return value

    @field_validator("receipt_ids")
    @classmethod
    def validate_receipts(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(_SHA256.fullmatch(value) is None for value in values):
            raise ValueError("persisted receipt IDs must be SHA-256 digests")
        if len(values) != len(set(values)) or tuple(sorted(values)) != values:
            raise ValueError("persisted receipt IDs must be unique and canonical")
        return values

    @field_validator("persisted_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("evidence persistence timestamp must include a timezone")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_record(self):
        if self.schema_version != 1:
            raise ValueError("persisted evidence schema is unsupported")
        admission_receipts = tuple(item.receipt.receipt_id for item in self.admission.receipts)
        if admission_receipts != self.receipt_ids:
            raise ValueError("persisted receipt IDs must match the admitted receipts")
        expected = sha256_json(self.model_dump(mode="json", exclude={"ledger_sha256"}))
        if expected != self.ledger_sha256:
            raise ValueError("persisted evidence hash does not match its contents")
        return self


class StrategyAdjudication(BaseModel):
    """Deterministic candidate verdict; final authority remains human."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: int = 1
    case_id: str
    strategy: VerificationStrategy
    candidate_verdict: VerificationVerdict
    reason: AdjudicationReason
    allowed_human_verdicts: tuple[VerificationVerdict, ...] = Field(min_length=1, max_length=3)
    receipt_ids: tuple[str, ...] = Field(min_length=1, max_length=50)
    created_at: datetime
    human_review_required: Literal[True] = True
    adjudication_sha256: str

    @field_validator("case_id", "adjudication_sha256")
    @classmethod
    def validate_hash(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("adjudication identities must be SHA-256 digests")
        return value

    @field_validator("receipt_ids")
    @classmethod
    def validate_receipts(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)) or tuple(sorted(values)) != values:
            raise ValueError("adjudication receipts must be unique and canonical")
        return values

    @field_validator("created_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("adjudication timestamp must include a timezone")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_adjudication(self):
        if self.schema_version != 1:
            raise ValueError("strategy adjudication schema is unsupported")
        canonical = tuple(sorted(self.allowed_human_verdicts, key=lambda item: item.value))
        if canonical != self.allowed_human_verdicts or len(canonical) != len(set(canonical)):
            raise ValueError("allowed human verdicts must be unique and canonical")
        if self.candidate_verdict not in self.allowed_human_verdicts:
            raise ValueError("candidate verdict must remain inside the human-review ceiling")
        if self.reason is AdjudicationReason.VALIDATION_GRADE_SUPPORT:
            if self.candidate_verdict is not VerificationVerdict.VALIDATED:
                raise ValueError("validation-grade support must produce a validated candidate")
        elif self.reason in {
            AdjudicationReason.PASSIVE_REJECTION,
            AdjudicationReason.EVIDENCE_REFUTATION,
        }:
            if self.candidate_verdict is not VerificationVerdict.REJECTED:
                raise ValueError("refutation must produce a rejected candidate")
        elif self.candidate_verdict is not VerificationVerdict.INCONCLUSIVE:
            raise ValueError("conflicting or insufficient evidence must remain inconclusive")
        expected = sha256_json(self.model_dump(mode="json", exclude={"adjudication_sha256"}))
        if expected != self.adjudication_sha256:
            raise ValueError("adjudication hash does not match its contents")
        return self


class HumanVerificationReview(BaseModel):
    """One authenticated, immutable human decision."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: int = 1
    review_id: str
    case_id: str
    adjudication_sha256: str
    reviewer_id: str
    role: HumanReviewRole
    verdict: VerificationVerdict
    submitted_at: datetime
    review_sha256: str

    @field_validator("review_id", "case_id", "adjudication_sha256", "review_sha256")
    @classmethod
    def validate_hash(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("human verification review identities must be SHA-256 digests")
        return value

    @field_validator("reviewer_id")
    @classmethod
    def validate_reviewer(cls, value: str) -> str:
        normalized = value.strip().casefold()
        if _IDENTIFIER.fullmatch(normalized) is None:
            raise ValueError("reviewer identity must be a stable lowercase identifier")
        return normalized

    @field_validator("submitted_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("human review timestamp must include a timezone")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_review(self):
        if self.schema_version != 1:
            raise ValueError("human verification review schema is unsupported")
        expected_id = sha256_json(
            {
                "case_id": self.case_id,
                "adjudication_sha256": self.adjudication_sha256,
                "reviewer_id": self.reviewer_id,
                "role": self.role.value,
            }
        )
        if expected_id != self.review_id:
            raise ValueError("human verification review ID does not match its authority binding")
        expected = sha256_json(self.model_dump(mode="json", exclude={"review_sha256"}))
        if expected != self.review_sha256:
            raise ValueError("human verification review hash does not match its contents")
        return self


class FinalVerificationDecision(BaseModel):
    """Terminal human-governed verdict with no severity, publication or remediation authority."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: int = 1
    decision_id: str
    case_id: str
    adjudication_sha256: str
    verdict: VerificationVerdict
    authorization_id: str
    authorization_record_sha256: str
    receipt_ids: tuple[str, ...] = Field(min_length=1, max_length=50)
    primary_review_ids: tuple[str, str]
    adjudicator_review_id: str | None = None
    decided_at: datetime
    human_review_completed: Literal[True] = True
    finding_confirmation_authority: Literal["governed_human_review"] = "governed_human_review"
    severity_assignment_permitted: Literal[False] = False
    publication_permitted: Literal[False] = False
    automatic_remediation_permitted: Literal[False] = False
    decision_sha256: str

    @field_validator(
        "decision_id",
        "case_id",
        "adjudication_sha256",
        "authorization_record_sha256",
        "adjudicator_review_id",
        "decision_sha256",
    )
    @classmethod
    def validate_hash(cls, value: str | None) -> str | None:
        if value is not None and _SHA256.fullmatch(value) is None:
            raise ValueError("final verification identities must be SHA-256 digests")
        return value

    @field_validator("receipt_ids", "primary_review_ids")
    @classmethod
    def validate_id_sets(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(_SHA256.fullmatch(value) is None for value in values):
            raise ValueError("final verification references must be SHA-256 digests")
        if len(values) != len(set(values)):
            raise ValueError("final verification references must be unique")
        return values

    @field_validator("decided_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("final verification timestamp must include a timezone")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_decision(self):
        if self.schema_version != 1:
            raise ValueError("final verification decision schema is unsupported")
        expected_id = sha256_json(
            {
                "case_id": self.case_id,
                "adjudication_sha256": self.adjudication_sha256,
                "primary_review_ids": list(self.primary_review_ids),
                "adjudicator_review_id": self.adjudicator_review_id,
            }
        )
        if self.decision_id != expected_id:
            raise ValueError("final verification decision ID does not match its review binding")
        expected = sha256_json(self.model_dump(mode="json", exclude={"decision_sha256"}))
        if expected != self.decision_sha256:
            raise ValueError("final verification decision hash does not match its contents")
        return self


class VerificationWorkerCapability(BaseModel):
    """Non-executing capability contract for an independently governed evidence worker."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: int = 1
    worker_id: str
    runtime_sha256: str
    evidence_class: ExternalEvidenceClass
    strategies: tuple[VerificationStrategy, ...] = Field(min_length=1, max_length=12)
    network_access_allowed: bool = False
    network_methods: tuple[Literal["GET", "HEAD"], ...] = ()
    maximum_evidence_bytes: int = Field(default=5_000_000, ge=1, le=50_000_000)
    mutating_requests_allowed: Literal[False] = False
    credential_use_allowed: Literal[False] = False
    authorization_bypass_allowed: Literal[False] = False
    shell_execution_allowed: Literal[False] = False
    payload_execution_allowed: Literal[False] = False
    capability_sha256: str

    @field_validator("worker_id")
    @classmethod
    def validate_worker_id(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("verification worker ID must be a stable lowercase identifier")
        return value

    @field_validator("runtime_sha256", "capability_sha256")
    @classmethod
    def validate_hash(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("verification worker hashes must be SHA-256 digests")
        return value

    @model_validator(mode="after")
    def validate_capability(self):
        if self.schema_version != 1:
            raise ValueError("verification worker capability schema is unsupported")
        strategies = tuple(sorted(self.strategies, key=lambda item: item.value))
        if strategies != self.strategies or len(strategies) != len(set(strategies)):
            raise ValueError("verification worker strategies must be unique and canonical")
        methods = tuple(sorted(self.network_methods))
        if methods != self.network_methods or len(methods) != len(set(methods)):
            raise ValueError("verification worker methods must be unique and canonical")
        if self.network_access_allowed and not self.network_methods:
            raise ValueError("network-capable verification workers must declare GET/HEAD methods")
        if not self.network_access_allowed and self.network_methods:
            raise ValueError("offline verification workers cannot declare network methods")
        if self.evidence_class is ExternalEvidenceClass.OFFLINE_ARTIFACT_REVIEW:
            if self.network_access_allowed:
                raise ValueError("offline verification workers cannot use network access")
        expected = sha256_json(self.model_dump(mode="json", exclude={"capability_sha256"}))
        if expected != self.capability_sha256:
            raise ValueError("verification worker capability hash does not match its contents")
        return self


class VerificationCollectionPlan(BaseModel):
    """Exact non-shell collection intent for one trusted worker and authorization snapshot."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: int = 1
    plan_id: str
    worker_id: str
    worker_runtime_sha256: str
    capability_sha256: str
    collector_id: str
    collector_key_id: str
    passive_verification_id: str
    passive_verification_result_sha256: str
    authorization_id: str
    authorization_reference_sha256: str
    authorization_snapshot_sha256: str
    target_reference_sha256: str
    strategy: VerificationStrategy
    evidence_class: ExternalEvidenceClass
    network_access_allowed: bool
    network_methods: tuple[Literal["GET", "HEAD"], ...]
    maximum_evidence_bytes: int = Field(ge=1, le=50_000_000)
    expires_at: datetime
    execution_command_included: Literal[False] = False
    mutating_requests_allowed: Literal[False] = False
    credential_use_allowed: Literal[False] = False
    authorization_bypass_allowed: Literal[False] = False
    shell_execution_allowed: Literal[False] = False
    payload_execution_allowed: Literal[False] = False
    plan_sha256: str

    @field_validator(
        "plan_id",
        "worker_runtime_sha256",
        "capability_sha256",
        "passive_verification_id",
        "passive_verification_result_sha256",
        "authorization_reference_sha256",
        "authorization_snapshot_sha256",
        "target_reference_sha256",
        "plan_sha256",
    )
    @classmethod
    def validate_hash(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("verification collection plan identities must be SHA-256 digests")
        return value

    @field_validator("collector_key_id")
    @classmethod
    def validate_key_id(cls, value: str) -> str:
        if _KEY_ID.fullmatch(value) is None:
            raise ValueError("verification collection plan collector key is invalid")
        return value

    @field_validator("expires_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("verification collection plan expiry must include a timezone")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_plan(self):
        if self.schema_version != 1:
            raise ValueError("verification collection plan schema is unsupported")
        expected_id = sha256_json(
            {
                "worker_id": self.worker_id,
                "capability_sha256": self.capability_sha256,
                "passive_verification_result_sha256": self.passive_verification_result_sha256,
                "authorization_snapshot_sha256": self.authorization_snapshot_sha256,
                "strategy": self.strategy.value,
                "evidence_class": self.evidence_class.value,
            }
        )
        if expected_id != self.plan_id:
            raise ValueError("verification collection plan ID does not match its bindings")
        expected = sha256_json(self.model_dump(mode="json", exclude={"plan_sha256"}))
        if expected != self.plan_sha256:
            raise ValueError("verification collection plan hash does not match its contents")
        return self


def verification_case_id_for(
    *, passive_verification_result_sha256: str, authorization_record_sha256: str
) -> str:
    return sha256_json(
        {
            "passive_verification_result_sha256": passive_verification_result_sha256,
            "authorization_record_sha256": authorization_record_sha256,
        }
    )
