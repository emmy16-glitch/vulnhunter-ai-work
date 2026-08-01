"""Unified finding, remediation, and retest lifecycle contracts."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from vulnhunter.actions.models import sha256_json

_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FIX_VERDICT = re.compile(
    r"^(fixed|partially_fixed|not_fixed|regression_detected|cannot_verify|out_of_scope_change)$"
)


def utc_now() -> datetime:
    return datetime.now(UTC)


class FindingSeverity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VerificationState(StrEnum):
    OBSERVED = "observed"
    NEEDS_REVIEW = "needs_review"
    VERIFIED = "verified"
    CONFLICTED = "conflicted"
    FALSE_POSITIVE = "false_positive"


class FindingStatus(StrEnum):
    OPEN = "open"
    TRIAGED = "triaged"
    IN_REMEDIATION = "in_remediation"
    READY_FOR_RETEST = "ready_for_retest"
    RETESTING = "retesting"
    REMEDIATED = "remediated"
    ACCEPTED_RISK = "accepted_risk"
    CLOSED = "closed"


class RemediationState(StrEnum):
    READY_FOR_IMPLEMENTATION = "ready_for_implementation"
    NEEDS_REWORK = "needs_rework"
    READY_FOR_RETEST = "ready_for_retest"
    CANCELLED = "cancelled"
    FAILED = "failed"


class EvidenceReference(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence_id: str
    sha256: str
    provenance: str = Field(min_length=3, max_length=1_000)
    content_type: str = Field(min_length=3, max_length=200)

    @field_validator("evidence_id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("evidence_id must be a stable identifier")
        return value

    @field_validator("sha256")
    @classmethod
    def validate_sha(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("sha256 must be a digest")
        return value


class RemediationVerificationReference(BaseModel):
    """Integrity pointer to one immutable developer handoff and verifier verdict."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    receipt_id: str
    sha256: str
    verdict: str
    original_revision: str = Field(min_length=1, max_length=256)
    fixed_revision: str = Field(min_length=1, max_length=256)
    created_at: datetime

    @field_validator("receipt_id")
    @classmethod
    def validate_receipt_id(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("verification receipt ID must be a stable identifier")
        return value

    @field_validator("sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("verification receipt sha256 must be a digest")
        return value

    @field_validator("verdict")
    @classmethod
    def validate_verdict(cls, value: str) -> str:
        if _FIX_VERDICT.fullmatch(value) is None:
            raise ValueError("verification verdict is not supported")
        return value

    @model_validator(mode="after")
    def validate_reference(self) -> Self:
        if self.original_revision == self.fixed_revision:
            raise ValueError("verification reference requires a changed revision")
        if self.created_at.tzinfo is None or self.created_at.utcoffset() is None:
            raise ValueError("verification receipt time must be timezone-aware")
        return self


class RemediationRecord(BaseModel):
    """A legacy note or an exact human-owned remediation plan.

    The original summary-only shape remains valid for backward compatibility. A
    governed record is present when ``remediation_id`` is set; all plan fields
    then become mandatory and are digest-bound to one exact finding revision.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    summary: str = Field(min_length=10, max_length=5_000)
    owner_id: str | None = None
    due_at: datetime | None = None
    references: tuple[str, ...] = ()
    remediation_id: str | None = None
    state: RemediationState | None = None
    source_finding_revision: int | None = Field(default=None, ge=0)
    source_finding_fingerprint: str | None = None
    plan_sha256: str | None = None
    target_references: tuple[str, ...] = ()
    regression_test: str | None = Field(default=None, min_length=3, max_length=4_000)
    verification_recipe: str | None = Field(default=None, min_length=3, max_length=4_000)
    compatibility_risks: tuple[str, ...] = ()
    verification_history: tuple[RemediationVerificationReference, ...] = ()
    created_at: datetime | None = None
    expires_at: datetime | None = None
    cancelled_at: datetime | None = None
    cancellation_reason: str | None = Field(default=None, min_length=3, max_length=1_000)

    @field_validator("owner_id")
    @classmethod
    def validate_owner_id(cls, value: str | None) -> str | None:
        if value is not None and _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("remediation owner must be a stable lowercase identifier")
        return value

    @field_validator("source_finding_fingerprint", "plan_sha256")
    @classmethod
    def validate_optional_sha(cls, value: str | None) -> str | None:
        if value is not None and _SHA256.fullmatch(value) is None:
            raise ValueError("remediation digest fields must be SHA-256 values")
        return value

    @field_validator("target_references")
    @classmethod
    def validate_target_references(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        cleaned = tuple(" ".join(value.split()) for value in values if value.strip())
        if any(len(value) > 1_000 for value in cleaned):
            raise ValueError("remediation target references must not exceed 1,000 characters")
        return cleaned

    @model_validator(mode="after")
    def validate_governed_record(self) -> Self:
        if self.remediation_id is None:
            governed_values = (
                self.state,
                self.source_finding_revision,
                self.source_finding_fingerprint,
                self.plan_sha256,
                self.target_references,
                self.regression_test,
                self.verification_recipe,
                self.compatibility_risks,
                self.verification_history,
                self.created_at,
                self.expires_at,
                self.cancelled_at,
                self.cancellation_reason,
            )
            if any(value not in (None, (), "") for value in governed_values):
                raise ValueError("governed remediation fields require remediation_id")
            return self

        if _IDENTIFIER.fullmatch(self.remediation_id) is None:
            raise ValueError("remediation_id must be a stable lowercase identifier")
        required = {
            "owner_id": self.owner_id,
            "state": self.state,
            "source_finding_revision": self.source_finding_revision,
            "source_finding_fingerprint": self.source_finding_fingerprint,
            "plan_sha256": self.plan_sha256,
            "regression_test": self.regression_test,
            "verification_recipe": self.verification_recipe,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        }
        missing = [name for name, value in required.items() if value is None]
        if missing:
            raise ValueError(
                "governed remediation record is missing: " + ", ".join(sorted(missing))
            )
        if not self.target_references:
            raise ValueError("governed remediation plan requires exact target references")
        assert self.created_at is not None
        assert self.expires_at is not None
        if self.created_at.tzinfo is None or self.created_at.utcoffset() is None:
            raise ValueError("remediation creation time must be timezone-aware")
        if self.expires_at.tzinfo is None or self.expires_at.utcoffset() is None:
            raise ValueError("remediation expiry must be timezone-aware")
        if self.expires_at <= self.created_at:
            raise ValueError("remediation expiry must follow creation")
        if self.due_at is not None:
            if self.due_at.tzinfo is None or self.due_at.utcoffset() is None:
                raise ValueError("remediation due time must be timezone-aware")
            if self.due_at < self.created_at:
                raise ValueError("remediation due time cannot predate creation")

        latest = self.verification_history[-1] if self.verification_history else None
        if self.state == RemediationState.READY_FOR_IMPLEMENTATION:
            if latest is not None:
                raise ValueError("ready-for-implementation plans cannot already have verification")
        elif self.state == RemediationState.NEEDS_REWORK:
            if latest is None or latest.verdict == "fixed":
                raise ValueError("needs-rework plans require a non-fixed verification receipt")
        elif self.state == RemediationState.READY_FOR_RETEST:
            if latest is None or latest.verdict != "fixed":
                raise ValueError("ready-for-retest plans require a fixed verification receipt")

        if self.state == RemediationState.CANCELLED:
            if self.cancelled_at is None or self.cancellation_reason is None:
                raise ValueError("cancelled remediation requires time and reason")
        elif self.cancelled_at is not None or self.cancellation_reason is not None:
            raise ValueError("cancellation metadata requires cancelled remediation state")
        return self

    @classmethod
    def create(
        cls,
        *,
        finding_id: str,
        finding_revision: int,
        finding_fingerprint: str,
        summary: str,
        owner_id: str,
        target_references: tuple[str, ...],
        regression_test: str,
        verification_recipe: str,
        compatibility_risks: tuple[str, ...] = (),
        references: tuple[str, ...] = (),
        created_at: datetime,
        expires_at: datetime,
        due_at: datetime | None = None,
    ) -> RemediationRecord:
        canonical = {
            "finding_id": finding_id,
            "finding_revision": finding_revision,
            "finding_fingerprint": finding_fingerprint,
            "summary": " ".join(summary.split()),
            "owner_id": owner_id,
            "target_references": list(target_references),
            "regression_test": " ".join(regression_test.split()),
            "verification_recipe": " ".join(verification_recipe.split()),
            "compatibility_risks": list(compatibility_risks),
            "references": list(references),
            "created_at": created_at.astimezone(UTC).isoformat(),
            "expires_at": expires_at.astimezone(UTC).isoformat(),
            "due_at": due_at.astimezone(UTC).isoformat() if due_at else None,
        }
        digest = sha256_json(canonical)
        return cls(
            remediation_id=f"remediation-{digest[:32]}",
            state=RemediationState.READY_FOR_IMPLEMENTATION,
            source_finding_revision=finding_revision,
            source_finding_fingerprint=finding_fingerprint,
            plan_sha256=digest,
            summary=canonical["summary"],
            owner_id=owner_id,
            due_at=due_at,
            references=references,
            target_references=target_references,
            regression_test=canonical["regression_test"],
            verification_recipe=canonical["verification_recipe"],
            compatibility_risks=compatibility_risks,
            created_at=created_at,
            expires_at=expires_at,
        )

    def record_verification(
        self,
        reference: RemediationVerificationReference,
    ) -> RemediationRecord:
        if self.remediation_id is None or self.state is None:
            raise ValueError("legacy remediation notes cannot record governed verification")
        if self.state not in {
            RemediationState.READY_FOR_IMPLEMENTATION,
            RemediationState.NEEDS_REWORK,
        }:
            raise ValueError("the remediation plan is not accepting implementation receipts")
        if any(item.receipt_id == reference.receipt_id for item in self.verification_history):
            raise ValueError("the fix-verification receipt is already recorded")
        state = (
            RemediationState.READY_FOR_RETEST
            if reference.verdict == "fixed"
            else RemediationState.NEEDS_REWORK
        )
        return RemediationRecord.model_validate(
            self.model_copy(
                update={
                    "state": state,
                    "verification_history": self.verification_history + (reference,),
                }
            ).model_dump()
        )

    def cancel(self, *, cancelled_at: datetime, reason: str) -> RemediationRecord:
        if self.remediation_id is None or self.state is None:
            raise ValueError("legacy remediation notes cannot be cancelled as governed plans")
        if self.state in {
            RemediationState.CANCELLED,
            RemediationState.FAILED,
            RemediationState.READY_FOR_RETEST,
        }:
            raise ValueError("terminal or verified remediation plans cannot be cancelled")
        return RemediationRecord.model_validate(
            self.model_copy(
                update={
                    "state": RemediationState.CANCELLED,
                    "cancelled_at": cancelled_at,
                    "cancellation_reason": " ".join(reason.split())[:1_000],
                }
            ).model_dump()
        )


class RetestRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    retest_id: str
    performed_by: str
    performed_at: datetime = Field(default_factory=utc_now)
    outcome: str = Field(pattern=r"^(passed|failed|partial|blocked)$")
    evidence: tuple[EvidenceReference, ...] = ()
    notes: str = Field(min_length=3, max_length=5_000)

    @field_validator("retest_id", "performed_by")
    @classmethod
    def validate_id(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("identifier must be stable and lowercase")
        return value


class Finding(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    finding_id: str
    campaign_id: str
    fingerprint: str
    title: str = Field(min_length=3, max_length=300)
    description: str = Field(min_length=10, max_length=20_000)
    severity: FindingSeverity
    confidence: int = Field(ge=0, le=100)
    verification: VerificationState = VerificationState.OBSERVED
    status: FindingStatus = FindingStatus.OPEN
    affected_asset: str = Field(min_length=1, max_length=1_000)
    affected_component: str | None = Field(default=None, max_length=1_000)
    cwe_ids: tuple[str, ...] = ()
    cve_ids: tuple[str, ...] = ()
    owasp_mappings: tuple[str, ...] = ()
    evidence: tuple[EvidenceReference, ...] = ()
    attack_path_ids: tuple[str, ...] = ()
    remediation: RemediationRecord | None = None
    retests: tuple[RetestRecord, ...] = ()
    analyst_decision: str | None = Field(default=None, max_length=5_000)
    revision: int = Field(default=0, ge=0)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    @field_validator("finding_id", "campaign_id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("identifier must be stable and lowercase")
        return value

    @field_validator("fingerprint")
    @classmethod
    def validate_fingerprint(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("fingerprint must be a SHA-256 digest")
        return value

    @model_validator(mode="after")
    def validate_lifecycle(self) -> Self:
        if self.updated_at < self.created_at:
            raise ValueError("updated_at cannot predate creation")
        if self.verification == VerificationState.VERIFIED and not self.evidence:
            raise ValueError("verified findings require evidence")
        if self.status == FindingStatus.IN_REMEDIATION:
            if (
                self.remediation is None
                or self.remediation.remediation_id is None
                or self.remediation.state
                not in {
                    RemediationState.READY_FOR_IMPLEMENTATION,
                    RemediationState.NEEDS_REWORK,
                }
            ):
                raise ValueError("in-remediation findings require an active governed plan")
        if self.status == FindingStatus.READY_FOR_RETEST:
            if (
                self.remediation is None
                or self.remediation.remediation_id is None
                or self.remediation.state != RemediationState.READY_FOR_RETEST
            ):
                raise ValueError("ready-for-retest findings require a fixed verification receipt")
        if self.status == FindingStatus.REMEDIATED:
            if not self.retests or self.retests[-1].outcome != "passed":
                raise ValueError("remediated findings require a passed retest")
        return self

    @classmethod
    def create_fingerprint(
        cls,
        *,
        campaign_id: str,
        title: str,
        affected_asset: str,
        affected_component: str | None,
    ) -> str:
        return sha256_json(
            {
                "campaign_id": campaign_id,
                "title": title.strip().casefold(),
                "affected_asset": affected_asset.strip().casefold(),
                "affected_component": (affected_component or "").strip().casefold(),
            }
        )

    def validate_update_from(self, previous: Finding) -> None:
        for name in ("finding_id", "campaign_id", "fingerprint", "created_at"):
            if getattr(self, name) != getattr(previous, name):
                raise ValueError(f"finding field is immutable: {name}")
        if self.revision != previous.revision + 1:
            raise ValueError("finding revision must increase by exactly one")
        if self.updated_at < previous.updated_at:
            raise ValueError("finding updated_at cannot move backwards")
        old_evidence = {item.sha256 for item in previous.evidence}
        new_evidence = {item.sha256 for item in self.evidence}
        if not old_evidence.issubset(new_evidence):
            raise ValueError("finding evidence is append-only")
        if self.retests[: len(previous.retests)] != previous.retests:
            raise ValueError("finding retest history is append-only")
        old_remediation = previous.remediation
        new_remediation = self.remediation
        if old_remediation is not None and old_remediation.remediation_id is not None:
            if new_remediation is None:
                raise ValueError("governed remediation history cannot be removed")
            if new_remediation.remediation_id != old_remediation.remediation_id:
                raise ValueError("governed remediation identifier is immutable")
            if (
                new_remediation.verification_history[: len(old_remediation.verification_history)]
                != old_remediation.verification_history
            ):
                raise ValueError("remediation verification history is append-only")
            if old_remediation.state in {
                RemediationState.CANCELLED,
                RemediationState.FAILED,
                RemediationState.READY_FOR_RETEST,
            }:
                if new_remediation != old_remediation:
                    raise ValueError("terminal remediation record is immutable")
