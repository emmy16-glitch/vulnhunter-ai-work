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
_RETEST_OUTCOME = re.compile(r"^(passed|failed|partial|cannot_verify|blocked|cancelled)$")


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
    AWAITING_REMEDIATION_REVIEW = "awaiting_remediation_review"
    READY_FOR_REPORT = "ready_for_report"
    REMEDIATED = "remediated"
    ACCEPTED_RISK = "accepted_risk"
    CLOSED = "closed"


class RemediationState(StrEnum):
    READY_FOR_IMPLEMENTATION = "ready_for_implementation"
    NEEDS_REWORK = "needs_rework"
    READY_FOR_RETEST = "ready_for_retest"
    RETEST_NEEDS_REWORK = "retest_needs_rework"
    AWAITING_REVIEW = "awaiting_review"
    REVIEW_NEEDS_REWORK = "review_needs_rework"
    REVIEW_APPROVED = "review_approved"
    CANCELLED = "cancelled"
    FAILED = "failed"


class RetestOutcome(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    PARTIAL = "partial"
    CANNOT_VERIFY = "cannot_verify"
    BLOCKED = "blocked"
    CANCELLED = "cancelled"


class RemediationReviewOutcome(StrEnum):
    APPROVED = "approved"
    CHANGES_REQUESTED = "changes_requested"
    CANNOT_VERIFY = "cannot_verify"
    BLOCKED = "blocked"


class RemediationReviewChecklist(BaseModel):
    """Evidence-based review checklist; unknown values force abstention."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence_lineage_complete: bool | None
    fixed_revision_matches: bool | None
    approved_scope_respected: bool | None
    security_claim_supported: bool | None
    regressions_acceptable: bool | None


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


class RetestPlanRecord(BaseModel):
    """Immutable request for one bounded retest of one fixed revision."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = "1.0"
    retest_id: str
    owner_id: str
    source_finding_revision: int = Field(ge=0)
    source_finding_fingerprint: str
    remediation_id: str
    fix_verification_receipt_id: str
    fixed_revision: str = Field(min_length=1, max_length=256)
    plan_sha256: str
    check_references: tuple[str, ...] = Field(min_length=1, max_length=100)
    before_evidence_ids: tuple[str, ...] = Field(min_length=1, max_length=100)
    created_at: datetime
    expires_at: datetime

    @field_validator(
        "retest_id",
        "owner_id",
        "remediation_id",
        "fix_verification_receipt_id",
    )
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("retest identifiers must be stable lowercase values")
        return value

    @field_validator("source_finding_fingerprint", "plan_sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("retest digest fields must be SHA-256 values")
        return value

    @field_validator("check_references")
    @classmethod
    def validate_checks(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        cleaned = tuple(" ".join(value.split()) for value in values if value.strip())
        if len(cleaned) != len(values):
            raise ValueError("retest check references must not be blank")
        if any(len(value) > 1_000 for value in cleaned):
            raise ValueError("retest check references must not exceed 1,000 characters")
        if len(set(cleaned)) != len(cleaned):
            raise ValueError("retest check references must be unique")
        return cleaned

    @field_validator("before_evidence_ids")
    @classmethod
    def validate_evidence_ids(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(values)) != len(values):
            raise ValueError("retest before-evidence identifiers must be unique")
        if any(_IDENTIFIER.fullmatch(value) is None for value in values):
            raise ValueError("retest before-evidence identifiers must be stable")
        return values

    @model_validator(mode="after")
    def validate_times(self) -> Self:
        for value in (self.created_at, self.expires_at):
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError("retest timestamps must be timezone-aware")
        if self.expires_at <= self.created_at:
            raise ValueError("retest expiry must follow creation")
        return self

    @classmethod
    def create(
        cls,
        *,
        finding_id: str,
        finding_revision: int,
        finding_fingerprint: str,
        remediation_id: str,
        fix_verification_receipt_id: str,
        fixed_revision: str,
        owner_id: str,
        check_references: tuple[str, ...],
        before_evidence_ids: tuple[str, ...],
        created_at: datetime,
        expires_at: datetime,
    ) -> RetestPlanRecord:
        canonical = {
            "finding_id": finding_id,
            "finding_revision": finding_revision,
            "finding_fingerprint": finding_fingerprint,
            "remediation_id": remediation_id,
            "fix_verification_receipt_id": fix_verification_receipt_id,
            "fixed_revision": fixed_revision,
            "owner_id": owner_id,
            "check_references": list(check_references),
            "before_evidence_ids": list(before_evidence_ids),
            "created_at": created_at.astimezone(UTC).isoformat(),
            "expires_at": expires_at.astimezone(UTC).isoformat(),
        }
        digest = sha256_json(canonical)
        return cls(
            retest_id=f"retest-{digest[:32]}",
            owner_id=owner_id,
            source_finding_revision=finding_revision,
            source_finding_fingerprint=finding_fingerprint,
            remediation_id=remediation_id,
            fix_verification_receipt_id=fix_verification_receipt_id,
            fixed_revision=fixed_revision,
            plan_sha256=digest,
            check_references=check_references,
            before_evidence_ids=before_evidence_ids,
            created_at=created_at,
            expires_at=expires_at,
        )


class RetestReceiptReference(BaseModel):
    """Integrity pointer to one immutable before/after retest receipt."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    receipt_id: str
    retest_id: str
    sha256: str
    outcome: RetestOutcome
    fixed_revision: str = Field(min_length=1, max_length=256)
    created_at: datetime

    @field_validator("receipt_id", "retest_id")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("retest receipt identifiers must be stable lowercase values")
        return value

    @field_validator("sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("retest receipt sha256 must be a digest")
        return value

    @model_validator(mode="after")
    def validate_reference(self) -> Self:
        if self.created_at.tzinfo is None or self.created_at.utcoffset() is None:
            raise ValueError("retest receipt time must be timezone-aware")
        return self


class RemediationReviewPlanRecord(BaseModel):
    """Immutable identity-bound review plan for one exact passed retest."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = "1.0"
    review_id: str
    reviewer_id: str
    reviewer_identity_sha256: str
    source_finding_revision: int = Field(ge=0)
    source_finding_fingerprint: str
    remediation_id: str
    fix_verification_receipt_id: str
    retest_receipt_id: str
    fixed_revision: str = Field(min_length=1, max_length=256)
    evidence_references: tuple[str, ...] = Field(min_length=1, max_length=500)
    plan_sha256: str
    created_at: datetime
    expires_at: datetime

    @field_validator(
        "review_id",
        "reviewer_id",
        "remediation_id",
        "fix_verification_receipt_id",
        "retest_receipt_id",
    )
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("remediation review identifiers must be stable lowercase values")
        return value

    @field_validator(
        "reviewer_identity_sha256",
        "source_finding_fingerprint",
        "plan_sha256",
    )
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("remediation review digest fields must be SHA-256 values")
        return value

    @field_validator("evidence_references")
    @classmethod
    def validate_evidence_references(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(values)) != len(values):
            raise ValueError("remediation review evidence references must be unique")
        if any(_IDENTIFIER.fullmatch(value) is None for value in values):
            raise ValueError("remediation review evidence references must be stable")
        return values

    @model_validator(mode="after")
    def validate_times(self) -> Self:
        for value in (self.created_at, self.expires_at):
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError("remediation review timestamps must be timezone-aware")
        if self.expires_at <= self.created_at:
            raise ValueError("remediation review expiry must follow creation")
        return self

    @classmethod
    def create(
        cls,
        *,
        finding_id: str,
        finding_revision: int,
        finding_fingerprint: str,
        remediation_id: str,
        reviewer_id: str,
        reviewer_identity_sha256: str,
        fix_verification_receipt_id: str,
        retest_receipt_id: str,
        fixed_revision: str,
        evidence_references: tuple[str, ...],
        created_at: datetime,
        expires_at: datetime,
    ) -> RemediationReviewPlanRecord:
        canonical = {
            "finding_id": finding_id,
            "finding_revision": finding_revision,
            "finding_fingerprint": finding_fingerprint,
            "remediation_id": remediation_id,
            "reviewer_id": reviewer_id,
            "reviewer_identity_sha256": reviewer_identity_sha256,
            "fix_verification_receipt_id": fix_verification_receipt_id,
            "retest_receipt_id": retest_receipt_id,
            "fixed_revision": fixed_revision,
            "evidence_references": list(evidence_references),
            "created_at": created_at.astimezone(UTC).isoformat(),
            "expires_at": expires_at.astimezone(UTC).isoformat(),
        }
        digest = sha256_json(canonical)
        return cls(
            review_id=f"review-{digest[:32]}",
            reviewer_id=reviewer_id,
            reviewer_identity_sha256=reviewer_identity_sha256,
            source_finding_revision=finding_revision,
            source_finding_fingerprint=finding_fingerprint,
            remediation_id=remediation_id,
            fix_verification_receipt_id=fix_verification_receipt_id,
            retest_receipt_id=retest_receipt_id,
            fixed_revision=fixed_revision,
            evidence_references=evidence_references,
            plan_sha256=digest,
            created_at=created_at,
            expires_at=expires_at,
        )


class RemediationReviewReference(BaseModel):
    """Integrity pointer to one signed independent remediation review."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    receipt_id: str
    review_id: str
    sha256: str
    outcome: RemediationReviewOutcome
    reviewer_id: str
    reviewer_identity_sha256: str
    fixed_revision: str = Field(min_length=1, max_length=256)
    retest_receipt_id: str
    created_at: datetime

    @field_validator("receipt_id", "review_id", "reviewer_id", "retest_receipt_id")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("remediation review references require stable identifiers")
        return value

    @field_validator("sha256", "reviewer_identity_sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("remediation review reference requires SHA-256 values")
        return value

    @model_validator(mode="after")
    def validate_reference(self) -> Self:
        if self.created_at.tzinfo is None or self.created_at.utcoffset() is None:
            raise ValueError("remediation review receipt time must be timezone-aware")
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
    retest_history: tuple[RetestReceiptReference, ...] = ()
    review_history: tuple[RemediationReviewReference, ...] = ()
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
                self.retest_history,
                self.review_history,
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

        latest_verification = self.verification_history[-1] if self.verification_history else None
        latest_retest = self.retest_history[-1] if self.retest_history else None
        latest_review = self.review_history[-1] if self.review_history else None
        if self.state == RemediationState.READY_FOR_IMPLEMENTATION:
            if latest_verification is not None or latest_retest is not None:
                raise ValueError("ready-for-implementation plans cannot have later receipts")
        elif self.state == RemediationState.NEEDS_REWORK:
            if latest_verification is None or latest_verification.verdict == "fixed":
                raise ValueError("needs-rework plans require a non-fixed verification receipt")
        elif self.state == RemediationState.READY_FOR_RETEST:
            if latest_verification is None or latest_verification.verdict != "fixed":
                raise ValueError("ready-for-retest plans require a fixed verification receipt")
            if latest_retest is not None and latest_retest.outcome != RetestOutcome.CANCELLED:
                raise ValueError("ready-for-retest allows only a cancelled prior retest")
        elif self.state == RemediationState.RETEST_NEEDS_REWORK:
            if latest_retest is None or latest_retest.outcome not in {
                RetestOutcome.FAILED,
                RetestOutcome.PARTIAL,
                RetestOutcome.CANNOT_VERIFY,
                RetestOutcome.BLOCKED,
            }:
                raise ValueError("retest-needs-rework requires a non-passing retest receipt")
        elif self.state == RemediationState.AWAITING_REVIEW:
            if latest_retest is None or latest_retest.outcome != RetestOutcome.PASSED:
                raise ValueError("awaiting-review remediation requires a passed retest receipt")
            if (
                latest_review is not None
                and latest_review.outcome == RemediationReviewOutcome.APPROVED
            ):
                raise ValueError("approved remediation cannot remain awaiting review")
        elif self.state == RemediationState.REVIEW_NEEDS_REWORK:
            if latest_review is None or latest_review.outcome not in {
                RemediationReviewOutcome.CHANGES_REQUESTED,
                RemediationReviewOutcome.CANNOT_VERIFY,
                RemediationReviewOutcome.BLOCKED,
            }:
                raise ValueError("review-needs-rework requires a non-approved review receipt")
        elif self.state == RemediationState.REVIEW_APPROVED:
            if latest_review is None or latest_review.outcome != RemediationReviewOutcome.APPROVED:
                raise ValueError("review-approved remediation requires an approved review receipt")

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
            RemediationState.REVIEW_NEEDS_REWORK,
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

    def record_retest(self, reference: RetestReceiptReference) -> RemediationRecord:
        if self.remediation_id is None or self.state is None:
            raise ValueError("legacy remediation notes cannot record governed retests")
        if self.state != RemediationState.READY_FOR_RETEST:
            raise ValueError("the remediation plan is not ready for a governed retest result")
        if any(item.receipt_id == reference.receipt_id for item in self.retest_history):
            raise ValueError("the retest receipt is already recorded")
        latest_verification = self.verification_history[-1] if self.verification_history else None
        if (
            latest_verification is None
            or reference.fixed_revision != latest_verification.fixed_revision
        ):
            raise ValueError("the retest receipt is bound to a different fixed revision")
        if reference.outcome == RetestOutcome.PASSED:
            state = RemediationState.AWAITING_REVIEW
        elif reference.outcome == RetestOutcome.CANCELLED:
            state = RemediationState.READY_FOR_RETEST
        else:
            state = RemediationState.RETEST_NEEDS_REWORK
        return RemediationRecord.model_validate(
            self.model_copy(
                update={
                    "state": state,
                    "retest_history": self.retest_history + (reference,),
                }
            ).model_dump()
        )

    def record_review(self, reference: RemediationReviewReference) -> RemediationRecord:
        if self.remediation_id is None or self.state is None:
            raise ValueError("legacy remediation notes cannot record governed review")
        if self.state != RemediationState.AWAITING_REVIEW:
            raise ValueError("the remediation plan is not accepting an independent review")
        if any(item.receipt_id == reference.receipt_id for item in self.review_history):
            raise ValueError("the remediation review receipt is already recorded")
        latest_verification = self.verification_history[-1] if self.verification_history else None
        latest_retest = self.retest_history[-1] if self.retest_history else None
        if latest_verification is None or latest_retest is None:
            raise ValueError("remediation review requires fixed-verification and retest history")
        if latest_verification.fixed_revision != reference.fixed_revision:
            raise ValueError("remediation review is bound to another fixed revision")
        if latest_retest.receipt_id != reference.retest_receipt_id:
            raise ValueError("remediation review is bound to another retest receipt")
        state = (
            RemediationState.REVIEW_APPROVED
            if reference.outcome == RemediationReviewOutcome.APPROVED
            else RemediationState.REVIEW_NEEDS_REWORK
        )
        return RemediationRecord.model_validate(
            self.model_copy(
                update={
                    "state": state,
                    "review_history": self.review_history + (reference,),
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
            RemediationState.RETEST_NEEDS_REWORK,
            RemediationState.AWAITING_REVIEW,
            RemediationState.REVIEW_NEEDS_REWORK,
            RemediationState.REVIEW_APPROVED,
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
    """Legacy direct retest record retained for backward compatibility."""

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
    retest_plans: tuple[RetestPlanRecord, ...] = ()
    retest_results: tuple[RetestReceiptReference, ...] = ()
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

        plan_ids = [item.retest_id for item in self.retest_plans]
        result_retest_ids = [item.retest_id for item in self.retest_results]
        result_receipt_ids = [item.receipt_id for item in self.retest_results]
        if len(set(plan_ids)) != len(plan_ids):
            raise ValueError("governed retest plan identifiers must be unique")
        if len(set(result_retest_ids)) != len(result_retest_ids):
            raise ValueError("each governed retest plan accepts only one result")
        if len(set(result_receipt_ids)) != len(result_receipt_ids):
            raise ValueError("governed retest receipt identifiers must be unique")
        if any(retest_id not in set(plan_ids) for retest_id in result_retest_ids):
            raise ValueError("governed retest results require a matching plan")
        active_plans = [
            item for item in self.retest_plans if item.retest_id not in set(result_retest_ids)
        ]
        if len(active_plans) > 1:
            raise ValueError("only one governed retest plan may be active")

        if self.status == FindingStatus.IN_REMEDIATION:
            if (
                self.remediation is None
                or self.remediation.remediation_id is None
                or self.remediation.state
                not in {
                    RemediationState.READY_FOR_IMPLEMENTATION,
                    RemediationState.NEEDS_REWORK,
                    RemediationState.RETEST_NEEDS_REWORK,
                    RemediationState.REVIEW_NEEDS_REWORK,
                }
            ):
                raise ValueError("in-remediation findings require an active governed plan")
        if self.status == FindingStatus.READY_FOR_RETEST:
            if (
                self.remediation is None
                or self.remediation.remediation_id is None
                or self.remediation.state != RemediationState.READY_FOR_RETEST
                or active_plans
            ):
                raise ValueError("ready-for-retest findings require no active retest plan")
        if self.status == FindingStatus.RETESTING:
            if (
                self.remediation is None
                or self.remediation.remediation_id is None
                or self.remediation.state != RemediationState.READY_FOR_RETEST
                or len(active_plans) != 1
            ):
                raise ValueError("retesting findings require one active governed retest")
        if self.status == FindingStatus.AWAITING_REMEDIATION_REVIEW:
            if (
                self.remediation is None
                or self.remediation.remediation_id is None
                or self.remediation.state != RemediationState.AWAITING_REVIEW
                or not self.retest_results
                or self.retest_results[-1].outcome != RetestOutcome.PASSED
                or active_plans
            ):
                raise ValueError("review-ready findings require a passed governed retest")
        if self.status == FindingStatus.READY_FOR_REPORT:
            if (
                self.remediation is None
                or self.remediation.remediation_id is None
                or self.remediation.state != RemediationState.REVIEW_APPROVED
            ):
                raise ValueError("report-ready findings require approved remediation review")
        if self.status == FindingStatus.REMEDIATED:
            if not self.retests or self.retests[-1].outcome != "passed":
                raise ValueError("remediated findings require a passed legacy retest")
        if self.remediation is not None and self.remediation.remediation_id is not None:
            if tuple(self.remediation.retest_history) != self.retest_results:
                raise ValueError("finding and remediation retest histories must match")
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
            raise ValueError("finding legacy retest history is append-only")
        if self.retest_plans[: len(previous.retest_plans)] != previous.retest_plans:
            raise ValueError("governed retest plans are append-only")
        if self.retest_results[: len(previous.retest_results)] != previous.retest_results:
            raise ValueError("governed retest results are append-only")
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
            if (
                new_remediation.retest_history[: len(old_remediation.retest_history)]
                != old_remediation.retest_history
            ):
                raise ValueError("remediation retest history is append-only")
            if (
                new_remediation.review_history[: len(old_remediation.review_history)]
                != old_remediation.review_history
            ):
                raise ValueError("remediation review history is append-only")
            if (
                old_remediation.state
                in {
                    RemediationState.CANCELLED,
                    RemediationState.FAILED,
                }
                and new_remediation != old_remediation
            ):
                raise ValueError("terminal remediation record is immutable")
