"""Governed finding lifecycle service."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from vulnhunter.findings.models import (
    EvidenceReference,
    Finding,
    FindingStatus,
    RemediationRecord,
    RemediationState,
    RemediationVerificationReference,
    RetestRecord,
    VerificationState,
    utc_now,
)
from vulnhunter.findings.store import FindingConflict, FindingStore


class FindingLifecycleError(RuntimeError):
    """A requested finding transition violates the governed lifecycle."""


@dataclass
class FindingService:
    store: FindingStore

    def update_verification(
        self,
        finding_id: str,
        *,
        verification: VerificationState,
        analyst_decision: str,
        expected_revision: int,
    ) -> Finding:
        finding = self.store.get(finding_id)
        updated = finding.model_copy(
            update={
                "verification": verification,
                "analyst_decision": analyst_decision,
                "revision": finding.revision + 1,
                "updated_at": utc_now(),
            }
        )
        updated = Finding.model_validate(updated.model_dump())
        self.store.save(updated, expected_revision=expected_revision)
        return updated

    def start_remediation(
        self,
        finding_id: str,
        *,
        owner_id: str,
        summary: str,
        target_references: tuple[str, ...],
        regression_test: str,
        verification_recipe: str,
        compatibility_risks: tuple[str, ...] = (),
        references: tuple[str, ...] = (),
        due_at: datetime | None = None,
        expires_at: datetime,
        expected_revision: int,
        now: datetime | None = None,
    ) -> Finding:
        """Atomically bind an exact human-owned plan to a verified finding."""

        finding = self.store.get(finding_id)
        if finding.revision != expected_revision:
            raise FindingConflict(
                f"finding revision conflict: expected {expected_revision}, found {finding.revision}"
            )
        if finding.verification != VerificationState.VERIFIED:
            raise FindingLifecycleError(
                "remediation planning requires an independently verified finding"
            )
        if finding.status not in {FindingStatus.OPEN, FindingStatus.TRIAGED}:
            raise FindingLifecycleError(
                "remediation can start only from an open or triaged finding"
            )
        if (
            finding.remediation is not None
            and finding.remediation.remediation_id is not None
            and finding.remediation.state == RemediationState.READY_FOR_IMPLEMENTATION
        ):
            raise FindingLifecycleError("an active remediation plan already exists")

        created_at = (now or datetime.now(UTC)).astimezone(UTC)
        if created_at < finding.updated_at.astimezone(UTC):
            raise FindingLifecycleError(
                "remediation timestamp cannot predate the current finding revision"
            )
        remediation = RemediationRecord.create(
            finding_id=finding.finding_id,
            finding_revision=finding.revision,
            finding_fingerprint=finding.fingerprint,
            summary=summary,
            owner_id=owner_id,
            target_references=target_references,
            regression_test=regression_test,
            verification_recipe=verification_recipe,
            compatibility_risks=compatibility_risks,
            references=references,
            created_at=created_at,
            expires_at=expires_at,
            due_at=due_at,
        )
        updated = Finding.model_validate(
            finding.model_copy(
                update={
                    "status": FindingStatus.IN_REMEDIATION,
                    "remediation": remediation,
                    "revision": finding.revision + 1,
                    "updated_at": created_at,
                }
            ).model_dump()
        )
        self.store.save(updated, expected_revision=expected_revision)
        return updated

    def record_fix_verification(
        self,
        finding_id: str,
        *,
        verification: RemediationVerificationReference,
        expected_revision: int,
        now: datetime | None = None,
    ) -> Finding:
        """Atomically append one immutable fix verdict and update the finding state."""

        finding = self.store.get(finding_id)
        if finding.revision != expected_revision:
            raise FindingConflict(
                f"finding revision conflict: expected {expected_revision}, found {finding.revision}"
            )
        remediation = finding.remediation
        if (
            finding.verification != VerificationState.VERIFIED
            or finding.status != FindingStatus.IN_REMEDIATION
            or remediation is None
            or remediation.remediation_id is None
            or remediation.state
            not in {RemediationState.READY_FOR_IMPLEMENTATION, RemediationState.NEEDS_REWORK}
        ):
            raise FindingLifecycleError(
                "fix verification requires an active independently verified remediation"
            )
        if any(item.evidence_id == verification.receipt_id for item in finding.evidence):
            raise FindingLifecycleError("the fix-verification receipt is already linked")

        recorded_at = (now or datetime.now(UTC)).astimezone(UTC)
        if recorded_at < finding.updated_at.astimezone(UTC):
            raise FindingLifecycleError(
                "fix-verification timestamp cannot predate the current finding revision"
            )
        if verification.created_at.astimezone(UTC) != recorded_at:
            raise FindingLifecycleError(
                "fix-verification reference and finding transition must share one timestamp"
            )

        updated_remediation = remediation.record_verification(verification)
        status = (
            FindingStatus.READY_FOR_RETEST
            if verification.verdict == "fixed"
            else FindingStatus.IN_REMEDIATION
        )
        evidence = EvidenceReference(
            evidence_id=verification.receipt_id,
            sha256=verification.sha256,
            provenance=(
                f"immutable read-only fix-verification bundle; verdict={verification.verdict}"
            ),
            content_type="application/vnd.vulnhunter.fix-verification+json",
        )
        updated = Finding.model_validate(
            finding.model_copy(
                update={
                    "status": status,
                    "remediation": updated_remediation,
                    "evidence": finding.evidence + (evidence,),
                    "revision": finding.revision + 1,
                    "updated_at": recorded_at,
                }
            ).model_dump()
        )
        self.store.save(updated, expected_revision=expected_revision)
        return updated

    def cancel_remediation(
        self,
        finding_id: str,
        *,
        reason: str,
        expected_revision: int,
        now: datetime | None = None,
    ) -> Finding:
        """Cancel a plan atomically while keeping the verified finding open."""

        finding = self.store.get(finding_id)
        if finding.revision != expected_revision:
            raise FindingConflict(
                f"finding revision conflict: expected {expected_revision}, found {finding.revision}"
            )
        remediation = finding.remediation
        if (
            finding.status != FindingStatus.IN_REMEDIATION
            or remediation is None
            or remediation.remediation_id is None
            or remediation.state
            not in {RemediationState.READY_FOR_IMPLEMENTATION, RemediationState.NEEDS_REWORK}
        ):
            raise FindingLifecycleError("no active governed remediation plan can be cancelled")
        cancelled_at = (now or datetime.now(UTC)).astimezone(UTC)
        if cancelled_at < finding.updated_at.astimezone(UTC):
            raise FindingLifecycleError(
                "remediation cancellation timestamp cannot predate the current finding revision"
            )
        cancelled = remediation.cancel(cancelled_at=cancelled_at, reason=reason)
        updated = Finding.model_validate(
            finding.model_copy(
                update={
                    "status": FindingStatus.TRIAGED,
                    "remediation": cancelled,
                    "revision": finding.revision + 1,
                    "updated_at": cancelled_at,
                }
            ).model_dump()
        )
        self.store.save(updated, expected_revision=expected_revision)
        return updated

    def append_retest(
        self,
        finding_id: str,
        *,
        retest: RetestRecord,
        expected_revision: int,
    ) -> Finding:
        finding = self.store.get(finding_id)
        status = FindingStatus.REMEDIATED if retest.outcome == "passed" else FindingStatus.OPEN
        updated = finding.model_copy(
            update={
                "retests": finding.retests + (retest,),
                "status": status,
                "revision": finding.revision + 1,
                "updated_at": utc_now(),
            }
        )
        updated = Finding.model_validate(updated.model_dump())
        self.store.save(updated, expected_revision=expected_revision)
        return updated
