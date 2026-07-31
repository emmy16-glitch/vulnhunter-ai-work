"""Governed finding lifecycle service."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from vulnhunter.findings.models import (
    Finding,
    FindingStatus,
    RemediationRecord,
    RemediationState,
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
                "finding revision conflict: "
                f"expected {expected_revision}, found {finding.revision}"
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
                "finding revision conflict: "
                f"expected {expected_revision}, found {finding.revision}"
            )
        remediation = finding.remediation
        if (
            finding.status != FindingStatus.IN_REMEDIATION
            or remediation is None
            or remediation.remediation_id is None
            or remediation.state != RemediationState.READY_FOR_IMPLEMENTATION
        ):
            raise FindingLifecycleError("no active governed remediation plan can be cancelled")
        cancelled_at = (now or datetime.now(UTC)).astimezone(UTC)
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
