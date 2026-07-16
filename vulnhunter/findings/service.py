"""Governed finding lifecycle service."""

from __future__ import annotations

from dataclasses import dataclass

from vulnhunter.findings.models import (
    Finding,
    FindingStatus,
    RetestRecord,
    VerificationState,
    utc_now,
)
from vulnhunter.findings.store import FindingStore


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
