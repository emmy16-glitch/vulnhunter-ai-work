"""Governed before/after retest plans, receipts, and atomic lifecycle service."""

from __future__ import annotations

import json
import os
import re
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from vulnhunter.actions.models import sha256_json
from vulnhunter.findings.models import (
    EvidenceReference,
    FindingStatus,
    RemediationState,
    RetestOutcome,
    RetestPlanRecord,
    RetestReceiptReference,
    VerificationState,
)
from vulnhunter.findings.service import FindingLifecycleError, FindingService
from vulnhunter.findings.store import FindingConflict, FindingStore, FindingStoreError
from vulnhunter.source_hunt.fix_verify import VerifierReceipt

_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")


class GovernedRetestError(RuntimeError):
    """A retest request or receipt violated an integrity or governance boundary."""


class GovernedRetestBundle(BaseModel):
    """One immutable before/after comparison for one exact retest plan."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = "1.0"
    receipt_id: str
    finding_id: str
    finding_revision: int = Field(ge=0)
    plan: RetestPlanRecord
    before_evidence: tuple[EvidenceReference, ...] = ()
    after_evidence: tuple[EvidenceReference, ...] = ()
    check_receipts: tuple[VerifierReceipt, ...] = ()
    original_issue_blocked: bool | None = None
    regression_free: bool | None = None
    blocked_reason: str | None = Field(default=None, min_length=3, max_length=1_000)
    cancellation_reason: str | None = Field(default=None, min_length=3, max_length=1_000)
    outcome: RetestOutcome
    summary: str = Field(min_length=3, max_length=2_000)
    created_at: datetime

    @field_validator("receipt_id", "finding_id")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("retest bundle identifiers must be stable lowercase values")
        return value

    @model_validator(mode="after")
    def validate_bundle(self):
        if self.created_at.tzinfo is None or self.created_at.utcoffset() is None:
            raise ValueError("retest bundle creation time must be timezone-aware")
        before_ids = tuple(item.evidence_id for item in self.before_evidence)
        after_ids = tuple(item.evidence_id for item in self.after_evidence)
        if len(set(before_ids)) != len(before_ids):
            raise ValueError("retest before evidence must not contain duplicate identifiers")
        if len(set(after_ids)) != len(after_ids):
            raise ValueError("retest after evidence must not contain duplicate identifiers")
        if set(before_ids).intersection(after_ids):
            raise ValueError("before and after retest evidence must use distinct identifiers")
        verifier_ids = tuple(item.verifier_id for item in self.check_receipts)
        if len(set(verifier_ids)) != len(verifier_ids):
            raise ValueError("retest deterministic verifier identities must be unique")

        if self.outcome == RetestOutcome.CANCELLED:
            if self.cancellation_reason is None:
                raise ValueError("cancelled retests require a cancellation reason")
            if self.blocked_reason is not None:
                raise ValueError("cancelled retests cannot also claim a blocked reason")
            return self

        if self.cancellation_reason is not None:
            raise ValueError("cancellation reason requires a cancelled retest")
        if set(before_ids) != set(self.plan.before_evidence_ids):
            raise ValueError("retest before evidence does not match the immutable plan")
        if self.outcome == RetestOutcome.BLOCKED and self.blocked_reason is None:
            raise ValueError("blocked retests require a blocked reason")
        if self.outcome != RetestOutcome.BLOCKED and self.blocked_reason is not None:
            raise ValueError("blocked reason requires a blocked retest")
        return self

    def fingerprint(self) -> str:
        return sha256_json(self.model_dump(mode="json"))

    @classmethod
    def create(
        cls,
        *,
        finding_id: str,
        finding_revision: int,
        plan: RetestPlanRecord,
        before_evidence: tuple[EvidenceReference, ...],
        after_evidence: tuple[EvidenceReference, ...],
        check_receipts: tuple[VerifierReceipt, ...],
        original_issue_blocked: bool | None,
        regression_free: bool | None,
        blocked_reason: str | None,
        created_at: datetime,
    ) -> GovernedRetestBundle:
        normalized_blocked_reason = (
            " ".join(blocked_reason.split())[:1_000] if blocked_reason else None
        )
        if normalized_blocked_reason:
            outcome = RetestOutcome.BLOCKED
            summary = f"The bounded retest was blocked: {normalized_blocked_reason}"
        elif not check_receipts:
            outcome = RetestOutcome.CANNOT_VERIFY
            summary = "No deterministic retest receipt was supplied, so the claim cannot be verified."
        elif any(not item.passed or item.exit_code != 0 for item in check_receipts):
            outcome = RetestOutcome.FAILED
            summary = "At least one deterministic retest check failed."
        elif original_issue_blocked is False:
            outcome = RetestOutcome.FAILED
            summary = "The original authorised issue still reproduces on the fixed revision."
        elif original_issue_blocked is None:
            outcome = RetestOutcome.CANNOT_VERIFY
            summary = "The supplied evidence does not prove whether the original issue is blocked."
        elif not after_evidence:
            outcome = RetestOutcome.CANNOT_VERIFY
            summary = "No after-fix evidence was supplied for the exact fixed revision."
        elif regression_free is False:
            outcome = RetestOutcome.FAILED
            summary = "The issue is blocked, but the supplied regression evidence reports failure."
        elif regression_free is None:
            outcome = RetestOutcome.PARTIAL
            summary = "The issue appears blocked, but broader regression status is incomplete."
        else:
            outcome = RetestOutcome.PASSED
            summary = (
                "The exact authorised check no longer reproduces the issue, deterministic retest "
                "receipts pass, after-fix evidence is present, and supplied regression checks pass."
            )

        canonical = {
            "schema_version": "1.0",
            "finding_id": finding_id,
            "finding_revision": finding_revision,
            "plan": plan.model_dump(mode="json"),
            "before_evidence": [item.model_dump(mode="json") for item in before_evidence],
            "after_evidence": [item.model_dump(mode="json") for item in after_evidence],
            "check_receipts": [item.model_dump(mode="json") for item in check_receipts],
            "original_issue_blocked": original_issue_blocked,
            "regression_free": regression_free,
            "blocked_reason": normalized_blocked_reason,
            "cancellation_reason": None,
            "outcome": outcome.value,
            "summary": summary,
            "created_at": created_at.astimezone(UTC).isoformat(),
        }
        digest = sha256_json(canonical)
        return cls(
            receipt_id=f"retest-receipt-{digest[:24]}",
            finding_id=finding_id,
            finding_revision=finding_revision,
            plan=plan,
            before_evidence=before_evidence,
            after_evidence=after_evidence,
            check_receipts=check_receipts,
            original_issue_blocked=original_issue_blocked,
            regression_free=regression_free,
            blocked_reason=normalized_blocked_reason,
            outcome=outcome,
            summary=summary,
            created_at=created_at,
        )

    @classmethod
    def cancelled(
        cls,
        *,
        finding_id: str,
        finding_revision: int,
        plan: RetestPlanRecord,
        reason: str,
        created_at: datetime,
    ) -> GovernedRetestBundle:
        cancellation_reason = " ".join(reason.split())[:1_000]
        if len(cancellation_reason) < 3:
            raise GovernedRetestError("retest cancellation requires a meaningful reason")
        canonical = {
            "schema_version": "1.0",
            "finding_id": finding_id,
            "finding_revision": finding_revision,
            "plan": plan.model_dump(mode="json"),
            "before_evidence": [],
            "after_evidence": [],
            "check_receipts": [],
            "original_issue_blocked": None,
            "regression_free": None,
            "blocked_reason": None,
            "cancellation_reason": cancellation_reason,
            "outcome": RetestOutcome.CANCELLED.value,
            "summary": f"The governed retest was cancelled: {cancellation_reason}",
            "created_at": created_at.astimezone(UTC).isoformat(),
        }
        digest = sha256_json(canonical)
        return cls(
            receipt_id=f"retest-receipt-{digest[:24]}",
            finding_id=finding_id,
            finding_revision=finding_revision,
            plan=plan,
            cancellation_reason=cancellation_reason,
            outcome=RetestOutcome.CANCELLED,
            summary=canonical["summary"],
            created_at=created_at,
        )


class RetestReceiptStore:
    """Atomic integrity-checked storage for immutable retest bundles."""

    def __init__(self, root: Path) -> None:
        self.root = root.expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, receipt_id: str) -> Path:
        if _IDENTIFIER.fullmatch(receipt_id) is None:
            raise GovernedRetestError("invalid retest receipt identifier")
        return self.root / f"{receipt_id}.json"

    def save(self, bundle: GovernedRetestBundle) -> tuple[Path, bool]:
        path = self._path(bundle.receipt_id)
        envelope = {
            "bundle": bundle.model_dump(mode="json"),
            "bundle_sha256": bundle.fingerprint(),
        }
        if path.exists():
            existing = self.load(bundle.receipt_id)
            if existing == bundle:
                return path, False
            raise GovernedRetestError("retest receipt already exists with different content")
        serialized = json.dumps(
            envelope,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        descriptor, temporary = tempfile.mkstemp(
            prefix=".retest-receipt-",
            suffix=".tmp",
            dir=self.root,
        )
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(serialized)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        return path, True

    def load(self, receipt_id: str) -> GovernedRetestBundle:
        path = self._path(receipt_id)
        try:
            envelope = json.loads(path.read_text(encoding="utf-8"))
            payload = envelope["bundle"]
            expected = envelope["bundle_sha256"]
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise GovernedRetestError("retest receipt is unavailable or invalid") from exc
        if sha256_json(payload) != expected:
            raise GovernedRetestError("retest receipt failed integrity verification")
        try:
            bundle = GovernedRetestBundle.model_validate(payload)
        except ValidationError as exc:
            raise GovernedRetestError("retest receipt has an invalid schema") from exc
        if bundle.fingerprint() != expected:
            raise GovernedRetestError("retest receipt fingerprint does not match its envelope")
        return bundle

    def delete(self, receipt_id: str) -> None:
        self._path(receipt_id).unlink(missing_ok=True)


@dataclass
class GovernedRetestService:
    """Create and complete governed retests without executing submitted commands."""

    finding_store: FindingStore
    receipt_store: RetestReceiptStore
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)

    def start(
        self,
        *,
        finding_id: str,
        expected_revision: int,
        owner_id: str,
        check_references: tuple[str, ...],
        expires_at: datetime,
    ):
        finding = self.finding_store.get(finding_id)
        if finding.revision != expected_revision:
            raise FindingConflict(
                f"finding revision conflict: expected {expected_revision}, found {finding.revision}"
            )
        remediation = finding.remediation
        latest_verification = (
            remediation.verification_history[-1]
            if remediation is not None and remediation.verification_history
            else None
        )
        if (
            finding.verification != VerificationState.VERIFIED
            or finding.status != FindingStatus.READY_FOR_RETEST
            or remediation is None
            or remediation.remediation_id is None
            or remediation.state != RemediationState.READY_FOR_RETEST
            or latest_verification is None
            or latest_verification.verdict != "fixed"
        ):
            raise FindingLifecycleError(
                "governed retest requires a ready-for-retest independently verified finding"
            )
        created_at = self.clock().astimezone(UTC)
        if created_at < finding.updated_at.astimezone(UTC):
            raise FindingLifecycleError(
                "retest timestamp cannot predate the current finding revision"
            )
        if expires_at.tzinfo is None or expires_at.utcoffset() is None:
            raise GovernedRetestError("retest expiry must be timezone-aware")
        expiry = expires_at.astimezone(UTC)
        if expiry <= created_at:
            raise GovernedRetestError("retest expiry must follow creation")
        evidence_ids = {item.evidence_id for item in finding.evidence}
        before_evidence_ids = tuple(
            item for item in remediation.references if item in evidence_ids
        )
        if not before_evidence_ids:
            before_evidence_ids = tuple(
                item.evidence_id
                for item in finding.evidence
                if item.evidence_id != latest_verification.receipt_id
            )
        if not before_evidence_ids:
            raise GovernedRetestError("governed retest requires original evidence lineage")
        try:
            plan = RetestPlanRecord.create(
                finding_id=finding.finding_id,
                finding_revision=finding.revision,
                finding_fingerprint=finding.fingerprint,
                remediation_id=remediation.remediation_id,
                fix_verification_receipt_id=latest_verification.receipt_id,
                fixed_revision=latest_verification.fixed_revision,
                owner_id=owner_id.strip().casefold(),
                check_references=check_references,
                before_evidence_ids=before_evidence_ids,
                created_at=created_at,
                expires_at=expiry,
            )
        except ValueError as exc:
            raise GovernedRetestError(str(exc)) from exc
        return FindingService(self.finding_store).start_governed_retest(
            finding_id,
            plan=plan,
            expected_revision=expected_revision,
            now=created_at,
        )

    def record(
        self,
        *,
        finding_id: str,
        retest_id: str,
        expected_revision: int,
        before_evidence: tuple[EvidenceReference, ...],
        after_evidence: tuple[EvidenceReference, ...],
        check_receipts: tuple[VerifierReceipt, ...],
        original_issue_blocked: bool | None,
        regression_free: bool | None,
        blocked_reason: str | None = None,
    ):
        finding = self.finding_store.get(finding_id)
        if finding.revision != expected_revision:
            raise FindingConflict(
                f"finding revision conflict: expected {expected_revision}, found {finding.revision}"
            )
        plan = self._active_plan(finding, retest_id)
        now = self.clock().astimezone(UTC)
        if now < finding.updated_at.astimezone(UTC):
            raise FindingLifecycleError(
                "retest result timestamp cannot predate the current finding revision"
            )
        if now > plan.expires_at.astimezone(UTC):
            raise GovernedRetestError("the governed retest plan has expired")
        original_by_id = {item.evidence_id: item for item in finding.evidence}
        supplied_by_id = {item.evidence_id: item for item in before_evidence}
        if set(supplied_by_id) != set(plan.before_evidence_ids):
            raise GovernedRetestError("retest original evidence does not match the immutable plan")
        for evidence_id in plan.before_evidence_ids:
            if original_by_id.get(evidence_id) != supplied_by_id[evidence_id]:
                raise GovernedRetestError(
                    "retest original evidence failed finding integrity verification"
                )
        if any(item.evidence_id in original_by_id for item in after_evidence):
            raise GovernedRetestError("after-fix evidence must use new evidence identifiers")

        try:
            bundle = GovernedRetestBundle.create(
                finding_id=finding.finding_id,
                finding_revision=finding.revision,
                plan=plan,
                before_evidence=before_evidence,
                after_evidence=after_evidence,
                check_receipts=check_receipts,
                original_issue_blocked=original_issue_blocked,
                regression_free=regression_free,
                blocked_reason=blocked_reason,
                created_at=now,
            )
        except ValueError as exc:
            raise GovernedRetestError(str(exc)) from exc
        return self._persist_result(finding, bundle, expected_revision=expected_revision)

    def cancel(
        self,
        *,
        finding_id: str,
        retest_id: str,
        expected_revision: int,
        reason: str,
    ):
        finding = self.finding_store.get(finding_id)
        if finding.revision != expected_revision:
            raise FindingConflict(
                f"finding revision conflict: expected {expected_revision}, found {finding.revision}"
            )
        plan = self._active_plan(finding, retest_id)
        now = self.clock().astimezone(UTC)
        if now < finding.updated_at.astimezone(UTC):
            raise FindingLifecycleError(
                "retest cancellation timestamp cannot predate the current finding revision"
            )
        bundle = GovernedRetestBundle.cancelled(
            finding_id=finding.finding_id,
            finding_revision=finding.revision,
            plan=plan,
            reason=reason,
            created_at=now,
        )
        return self._persist_result(finding, bundle, expected_revision=expected_revision)

    @staticmethod
    def _active_plan(finding, retest_id: str) -> RetestPlanRecord:
        completed = {item.retest_id for item in finding.retest_results}
        active = [item for item in finding.retest_plans if item.retest_id not in completed]
        if finding.status != FindingStatus.RETESTING or len(active) != 1:
            raise FindingLifecycleError("no active governed retest can accept this operation")
        plan = active[0]
        if plan.retest_id != retest_id:
            raise FindingLifecycleError("the request is bound to another governed retest")
        return plan

    def _persist_result(self, finding, bundle, *, expected_revision: int):
        _path, created = self.receipt_store.save(bundle)
        reference = RetestReceiptReference(
            receipt_id=bundle.receipt_id,
            retest_id=bundle.plan.retest_id,
            sha256=bundle.fingerprint(),
            outcome=bundle.outcome,
            fixed_revision=bundle.plan.fixed_revision,
            created_at=bundle.created_at,
        )
        evidence = EvidenceReference(
            evidence_id=bundle.receipt_id,
            sha256=bundle.fingerprint(),
            provenance=(
                "immutable governed before/after retest bundle; "
                f"outcome={bundle.outcome.value}"
            ),
            content_type="application/vnd.vulnhunter.retest+json",
        )
        try:
            updated = FindingService(self.finding_store).record_governed_retest(
                finding.finding_id,
                result=reference,
                evidence=evidence,
                expected_revision=expected_revision,
                now=bundle.created_at,
            )
        except (
            FindingConflict,
            FindingLifecycleError,
            FindingStoreError,
            OSError,
            ValueError,
        ):
            if created:
                self.receipt_store.delete(bundle.receipt_id)
            raise
        return updated, bundle


__all__ = [
    "GovernedRetestBundle",
    "GovernedRetestError",
    "GovernedRetestService",
    "RetestReceiptStore",
]
