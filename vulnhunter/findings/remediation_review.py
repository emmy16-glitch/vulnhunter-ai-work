"""Identity-bound independent remediation review receipts and lifecycle service."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from vulnhunter.actions.models import sha256_json
from vulnhunter.exceptions import (
    GovernanceAuthenticationError,
    GovernanceError,
    GovernancePolicyError,
)
from vulnhunter.findings.models import (
    EvidenceReference,
    FindingStatus,
    RemediationReviewChecklist,
    RemediationReviewOutcome,
    RemediationReviewPlanRecord,
    RemediationReviewReference,
    RemediationState,
    RetestOutcome,
    VerificationState,
)
from vulnhunter.findings.service import FindingLifecycleError, FindingService
from vulnhunter.findings.store import FindingConflict, FindingStore, FindingStoreError
from vulnhunter.governance.service import authenticate_identity
from vulnhunter.governance.store import GovernanceStore
from vulnhunter.review import normalize_reviewer_id

_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")


class RemediationReviewError(RuntimeError):
    """An independent remediation review violated an integrity or authority boundary."""


class RemediationReviewBundle(BaseModel):
    """One signed, identity-bound decision over one exact passed retest."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = "1.0"
    receipt_id: str
    finding_id: str
    finding_revision: int = Field(ge=0)
    plan: RemediationReviewPlanRecord
    reviewer_identity_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    checklist: RemediationReviewChecklist
    outcome: RemediationReviewOutcome
    rationale: str = Field(min_length=10, max_length=5_000)
    limitations: tuple[str, ...] = Field(default=(), max_length=100)
    blocked_reason: str | None = Field(default=None, min_length=3, max_length=1_000)
    created_at: datetime

    @field_validator("receipt_id", "finding_id")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("remediation review identifiers must be stable lowercase values")
        return value

    @field_validator("limitations")
    @classmethod
    def validate_limitations(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        cleaned = tuple(" ".join(item.split()) for item in values if item.strip())
        if len(cleaned) != len(values):
            raise ValueError("review limitations must not be blank")
        if len(set(cleaned)) != len(cleaned):
            raise ValueError("review limitations must be unique")
        if any(len(item) > 1_000 for item in cleaned):
            raise ValueError("review limitations must not exceed 1,000 characters")
        return cleaned

    @model_validator(mode="after")
    def validate_bundle(self):
        if self.created_at.tzinfo is None or self.created_at.utcoffset() is None:
            raise ValueError("review receipt time must be timezone-aware")
        if self.created_at != self.plan.created_at:
            raise ValueError("review plan and decision must share one timestamp")
        if self.reviewer_identity_sha256 != self.plan.reviewer_identity_sha256:
            raise ValueError("review identity digest does not match the immutable plan")
        if self.outcome == RemediationReviewOutcome.BLOCKED:
            if self.blocked_reason is None:
                raise ValueError("blocked remediation reviews require a blocked reason")
        elif self.blocked_reason is not None:
            raise ValueError("blocked reason requires a blocked remediation review")
        expected = self.compute_outcome(self.checklist, blocked_reason=self.blocked_reason)
        if self.outcome != expected:
            raise ValueError("review outcome does not match the evidence checklist")
        return self

    def fingerprint(self) -> str:
        return sha256_json(self.model_dump(mode="json"))

    @staticmethod
    def compute_outcome(
        checklist: RemediationReviewChecklist,
        *,
        blocked_reason: str | None,
    ) -> RemediationReviewOutcome:
        if blocked_reason:
            return RemediationReviewOutcome.BLOCKED
        values = (
            checklist.evidence_lineage_complete,
            checklist.fixed_revision_matches,
            checklist.approved_scope_respected,
            checklist.security_claim_supported,
            checklist.regressions_acceptable,
        )
        if any(value is False for value in values):
            return RemediationReviewOutcome.CHANGES_REQUESTED
        if any(value is None for value in values):
            return RemediationReviewOutcome.CANNOT_VERIFY
        return RemediationReviewOutcome.APPROVED

    @classmethod
    def create(
        cls,
        *,
        finding_id: str,
        finding_revision: int,
        plan: RemediationReviewPlanRecord,
        checklist: RemediationReviewChecklist,
        rationale: str,
        limitations: tuple[str, ...],
        blocked_reason: str | None,
        created_at: datetime,
    ) -> RemediationReviewBundle:
        normalized_rationale = " ".join(rationale.split())[:5_000]
        normalized_blocked = " ".join(blocked_reason.split())[:1_000] if blocked_reason else None
        outcome = cls.compute_outcome(checklist, blocked_reason=normalized_blocked)
        canonical = {
            "schema_version": "1.0",
            "finding_id": finding_id,
            "finding_revision": finding_revision,
            "plan": plan.model_dump(mode="json"),
            "reviewer_identity_sha256": plan.reviewer_identity_sha256,
            "checklist": checklist.model_dump(mode="json"),
            "outcome": outcome.value,
            "rationale": normalized_rationale,
            "limitations": list(limitations),
            "blocked_reason": normalized_blocked,
            "created_at": created_at.astimezone(UTC).isoformat(),
        }
        digest = sha256_json(canonical)
        return cls(
            receipt_id=f"remediation-review-{digest[:24]}",
            finding_id=finding_id,
            finding_revision=finding_revision,
            plan=plan,
            reviewer_identity_sha256=plan.reviewer_identity_sha256,
            checklist=checklist,
            outcome=outcome,
            rationale=normalized_rationale,
            limitations=limitations,
            blocked_reason=normalized_blocked,
            created_at=created_at,
        )


class RemediationReviewReceiptStore:
    """Atomic HMAC-signed storage for immutable remediation review receipts."""

    def __init__(self, root: Path, *, signing_key: bytes) -> None:
        if len(signing_key) < 16:
            raise RemediationReviewError("remediation review signing key is too short")
        self.root = root.expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self._signing_key = bytes(signing_key)

    def _path(self, receipt_id: str) -> Path:
        if _IDENTIFIER.fullmatch(receipt_id) is None:
            raise RemediationReviewError("invalid remediation review receipt identifier")
        return self.root / f"{receipt_id}.json"

    def _signature(self, payload: dict[str, object]) -> str:
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        return hmac.new(self._signing_key, encoded, hashlib.sha256).hexdigest()

    def save(self, bundle: RemediationReviewBundle) -> tuple[Path, bool]:
        path = self._path(bundle.receipt_id)
        signed_payload: dict[str, object] = {
            "bundle": bundle.model_dump(mode="json"),
            "bundle_sha256": bundle.fingerprint(),
            "reviewer_identity_sha256": bundle.reviewer_identity_sha256,
        }
        envelope = {
            **signed_payload,
            "signature_sha256": self._signature(signed_payload),
        }
        if path.exists():
            existing = self.load(bundle.receipt_id)
            if existing == bundle:
                return path, False
            raise RemediationReviewError(
                "remediation review receipt already exists with different content"
            )
        serialized = json.dumps(
            envelope,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        descriptor, temporary = tempfile.mkstemp(
            prefix=".remediation-review-",
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

    def load(self, receipt_id: str) -> RemediationReviewBundle:
        path = self._path(receipt_id)
        try:
            envelope = json.loads(path.read_text(encoding="utf-8"))
            signed_payload = {
                "bundle": envelope["bundle"],
                "bundle_sha256": envelope["bundle_sha256"],
                "reviewer_identity_sha256": envelope["reviewer_identity_sha256"],
            }
            signature = str(envelope["signature_sha256"])
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise RemediationReviewError(
                "remediation review receipt is unavailable or invalid"
            ) from exc
        expected_signature = self._signature(signed_payload)
        if not hmac.compare_digest(signature, expected_signature):
            raise RemediationReviewError("remediation review receipt signature verification failed")
        payload = signed_payload["bundle"]
        expected_digest = str(signed_payload["bundle_sha256"])
        if sha256_json(payload) != expected_digest:
            raise RemediationReviewError("remediation review receipt failed integrity verification")
        try:
            bundle = RemediationReviewBundle.model_validate(payload)
        except ValidationError as exc:
            raise RemediationReviewError(
                "remediation review receipt has an invalid schema"
            ) from exc
        if bundle.fingerprint() != expected_digest:
            raise RemediationReviewError(
                "remediation review receipt fingerprint does not match its envelope"
            )
        if bundle.reviewer_identity_sha256 != signed_payload["reviewer_identity_sha256"]:
            raise RemediationReviewError(
                "remediation review identity attestation does not match its envelope"
            )
        return bundle

    def delete(self, receipt_id: str) -> None:
        self._path(receipt_id).unlink(missing_ok=True)


@dataclass
class RemediationReviewService:
    """Authenticate one independent reviewer and append one signed decision."""

    finding_store: FindingStore
    governance_store: GovernanceStore
    fix_verification_store: object
    retest_receipt_store: object
    receipt_store: RemediationReviewReceiptStore
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)

    def record(
        self,
        *,
        finding_id: str,
        expected_revision: int,
        reviewer_id: str,
        reviewer_secret: str,
        checklist: RemediationReviewChecklist,
        rationale: str,
        limitations: tuple[str, ...] = (),
        blocked_reason: str | None = None,
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
        latest_retest = (
            remediation.retest_history[-1]
            if remediation is not None and remediation.retest_history
            else None
        )
        if (
            finding.verification != VerificationState.VERIFIED
            or finding.status != FindingStatus.AWAITING_REMEDIATION_REVIEW
            or remediation is None
            or remediation.remediation_id is None
            or remediation.state != RemediationState.AWAITING_REVIEW
            or latest_verification is None
            or latest_verification.verdict != "fixed"
            or latest_retest is None
            or latest_retest.outcome != RetestOutcome.PASSED
        ):
            raise FindingLifecycleError(
                "independent remediation review requires an exact passed governed retest"
            )

        try:
            normalized_reviewer = normalize_reviewer_id(reviewer_id)
        except ValueError as exc:
            raise RemediationReviewError(str(exc)) from exc
        fix_bundle = self.fix_verification_store.load(latest_verification.receipt_id)
        retest_bundle = self.retest_receipt_store.load(latest_retest.receipt_id)
        conflicts = {
            remediation.owner_id: "remediation owner",
            str(getattr(fix_bundle, "builder_id", "")): "implementation builder",
            str(getattr(fix_bundle, "verifier_id", "")): "fix verifier",
            str(getattr(getattr(retest_bundle, "plan", None), "owner_id", "")): ("retest operator"),
        }
        conflict_role = conflicts.get(normalized_reviewer)
        if conflict_role:
            raise RemediationReviewError(f"the independent reviewer cannot be the {conflict_role}")
        try:
            identity = authenticate_identity(
                self.governance_store,
                normalized_reviewer,
                reviewer_secret,
                required_role="reviewer",
            )
        except (GovernanceAuthenticationError, GovernancePolicyError, GovernanceError) as exc:
            raise RemediationReviewError(str(exc)) from exc

        fix_digest = str(fix_bundle.fingerprint())
        retest_digest = str(retest_bundle.fingerprint())
        if fix_digest != latest_verification.sha256:
            raise RemediationReviewError(
                "the fixed-revision receipt failed finding integrity verification"
            )
        if retest_digest != latest_retest.sha256:
            raise RemediationReviewError("the retest receipt failed finding integrity verification")
        fixed_revision = str(getattr(getattr(fix_bundle, "fixed_snapshot", None), "revision", ""))
        retest_fixed_revision = str(
            getattr(getattr(retest_bundle, "plan", None), "fixed_revision", "")
        )
        if not fixed_revision or fixed_revision != latest_verification.fixed_revision:
            raise RemediationReviewError("fix receipt is bound to another fixed revision")
        if (
            retest_fixed_revision != fixed_revision
            or latest_retest.fixed_revision != fixed_revision
        ):
            raise RemediationReviewError("retest receipt is bound to another fixed revision")

        now = self.clock().astimezone(UTC)
        if now < finding.updated_at.astimezone(UTC):
            raise FindingLifecycleError(
                "review timestamp cannot predate the current finding revision"
            )
        evidence_ids = tuple(item.evidence_id for item in finding.evidence)
        try:
            plan = RemediationReviewPlanRecord.create(
                finding_id=finding.finding_id,
                finding_revision=finding.revision,
                finding_fingerprint=finding.fingerprint,
                remediation_id=remediation.remediation_id,
                reviewer_id=identity.reviewer_id,
                reviewer_identity_sha256=identity.record_sha256,
                fix_verification_receipt_id=latest_verification.receipt_id,
                retest_receipt_id=latest_retest.receipt_id,
                fixed_revision=fixed_revision,
                evidence_references=evidence_ids,
                created_at=now,
                expires_at=now + timedelta(days=2),
            )
            bundle = RemediationReviewBundle.create(
                finding_id=finding.finding_id,
                finding_revision=finding.revision,
                plan=plan,
                checklist=checklist,
                rationale=rationale,
                limitations=limitations,
                blocked_reason=blocked_reason,
                created_at=now,
            )
        except ValueError as exc:
            raise RemediationReviewError(str(exc)) from exc

        _path, created = self.receipt_store.save(bundle)
        reference = RemediationReviewReference(
            receipt_id=bundle.receipt_id,
            review_id=plan.review_id,
            sha256=bundle.fingerprint(),
            outcome=bundle.outcome,
            reviewer_id=identity.reviewer_id,
            reviewer_identity_sha256=identity.record_sha256,
            fixed_revision=fixed_revision,
            retest_receipt_id=latest_retest.receipt_id,
            created_at=now,
        )
        evidence = EvidenceReference(
            evidence_id=bundle.receipt_id,
            sha256=bundle.fingerprint(),
            provenance=(
                "server-signed identity-bound independent remediation review; "
                f"outcome={bundle.outcome.value}"
            ),
            content_type="application/vnd.vulnhunter.remediation-review+json",
        )
        try:
            updated = FindingService(self.finding_store).record_remediation_review(
                finding.finding_id,
                review=reference,
                evidence=evidence,
                expected_revision=expected_revision,
                now=now,
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
    "RemediationReviewBundle",
    "RemediationReviewError",
    "RemediationReviewReceiptStore",
    "RemediationReviewService",
]
