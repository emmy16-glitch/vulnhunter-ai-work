"""Immutable developer handoff and read-only fix-verification receipts."""

from __future__ import annotations

import json
import os
import re
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from vulnhunter.actions.models import sha256_json
from vulnhunter.findings.models import (
    FindingStatus,
    RemediationState,
    RemediationVerificationReference,
    VerificationState,
)
from vulnhunter.findings.service import FindingLifecycleError, FindingService
from vulnhunter.findings.store import (
    FindingConflict,
    FindingStore,
    FindingStoreError,
)
from vulnhunter.source_hunt.fix_verify import (
    FixVerificationInput,
    ReadOnlyFixVerifier,
    VerifierReceipt,
)
from vulnhunter.source_hunt.models import (
    FixVerificationReport,
    RepositorySnapshot,
    SourceReference,
)

_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class RemediationFixVerificationError(RuntimeError):
    """A fixed-revision handoff failed a governance or integrity boundary."""


def _normalize_paths(values: tuple[str, ...], *, label: str) -> tuple[str, ...]:
    normalized: list[str] = []
    for raw in values:
        value = raw.strip().replace("\\", "/")
        path = PurePosixPath(value)
        if not value or path.is_absolute() or ".." in path.parts:
            raise RemediationFixVerificationError(
                f"{label} must contain repository-relative traversal-free paths"
            )
        normalized.append(path.as_posix())
    if len(set(normalized)) != len(normalized):
        raise RemediationFixVerificationError(f"{label} must not contain duplicate paths")
    return tuple(normalized)


def _path_allowed(path: str, allowed: tuple[str, ...]) -> bool:
    candidate = PurePosixPath(path)
    return any(
        root == "."
        or candidate == PurePosixPath(root)
        or PurePosixPath(root) in candidate.parents
        for root in allowed
    )


class RemediationFixVerificationBundle(BaseModel):
    """One integrity-linked implementation attempt and deterministic verifier verdict."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = "1.0"
    receipt_id: str
    finding_id: str
    finding_revision: int = Field(ge=0)
    remediation_id: str
    plan_sha256: str
    builder_id: str
    verifier_id: str = "read-only-fix-verifier"
    allowed_paths: tuple[str, ...] = Field(min_length=1, max_length=100)
    changed_files: tuple[str, ...] = Field(min_length=1, max_length=2_000)
    original_snapshot: RepositorySnapshot
    fixed_snapshot: RepositorySnapshot
    security_test: VerifierReceipt | None = None
    regression_tests: tuple[VerifierReceipt, ...] = ()
    fixed_evidence_refs: tuple[SourceReference, ...] = ()
    original_attack_blocked: bool | None = None
    report: FixVerificationReport
    created_at: datetime

    @field_validator(
        "receipt_id",
        "finding_id",
        "remediation_id",
        "builder_id",
        "verifier_id",
    )
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("fix-verification identifiers must be stable lowercase values")
        return value

    @field_validator("plan_sha256")
    @classmethod
    def validate_plan_sha256(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("plan_sha256 must be a SHA-256 digest")
        return value

    @field_validator("allowed_paths", "changed_files", mode="before")
    @classmethod
    def validate_paths(cls, values):
        return _normalize_paths(
            tuple(str(item) for item in values),
            label="fix-verification paths",
        )

    @model_validator(mode="after")
    def validate_binding(self):
        if self.builder_id == self.verifier_id:
            raise ValueError("the read-only fix verifier must be independent from the builder")
        if self.original_snapshot.repository_id != self.fixed_snapshot.repository_id:
            raise ValueError("original and fixed snapshots must belong to the same repository")
        if self.original_snapshot.revision == self.fixed_snapshot.revision:
            raise ValueError("fixed revision must differ from the vulnerable revision")
        fixed_files = {item.path for item in self.fixed_snapshot.files}
        missing = tuple(path for path in self.changed_files if path not in fixed_files)
        if missing:
            raise ValueError("changed files must exist in the exact fixed snapshot")
        outside = tuple(
            path for path in self.changed_files if not _path_allowed(path, self.allowed_paths)
        )
        if outside:
            raise ValueError("changed files exceed the approved remediation boundary")
        if self.report.finding_id != self.finding_id:
            raise ValueError("fix-verification report is bound to another finding")
        if self.report.original_revision != self.original_snapshot.revision:
            raise ValueError("report original revision does not match the vulnerable snapshot")
        if self.report.fixed_revision != self.fixed_snapshot.revision:
            raise ValueError("report fixed revision does not match the fixed snapshot")
        if self.created_at.tzinfo is None or self.created_at.utcoffset() is None:
            raise ValueError("fix-verification creation time must be timezone-aware")
        if self.report.created_at != self.created_at:
            raise ValueError("fix-verification report and bundle timestamps must match")
        return self

    def fingerprint(self) -> str:
        return sha256_json(self.model_dump(mode="json"))

    @classmethod
    def create(
        cls,
        *,
        finding_id: str,
        finding_revision: int,
        remediation_id: str,
        plan_sha256: str,
        builder_id: str,
        allowed_paths: tuple[str, ...],
        changed_files: tuple[str, ...],
        original_snapshot: RepositorySnapshot,
        fixed_snapshot: RepositorySnapshot,
        security_test: VerifierReceipt | None,
        regression_tests: tuple[VerifierReceipt, ...],
        fixed_evidence_refs: tuple[SourceReference, ...],
        original_attack_blocked: bool | None,
        verifier: ReadOnlyFixVerifier,
        created_at: datetime,
    ) -> RemediationFixVerificationBundle:
        request = FixVerificationInput(
            finding_id=finding_id,
            original_revision=original_snapshot.revision,
            fixed_snapshot=fixed_snapshot,
            allowed_paths=allowed_paths,
            changed_files=changed_files,
            security_test=security_test,
            regression_tests=regression_tests,
            fixed_evidence_refs=fixed_evidence_refs,
            original_attack_blocked=original_attack_blocked,
        )
        report = verifier.verify(request, now=created_at)
        canonical = {
            "schema_version": "1.0",
            "finding_id": finding_id,
            "finding_revision": finding_revision,
            "remediation_id": remediation_id,
            "plan_sha256": plan_sha256,
            "builder_id": builder_id,
            "verifier_id": "read-only-fix-verifier",
            "allowed_paths": list(allowed_paths),
            "changed_files": list(changed_files),
            "original_snapshot": original_snapshot.model_dump(mode="json"),
            "fixed_snapshot": fixed_snapshot.model_dump(mode="json"),
            "security_test": (
                security_test.model_dump(mode="json") if security_test else None
            ),
            "regression_tests": [
                item.model_dump(mode="json") for item in regression_tests
            ],
            "fixed_evidence_refs": [
                item.model_dump(mode="json") for item in fixed_evidence_refs
            ],
            "original_attack_blocked": original_attack_blocked,
            "report": report.model_dump(mode="json"),
            "created_at": created_at.astimezone(UTC).isoformat(),
        }
        digest = sha256_json(canonical)
        return cls(
            receipt_id=f"fix-verification-{digest[:24]}",
            finding_id=finding_id,
            finding_revision=finding_revision,
            remediation_id=remediation_id,
            plan_sha256=plan_sha256,
            builder_id=builder_id,
            allowed_paths=allowed_paths,
            changed_files=changed_files,
            original_snapshot=original_snapshot,
            fixed_snapshot=fixed_snapshot,
            security_test=security_test,
            regression_tests=regression_tests,
            fixed_evidence_refs=fixed_evidence_refs,
            original_attack_blocked=original_attack_blocked,
            report=report,
            created_at=created_at,
        )


class RemediationFixVerificationStore:
    """Atomic, integrity-checked storage for immutable verification bundles."""

    def __init__(self, root: Path) -> None:
        self.root = root.expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, receipt_id: str) -> Path:
        if _IDENTIFIER.fullmatch(receipt_id) is None:
            raise RemediationFixVerificationError(
                "invalid fix-verification receipt identifier"
            )
        return self.root / f"{receipt_id}.json"

    def save(self, bundle: RemediationFixVerificationBundle) -> tuple[Path, bool]:
        path = self._path(bundle.receipt_id)
        envelope = {
            "bundle": bundle.model_dump(mode="json"),
            "bundle_sha256": bundle.fingerprint(),
        }
        if path.exists():
            existing = self.load(bundle.receipt_id)
            if existing == bundle:
                return path, False
            raise RemediationFixVerificationError(
                "fix-verification receipt already exists with different content"
            )
        serialized = json.dumps(
            envelope,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        descriptor, temporary = tempfile.mkstemp(
            prefix=".fix-verification-",
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

    def load(self, receipt_id: str) -> RemediationFixVerificationBundle:
        path = self._path(receipt_id)
        try:
            envelope = json.loads(path.read_text(encoding="utf-8"))
            payload = envelope["bundle"]
            expected = envelope["bundle_sha256"]
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise RemediationFixVerificationError(
                "fix-verification receipt is unavailable or invalid"
            ) from exc
        if sha256_json(payload) != expected:
            raise RemediationFixVerificationError(
                "fix-verification receipt failed integrity verification"
            )
        try:
            bundle = RemediationFixVerificationBundle.model_validate(payload)
        except ValidationError as exc:
            raise RemediationFixVerificationError(
                "fix-verification receipt has an invalid schema"
            ) from exc
        if bundle.fingerprint() != expected:
            raise RemediationFixVerificationError(
                "fix-verification receipt fingerprint does not match its envelope"
            )
        return bundle

    def delete(self, receipt_id: str) -> None:
        self._path(receipt_id).unlink(missing_ok=True)


@dataclass
class RemediationFixVerificationService:
    """Bind one external developer attempt to a plan and run the verifier read-only."""

    finding_store: FindingStore
    receipt_store: RemediationFixVerificationStore
    verifier: ReadOnlyFixVerifier = field(default_factory=ReadOnlyFixVerifier)
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)

    def record(
        self,
        *,
        finding_id: str,
        expected_revision: int,
        builder_id: str,
        allowed_paths: tuple[str, ...],
        changed_files: tuple[str, ...],
        original_snapshot: RepositorySnapshot,
        fixed_snapshot: RepositorySnapshot,
        security_test: VerifierReceipt | None,
        regression_tests: tuple[VerifierReceipt, ...],
        fixed_evidence_refs: tuple[SourceReference, ...],
        original_attack_blocked: bool | None,
    ):
        finding = self.finding_store.get(finding_id)
        if finding.revision != expected_revision:
            raise FindingConflict(
                f"finding revision conflict: expected {expected_revision}, "
                f"found {finding.revision}"
            )
        remediation = finding.remediation
        if finding.verification != VerificationState.VERIFIED:
            raise FindingLifecycleError(
                "fix verification requires an independently verified finding"
            )
        if (
            finding.status != FindingStatus.IN_REMEDIATION
            or remediation is None
            or remediation.remediation_id is None
            or remediation.plan_sha256 is None
            or remediation.state
            not in {
                RemediationState.READY_FOR_IMPLEMENTATION,
                RemediationState.NEEDS_REWORK,
            }
        ):
            raise FindingLifecycleError(
                "fix verification requires an active governed remediation plan"
            )

        normalized_allowed = _normalize_paths(allowed_paths, label="allowed paths")
        normalized_changed = _normalize_paths(changed_files, label="changed files")
        approved_targets = set(remediation.target_references)
        if any(path not in approved_targets for path in normalized_allowed):
            raise RemediationFixVerificationError(
                "allowed paths must be an exact subset of the approved remediation targets"
            )
        if builder_id.strip().casefold() == "read-only-fix-verifier":
            raise RemediationFixVerificationError(
                "the read-only verifier must remain independent from the developer builder"
            )

        created_at = self.clock().astimezone(UTC)
        if created_at < finding.updated_at.astimezone(UTC):
            raise FindingLifecycleError(
                "fix-verification timestamp cannot predate the current finding revision"
            )
        try:
            bundle = RemediationFixVerificationBundle.create(
                finding_id=finding.finding_id,
                finding_revision=finding.revision,
                remediation_id=remediation.remediation_id,
                plan_sha256=remediation.plan_sha256,
                builder_id=builder_id.strip().casefold(),
                allowed_paths=normalized_allowed,
                changed_files=normalized_changed,
                original_snapshot=original_snapshot,
                fixed_snapshot=fixed_snapshot,
                security_test=security_test,
                regression_tests=regression_tests,
                fixed_evidence_refs=fixed_evidence_refs,
                original_attack_blocked=original_attack_blocked,
                verifier=self.verifier,
                created_at=created_at,
            )
        except ValueError as exc:
            raise RemediationFixVerificationError(str(exc)) from exc

        _path, created = self.receipt_store.save(bundle)
        reference = RemediationVerificationReference(
            receipt_id=bundle.receipt_id,
            sha256=bundle.fingerprint(),
            verdict=bundle.report.verdict.value,
            original_revision=bundle.report.original_revision,
            fixed_revision=bundle.report.fixed_revision,
            created_at=bundle.created_at,
        )
        try:
            updated = FindingService(self.finding_store).record_fix_verification(
                finding_id,
                verification=reference,
                expected_revision=expected_revision,
                now=created_at,
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
    "RemediationFixVerificationBundle",
    "RemediationFixVerificationError",
    "RemediationFixVerificationService",
    "RemediationFixVerificationStore",
]
