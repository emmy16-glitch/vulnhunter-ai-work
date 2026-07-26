"""Read-only deterministic verification for source-hunt remediation work."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import PurePosixPath

from pydantic import BaseModel, ConfigDict, Field, field_validator

from vulnhunter.source_hunt.models import (
    FixVerificationReport,
    FixVerificationVerdict,
    RepositorySnapshot,
    SourceReference,
)


class VerifierReceipt(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    verifier_id: str = Field(min_length=2, max_length=128)
    passed: bool
    exit_code: int
    output_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    duration_seconds: float = Field(ge=0, le=86_400)
    safe_summary: str = Field(min_length=2, max_length=1_000)


class FixVerificationInput(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    finding_id: str = Field(min_length=2, max_length=128)
    original_revision: str = Field(min_length=1, max_length=256)
    fixed_snapshot: RepositorySnapshot
    allowed_paths: tuple[str, ...]
    changed_files: tuple[str, ...]
    security_test: VerifierReceipt | None = None
    regression_tests: tuple[VerifierReceipt, ...] = ()
    fixed_evidence_refs: tuple[SourceReference, ...] = ()
    original_attack_blocked: bool | None = None

    @field_validator("allowed_paths", "changed_files")
    @classmethod
    def validate_relative_paths(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized: list[str] = []
        for value in values:
            path = PurePosixPath(value)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError("fix-verification paths must be repository-relative")
            normalized.append(path.as_posix())
        return tuple(normalized)


class ReadOnlyFixVerifier:
    """Issue a verdict from immutable snapshot data and deterministic verifier receipts."""

    def verify(self, request: FixVerificationInput) -> FixVerificationReport:
        verdict = FixVerificationVerdict.CANNOT_VERIFY
        summary = "The fix could not be proven from the supplied deterministic evidence."
        regressions: tuple[str, ...] = ()

        outside = tuple(
            path
            for path in request.changed_files
            if not self._path_allowed(path, request.allowed_paths)
        )
        if outside:
            verdict = FixVerificationVerdict.OUT_OF_SCOPE_CHANGE
            summary = "The proposed fix changed files outside the approved remediation boundary."
            regressions = outside
        elif request.fixed_snapshot.revision == request.original_revision:
            summary = "The fixed revision is identical to the vulnerable revision."
        elif request.security_test is None:
            summary = "No deterministic security regression test receipt was supplied."
        elif not request.security_test.passed or request.security_test.exit_code != 0:
            verdict = FixVerificationVerdict.NOT_FIXED
            summary = "The security regression test still reproduces the original attack condition."
        elif request.original_attack_blocked is not True:
            verdict = FixVerificationVerdict.PARTIALLY_FIXED
            summary = "The test passed, but the original attack recipe was not independently shown blocked."
        else:
            failed_regressions = tuple(
                receipt.verifier_id
                for receipt in request.regression_tests
                if not receipt.passed or receipt.exit_code != 0
            )
            if failed_regressions:
                verdict = FixVerificationVerdict.REGRESSION_DETECTED
                summary = "The security condition is blocked, but one or more regression verifiers failed."
                regressions = failed_regressions
            elif not request.regression_tests:
                verdict = FixVerificationVerdict.PARTIALLY_FIXED
                summary = "The attack is blocked, but no broader regression suite receipt was supplied."
            else:
                self._validate_evidence_references(
                    request.fixed_snapshot,
                    request.fixed_evidence_refs,
                )
                verdict = FixVerificationVerdict.FIXED
                summary = (
                    "The original attack condition is blocked, the security test passes, all supplied "
                    "regression verifiers pass, and fixed evidence references match the exact snapshot."
                )

        return FixVerificationReport(
            finding_id=request.finding_id,
            original_revision=request.original_revision,
            fixed_revision=request.fixed_snapshot.revision,
            verdict=verdict,
            summary=summary,
            evidence_refs=request.fixed_evidence_refs,
            regressions=regressions,
            created_at=datetime.now(UTC),
        )

    @staticmethod
    def _path_allowed(path: str, allowed: tuple[str, ...]) -> bool:
        candidate = PurePosixPath(path)
        return any(
            root == "."
            or candidate == PurePosixPath(root)
            or PurePosixPath(root) in candidate.parents
            for root in allowed
        )

    @staticmethod
    def _validate_evidence_references(
        snapshot: RepositorySnapshot,
        references: tuple[SourceReference, ...],
    ) -> None:
        files = {item.path: item for item in snapshot.files}
        for reference in references:
            file = files.get(reference.path)
            if file is None or file.sha256 != reference.source_sha256:
                raise ValueError("fix verifier received evidence outside the fixed snapshot")
            if reference.line_end > max(1, file.line_count):
                raise ValueError("fix verifier received an out-of-range source line")
