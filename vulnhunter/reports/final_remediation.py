"""Governed final remediation reports and signed unreleased export manifests."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import shutil
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from vulnhunter.actions.models import sha256_json
from vulnhunter.exceptions import (
    GovernanceAuthenticationError,
    GovernanceError,
    GovernancePolicyError,
)
from vulnhunter.findings.models import (
    EvidenceReference,
    FinalReportReference,
    FindingSeverity,
    FindingStatus,
    RemediationReviewOutcome,
    RemediationState,
    RetestOutcome,
    VerificationState,
)
from vulnhunter.findings.service import FindingLifecycleError, FindingService
from vulnhunter.findings.store import FindingConflict, FindingStore, FindingStoreError
from vulnhunter.governance.service import authenticate_identity
from vulnhunter.governance.store import GovernanceStore
from vulnhunter.reports.export import ReportExporter
from vulnhunter.security import redact_text

_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class FinalRemediationReportError(RuntimeError):
    """Final report generation violated an authority, integrity, or storage boundary."""


class FinalReportFormat(StrEnum):
    JSON = "json"
    HTML = "html"
    PDF = "pdf"


class PdfRendererReadiness(BaseModel):
    """Explicit readiness contract for the optional deterministic PDF renderer."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    enabled: bool = False
    renderer_id: str = "builtin-minimal-pdf"
    renderer_version: str = Field(min_length=1, max_length=50)
    renderer_sha256: str

    @field_validator("renderer_id")
    @classmethod
    def validate_renderer_id(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("PDF renderer ID must be a stable lowercase identifier")
        return value

    @field_validator("renderer_sha256")
    @classmethod
    def validate_renderer_sha256(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("PDF renderer digest must be a SHA-256 value")
        return value


class FinalReportFindingSummary(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    finding_id: str
    campaign_id: str
    fingerprint: str
    title: str
    description: str
    severity: FindingSeverity
    confidence: int = Field(ge=0, le=100)
    verification: VerificationState
    status_at_generation: FindingStatus
    affected_asset: str
    affected_component: str


class FinalReportRemediationSummary(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    remediation_id: str
    summary: str
    owner_id: str
    target_references: tuple[str, ...]
    regression_test: str
    verification_recipe: str
    compatibility_risks: tuple[str, ...]


class FinalReportVerificationSummary(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    receipt_id: str
    sha256: str
    verdict: Literal["fixed"]
    original_revision: str
    fixed_revision: str
    builder_id: str
    verifier_id: str


class FinalReportRetestSummary(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    receipt_id: str
    sha256: str
    outcome: RetestOutcome
    retest_id: str
    operator_id: str
    fixed_revision: str


class FinalReportReviewSummary(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    receipt_id: str
    sha256: str
    outcome: RemediationReviewOutcome
    reviewer_id: str
    reviewer_identity_sha256: str
    rationale: str
    limitations: tuple[str, ...]
    fixed_revision: str
    retest_receipt_id: str


class FinalReportEvidenceCitation(BaseModel):
    """Redacted metadata citation; raw evidence bytes are never embedded."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence_id: str
    sha256: str
    provenance: str
    content_type: str

    @field_validator("evidence_id")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("report evidence identifiers must be stable")
        return value

    @field_validator("sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("report evidence citation requires a SHA-256 digest")
        return value


class FinalRemediationReport(BaseModel):
    """Stable schema for one reviewed and retested remediation result."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = "1.0"
    report_id: str
    source_finding_revision: int = Field(ge=0)
    finding: FinalReportFindingSummary
    remediation: FinalReportRemediationSummary
    verification: FinalReportVerificationSummary
    retest: FinalReportRetestSummary
    review: FinalReportReviewSummary
    evidence_citations: tuple[FinalReportEvidenceCitation, ...] = Field(min_length=1)
    limitations: tuple[str, ...] = ()
    generated_by: str
    generator_identity_sha256: str
    generated_at: datetime
    release_state: Literal["unreleased"] = "unreleased"

    @field_validator("report_id", "generated_by")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("final report identifiers must be stable lowercase values")
        return value

    @field_validator("generator_identity_sha256")
    @classmethod
    def validate_identity_sha256(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("final report generator identity must be digest-bound")
        return value

    @field_validator("limitations")
    @classmethod
    def validate_limitations(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        cleaned = tuple(" ".join(value.split()) for value in values if value.strip())
        if len(cleaned) != len(values):
            raise ValueError("final report limitations must not be blank")
        if len(set(cleaned)) != len(cleaned):
            raise ValueError("final report limitations must be unique")
        if any(len(value) > 1_000 for value in cleaned):
            raise ValueError("final report limitations must not exceed 1,000 characters")
        return cleaned

    @model_validator(mode="after")
    def validate_lineage(self) -> Self:
        if self.generated_at.tzinfo is None or self.generated_at.utcoffset() is None:
            raise ValueError("final report generation time must be timezone-aware")
        if self.finding.status_at_generation != FindingStatus.READY_FOR_REPORT:
            raise ValueError("final report requires the ready-for-report finding state")
        if self.verification.verdict != "fixed":
            raise ValueError("final report requires a fixed verification verdict")
        if self.retest.outcome != RetestOutcome.PASSED:
            raise ValueError("final report requires a passed governed retest")
        if self.review.outcome != RemediationReviewOutcome.APPROVED:
            raise ValueError("final report requires an approved independent review")
        revisions = {
            self.verification.fixed_revision,
            self.retest.fixed_revision,
            self.review.fixed_revision,
        }
        if len(revisions) != 1:
            raise ValueError("final report lineage is bound to different fixed revisions")
        if self.review.retest_receipt_id != self.retest.receipt_id:
            raise ValueError("final report review is bound to another retest receipt")
        return self

    def fingerprint(self) -> str:
        return sha256_json(self.model_dump(mode="json"))

    @classmethod
    def create(
        cls,
        *,
        source_finding_revision: int,
        finding: FinalReportFindingSummary,
        remediation: FinalReportRemediationSummary,
        verification: FinalReportVerificationSummary,
        retest: FinalReportRetestSummary,
        review: FinalReportReviewSummary,
        evidence_citations: tuple[FinalReportEvidenceCitation, ...],
        limitations: tuple[str, ...],
        generated_by: str,
        generator_identity_sha256: str,
        generated_at: datetime,
    ) -> FinalRemediationReport:
        canonical = {
            "schema_version": "1.0",
            "source_finding_revision": source_finding_revision,
            "finding": finding.model_dump(mode="json"),
            "remediation": remediation.model_dump(mode="json"),
            "verification": verification.model_dump(mode="json"),
            "retest": retest.model_dump(mode="json"),
            "review": review.model_dump(mode="json"),
            "evidence_citations": [item.model_dump(mode="json") for item in evidence_citations],
            "limitations": list(limitations),
            "generated_by": generated_by,
            "generator_identity_sha256": generator_identity_sha256,
            "generated_at": generated_at.astimezone(UTC).isoformat(),
            "release_state": "unreleased",
        }
        digest = sha256_json(canonical)
        return cls(
            report_id=f"final-report-{digest[:24]}",
            source_finding_revision=source_finding_revision,
            finding=finding,
            remediation=remediation,
            verification=verification,
            retest=retest,
            review=review,
            evidence_citations=evidence_citations,
            limitations=limitations,
            generated_by=generated_by,
            generator_identity_sha256=generator_identity_sha256,
            generated_at=generated_at,
        )


class FinalReportArtifactReference(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    format: FinalReportFormat
    filename: str = Field(min_length=3, max_length=220)
    content_type: str = Field(min_length=3, max_length=200)
    sha256: str
    size_bytes: int = Field(ge=1)

    @field_validator("sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("final report artifact requires a SHA-256 digest")
        return value


class FinalReportManifest(BaseModel):
    """Signed manifest for unreleased report artifacts."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = "1.0"
    manifest_id: str
    report_id: str
    report_sha256: str
    artifacts: tuple[FinalReportArtifactReference, ...] = Field(min_length=2, max_length=3)
    provenance: tuple[str, ...] = Field(min_length=3)
    generated_by: str
    generator_identity_sha256: str
    pdf_renderer: PdfRendererReadiness | None = None
    release_state: Literal["unreleased"] = "unreleased"
    created_at: datetime

    @field_validator("manifest_id", "report_id", "generated_by")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("final report manifest identifiers must be stable")
        return value

    @field_validator("report_sha256", "generator_identity_sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("final report manifest digest fields must be SHA-256 values")
        return value

    @model_validator(mode="after")
    def validate_manifest(self) -> Self:
        if self.created_at.tzinfo is None or self.created_at.utcoffset() is None:
            raise ValueError("final report manifest time must be timezone-aware")
        formats = tuple(item.format for item in self.artifacts)
        if len(set(formats)) != len(formats):
            raise ValueError("final report manifest formats must be unique")
        if FinalReportFormat.JSON not in formats or FinalReportFormat.HTML not in formats:
            raise ValueError("final report manifest requires JSON and HTML artifacts")
        if FinalReportFormat.PDF in formats:
            if self.pdf_renderer is None or not self.pdf_renderer.enabled:
                raise ValueError("PDF artifact requires an enabled renderer readiness contract")
        elif self.pdf_renderer is not None:
            raise ValueError("PDF renderer metadata requires a PDF artifact")
        return self

    def fingerprint(self) -> str:
        return sha256_json(self.model_dump(mode="json"))

    @classmethod
    def create(
        cls,
        *,
        report: FinalRemediationReport,
        artifacts: tuple[FinalReportArtifactReference, ...],
        provenance: tuple[str, ...],
        pdf_renderer: PdfRendererReadiness | None,
    ) -> FinalReportManifest:
        canonical = {
            "schema_version": "1.0",
            "report_id": report.report_id,
            "report_sha256": report.fingerprint(),
            "artifacts": [item.model_dump(mode="json") for item in artifacts],
            "provenance": list(provenance),
            "generated_by": report.generated_by,
            "generator_identity_sha256": report.generator_identity_sha256,
            "pdf_renderer": (
                pdf_renderer.model_dump(mode="json") if pdf_renderer is not None else None
            ),
            "release_state": "unreleased",
            "created_at": report.generated_at.astimezone(UTC).isoformat(),
        }
        digest = sha256_json(canonical)
        return cls(
            manifest_id=f"report-manifest-{digest[:24]}",
            report_id=report.report_id,
            report_sha256=report.fingerprint(),
            artifacts=artifacts,
            provenance=provenance,
            generated_by=report.generated_by,
            generator_identity_sha256=report.generator_identity_sha256,
            pdf_renderer=pdf_renderer,
            created_at=report.generated_at,
        )


class FinalReportBundle(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    report: FinalRemediationReport
    manifest: FinalReportManifest

    @model_validator(mode="after")
    def validate_bundle(self) -> Self:
        if self.manifest.report_id != self.report.report_id:
            raise ValueError("final report manifest is bound to another report")
        if self.manifest.report_sha256 != self.report.fingerprint():
            raise ValueError("final report manifest digest does not match the report")
        return self


class BuiltInPdfRenderer:
    """Small deterministic text renderer, activated only by explicit readiness."""

    def __init__(self, readiness: PdfRendererReadiness) -> None:
        self.readiness = readiness

    def render(self, report: FinalRemediationReport) -> bytes:
        if not self.readiness.enabled:
            raise FinalRemediationReportError("PDF renderer is not configured as ready")
        lines = (
            "VulnHunter AI final remediation report",
            f"Report: {report.report_id}",
            f"Finding: {report.finding.finding_id} — {report.finding.title}",
            f"Severity: {report.finding.severity.value}",
            f"Verification: {report.verification.verdict}",
            f"Retest: {report.retest.outcome.value}",
            f"Independent review: {report.review.outcome.value}",
            f"Fixed revision: {report.verification.fixed_revision}",
            "Release state: unreleased",
            "Publication, closure and deployment require separate human authority.",
        )
        return self._minimal_pdf(lines)

    @staticmethod
    def _minimal_pdf(lines: tuple[str, ...]) -> bytes:
        def escape(value: str) -> str:
            return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

        commands = ["BT", "/F1 11 Tf", "72 760 Td", "14 TL"]
        for index, line in enumerate(lines):
            if index:
                commands.append("T*")
            commands.append(f"({escape(line[:120])}) Tj")
        commands.append("ET")
        stream = "\n".join(commands).encode("latin-1", errors="replace")
        objects = (
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            (
                b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>"
            ),
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
            b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
        )
        output = bytearray(b"%PDF-1.4\n")
        offsets = [0]
        for number, body in enumerate(objects, start=1):
            offsets.append(len(output))
            output.extend(f"{number} 0 obj\n".encode())
            output.extend(body)
            output.extend(b"\nendobj\n")
        xref = len(output)
        output.extend(f"xref\n0 {len(objects) + 1}\n".encode())
        output.extend(b"0000000000 65535 f \n")
        for offset in offsets[1:]:
            output.extend(f"{offset:010d} 00000 n \n".encode())
        output.extend(
            (
                f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n"
            ).encode()
        )
        return bytes(output)


class FinalReportStore:
    """Atomic signed storage for one report and its immutable artifacts."""

    def __init__(self, root: Path, *, signing_key: bytes) -> None:
        if len(signing_key) < 16:
            raise FinalRemediationReportError("final report signing key is too short")
        self.root = root.expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self._signing_key = bytes(signing_key)

    def _directory(self, report_id: str) -> Path:
        if _IDENTIFIER.fullmatch(report_id) is None:
            raise FinalRemediationReportError("invalid final report identifier")
        return self.root / report_id

    def _signature(self, payload: dict[str, object]) -> str:
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        return hmac.new(self._signing_key, encoded, hashlib.sha256).hexdigest()

    def save(
        self,
        bundle: FinalReportBundle,
        *,
        artifacts: dict[FinalReportFormat, bytes],
    ) -> tuple[Path, bool]:
        destination = self._directory(bundle.report.report_id)
        if destination.exists():
            existing = self.load(bundle.report.report_id)
            if existing == bundle:
                return destination, False
            raise FinalRemediationReportError(
                "final report already exists with different immutable content"
            )
        expected = {item.format for item in bundle.manifest.artifacts}
        if set(artifacts) != expected:
            raise FinalRemediationReportError(
                "final report artifact set does not match its manifest"
            )
        staging = Path(tempfile.mkdtemp(prefix=".final-report-", dir=self.root))
        os.chmod(staging, 0o700)
        signed_payload = {
            "bundle": bundle.model_dump(mode="json"),
            "report_sha256": bundle.report.fingerprint(),
            "manifest_sha256": bundle.manifest.fingerprint(),
            "generator_identity_sha256": bundle.report.generator_identity_sha256,
        }
        envelope = {**signed_payload, "signature_sha256": self._signature(signed_payload)}
        try:
            references = {item.format: item for item in bundle.manifest.artifacts}
            for format, raw in artifacts.items():
                reference = references[format]
                if hashlib.sha256(raw).hexdigest() != reference.sha256:
                    raise FinalRemediationReportError(
                        "final report artifact digest does not match its manifest"
                    )
                if len(raw) != reference.size_bytes:
                    raise FinalRemediationReportError(
                        "final report artifact size does not match its manifest"
                    )
                path = staging / reference.filename
                descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(raw)
                    handle.flush()
                    os.fsync(handle.fileno())
            manifest_path = staging / "manifest.json"
            descriptor = os.open(
                manifest_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(
                    envelope,
                    handle,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                )
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(staging, destination)
        except Exception:
            shutil.rmtree(staging, ignore_errors=True)
            raise
        return destination, True

    def load(self, report_id: str) -> FinalReportBundle:
        directory = self._directory(report_id)
        manifest_path = directory / "manifest.json"
        try:
            if directory.is_symlink() or manifest_path.is_symlink():
                raise FinalRemediationReportError("final report storage contains an unsafe symlink")
            envelope = json.loads(manifest_path.read_text(encoding="utf-8"))
            signed_payload = {
                "bundle": envelope["bundle"],
                "report_sha256": envelope["report_sha256"],
                "manifest_sha256": envelope["manifest_sha256"],
                "generator_identity_sha256": envelope["generator_identity_sha256"],
            }
            signature = str(envelope["signature_sha256"])
        except FinalRemediationReportError:
            raise
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise FinalRemediationReportError(
                "final report manifest is unavailable or invalid"
            ) from exc
        if not hmac.compare_digest(signature, self._signature(signed_payload)):
            raise FinalRemediationReportError("final report manifest signature verification failed")
        try:
            bundle = FinalReportBundle.model_validate(signed_payload["bundle"])
        except ValidationError as exc:
            raise FinalRemediationReportError("final report bundle has an invalid schema") from exc
        if bundle.report.report_id != report_id:
            raise FinalRemediationReportError("final report directory is bound to another report")
        if bundle.report.fingerprint() != signed_payload["report_sha256"]:
            raise FinalRemediationReportError("final report failed integrity verification")
        if bundle.manifest.fingerprint() != signed_payload["manifest_sha256"]:
            raise FinalRemediationReportError("final report manifest failed integrity verification")
        if bundle.report.generator_identity_sha256 != signed_payload["generator_identity_sha256"]:
            raise FinalRemediationReportError("final report generator attestation does not match")
        for artifact in bundle.manifest.artifacts:
            path = directory / artifact.filename
            try:
                if path.is_symlink():
                    raise FinalRemediationReportError(
                        "final report artifact contains an unsafe symlink"
                    )
                raw = path.read_bytes()
            except FinalRemediationReportError:
                raise
            except OSError as exc:
                raise FinalRemediationReportError("final report artifact is unavailable") from exc
            if len(raw) != artifact.size_bytes:
                raise FinalRemediationReportError("final report artifact size failed verification")
            if hashlib.sha256(raw).hexdigest() != artifact.sha256:
                raise FinalRemediationReportError(
                    "final report artifact integrity verification failed"
                )
        return bundle

    def artifact_path(self, report_id: str, format: str | FinalReportFormat) -> Path:
        bundle = self.load(report_id)
        try:
            normalized = FinalReportFormat(format)
        except ValueError as exc:
            raise FinalRemediationReportError("unsupported final report artifact format") from exc
        for artifact in bundle.manifest.artifacts:
            if artifact.format == normalized:
                path = self._directory(report_id) / artifact.filename
                if path.is_symlink():
                    raise FinalRemediationReportError("unsafe final report artifact path")
                return path
        raise FinalRemediationReportError("requested final report artifact was not generated")

    def delete(self, report_id: str) -> None:
        directory = self._directory(report_id)
        if directory.exists() and not directory.is_symlink():
            shutil.rmtree(directory)


@dataclass
class FinalRemediationReportService:
    """Authenticate a separate report writer and persist one exact final report."""

    finding_store: FindingStore
    governance_store: GovernanceStore
    fix_verification_store: object
    retest_receipt_store: object
    review_receipt_store: object
    report_store: FinalReportStore
    pdf_renderer: BuiltInPdfRenderer | None = None
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)

    def generate(
        self,
        *,
        finding_id: str,
        expected_revision: int,
        generator_id: str,
        generator_secret: str,
        limitations: tuple[str, ...] = (),
        include_pdf: bool = False,
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
        latest_review = (
            remediation.review_history[-1]
            if remediation is not None and remediation.review_history
            else None
        )
        if (
            finding.verification != VerificationState.VERIFIED
            or finding.status != FindingStatus.READY_FOR_REPORT
            or remediation is None
            or remediation.remediation_id is None
            or remediation.state != RemediationState.REVIEW_APPROVED
            or latest_verification is None
            or latest_verification.verdict != "fixed"
            or latest_retest is None
            or latest_retest.outcome != RetestOutcome.PASSED
            or latest_review is None
            or latest_review.outcome != RemediationReviewOutcome.APPROVED
        ):
            raise FinalRemediationReportError(
                "final report generation requires an approved remediation review"
            )

        fix_bundle = self.fix_verification_store.load(latest_verification.receipt_id)
        retest_bundle = self.retest_receipt_store.load(latest_retest.receipt_id)
        review_bundle = self.review_receipt_store.load(latest_review.receipt_id)
        normalized_generator = generator_id.strip().casefold()
        conflicts = {
            str(remediation.owner_id or ""): "remediation owner",
            str(getattr(fix_bundle, "builder_id", "")): "implementation builder",
            str(getattr(fix_bundle, "verifier_id", "")): "fix verifier",
            str(getattr(getattr(retest_bundle, "plan", None), "owner_id", "")): ("retest operator"),
            str(getattr(getattr(review_bundle, "plan", None), "reviewer_id", "")): (
                "independent reviewer"
            ),
        }
        conflict_role = conflicts.get(normalized_generator)
        if conflict_role:
            raise FinalRemediationReportError(f"the report writer cannot be the {conflict_role}")
        try:
            identity = authenticate_identity(
                self.governance_store,
                normalized_generator,
                generator_secret,
                required_role="campaign_admin",
            )
        except (GovernanceAuthenticationError, GovernancePolicyError, GovernanceError) as exc:
            raise FinalRemediationReportError(str(exc)) from exc

        self._verify_receipt_lineage(
            latest_verification=latest_verification,
            latest_retest=latest_retest,
            latest_review=latest_review,
            fix_bundle=fix_bundle,
            retest_bundle=retest_bundle,
            review_bundle=review_bundle,
        )
        now = self.clock().astimezone(UTC)
        if now < finding.updated_at.astimezone(UTC):
            raise FinalRemediationReportError(
                "final report timestamp cannot predate the current finding revision"
            )
        combined_limitations = self._limitations(
            tuple(getattr(review_bundle, "limitations", ())) + limitations
        )
        try:
            report = FinalRemediationReport.create(
                source_finding_revision=finding.revision,
                finding=FinalReportFindingSummary(
                    finding_id=finding.finding_id,
                    campaign_id=finding.campaign_id,
                    fingerprint=finding.fingerprint,
                    title=redact_text(finding.title),
                    description=redact_text(finding.description),
                    severity=finding.severity,
                    confidence=finding.confidence,
                    verification=finding.verification,
                    status_at_generation=finding.status,
                    affected_asset=redact_text(finding.affected_asset),
                    affected_component=redact_text(finding.affected_component or "Not specified"),
                ),
                remediation=FinalReportRemediationSummary(
                    remediation_id=remediation.remediation_id,
                    summary=redact_text(remediation.summary),
                    owner_id=remediation.owner_id or "unknown-owner",
                    target_references=tuple(
                        redact_text(item) for item in remediation.target_references
                    ),
                    regression_test=redact_text(remediation.regression_test or "Unavailable"),
                    verification_recipe=redact_text(
                        remediation.verification_recipe or "Unavailable"
                    ),
                    compatibility_risks=tuple(
                        redact_text(item) for item in remediation.compatibility_risks
                    ),
                ),
                verification=FinalReportVerificationSummary(
                    receipt_id=latest_verification.receipt_id,
                    sha256=latest_verification.sha256,
                    verdict="fixed",
                    original_revision=latest_verification.original_revision,
                    fixed_revision=latest_verification.fixed_revision,
                    builder_id=str(getattr(fix_bundle, "builder_id", "unknown-builder")),
                    verifier_id=str(getattr(fix_bundle, "verifier_id", "unknown-verifier")),
                ),
                retest=FinalReportRetestSummary(
                    receipt_id=latest_retest.receipt_id,
                    sha256=latest_retest.sha256,
                    outcome=latest_retest.outcome,
                    retest_id=latest_retest.retest_id,
                    operator_id=str(
                        getattr(
                            getattr(retest_bundle, "plan", None), "owner_id", "unknown-operator"
                        )
                    ),
                    fixed_revision=latest_retest.fixed_revision,
                ),
                review=FinalReportReviewSummary(
                    receipt_id=latest_review.receipt_id,
                    sha256=latest_review.sha256,
                    outcome=latest_review.outcome,
                    reviewer_id=latest_review.reviewer_id,
                    reviewer_identity_sha256=latest_review.reviewer_identity_sha256,
                    rationale=redact_text(str(getattr(review_bundle, "rationale", "Unavailable"))),
                    limitations=tuple(
                        redact_text(item)
                        for item in tuple(getattr(review_bundle, "limitations", ()))
                    ),
                    fixed_revision=latest_review.fixed_revision,
                    retest_receipt_id=latest_review.retest_receipt_id,
                ),
                evidence_citations=tuple(
                    FinalReportEvidenceCitation(
                        evidence_id=item.evidence_id,
                        sha256=item.sha256,
                        provenance=redact_text(item.provenance),
                        content_type=item.content_type,
                    )
                    for item in finding.evidence
                ),
                limitations=combined_limitations,
                generated_by=identity.reviewer_id,
                generator_identity_sha256=identity.record_sha256,
                generated_at=now,
            )
        except ValueError as exc:
            raise FinalRemediationReportError(str(exc)) from exc

        artifact_bytes, artifact_references, readiness = self._render_artifacts(
            report,
            include_pdf=include_pdf,
        )
        provenance = (
            latest_verification.receipt_id,
            latest_retest.receipt_id,
            latest_review.receipt_id,
            *(item.evidence_id for item in finding.evidence),
        )
        manifest = FinalReportManifest.create(
            report=report,
            artifacts=artifact_references,
            provenance=provenance,
            pdf_renderer=readiness,
        )
        bundle = FinalReportBundle(report=report, manifest=manifest)
        _path, created = self.report_store.save(bundle, artifacts=artifact_bytes)
        reference = FinalReportReference(
            report_id=report.report_id,
            manifest_id=manifest.manifest_id,
            report_sha256=report.fingerprint(),
            manifest_sha256=manifest.fingerprint(),
            generator_id=identity.reviewer_id,
            generator_identity_sha256=identity.record_sha256,
            fixed_revision=latest_verification.fixed_revision,
            review_receipt_id=latest_review.receipt_id,
            formats=tuple(item.format.value for item in manifest.artifacts),
            created_at=now,
        )
        evidence = EvidenceReference(
            evidence_id=manifest.manifest_id,
            sha256=manifest.fingerprint(),
            provenance=(
                "signed unreleased final remediation report manifest; publication authority absent"
            ),
            content_type="application/vnd.vulnhunter.final-report-manifest+json",
        )
        try:
            updated = FindingService(self.finding_store).record_final_report(
                finding_id,
                report=reference,
                evidence=evidence,
                expected_revision=expected_revision,
                now=now,
            )
        except (FindingConflict, FindingLifecycleError, FindingStoreError):
            if created:
                self.report_store.delete(report.report_id)
            raise
        return updated, bundle

    @staticmethod
    def _limitations(values: tuple[str, ...]) -> tuple[str, ...]:
        cleaned: list[str] = []
        for value in values:
            normalized = " ".join(redact_text(value).split())[:1_000]
            if normalized and normalized not in cleaned:
                cleaned.append(normalized)
        return tuple(cleaned)

    @staticmethod
    def _verify_receipt_lineage(
        *,
        latest_verification,
        latest_retest,
        latest_review,
        fix_bundle,
        retest_bundle,
        review_bundle,
    ) -> None:
        if str(fix_bundle.fingerprint()) != latest_verification.sha256:
            raise FinalRemediationReportError(
                "fix-verification receipt failed integrity verification"
            )
        if str(retest_bundle.fingerprint()) != latest_retest.sha256:
            raise FinalRemediationReportError("retest receipt failed integrity verification")
        if str(review_bundle.fingerprint()) != latest_review.sha256:
            raise FinalRemediationReportError("review receipt failed integrity verification")
        fixed_revision = str(getattr(getattr(fix_bundle, "fixed_snapshot", None), "revision", ""))
        retest_revision = str(getattr(getattr(retest_bundle, "plan", None), "fixed_revision", ""))
        review_plan = getattr(review_bundle, "plan", None)
        review_revision = str(getattr(review_plan, "fixed_revision", ""))
        review_retest = str(getattr(review_plan, "retest_receipt_id", ""))
        review_fix = str(getattr(review_plan, "fix_verification_receipt_id", ""))
        if not fixed_revision or fixed_revision != latest_verification.fixed_revision:
            raise FinalRemediationReportError("fix receipt is bound to another fixed revision")
        if retest_revision != fixed_revision or latest_retest.fixed_revision != fixed_revision:
            raise FinalRemediationReportError("retest receipt is bound to another fixed revision")
        if review_revision != fixed_revision or latest_review.fixed_revision != fixed_revision:
            raise FinalRemediationReportError("review receipt is bound to another fixed revision")
        if review_retest != latest_retest.receipt_id:
            raise FinalRemediationReportError("review receipt is bound to another retest receipt")
        if review_fix != latest_verification.receipt_id:
            raise FinalRemediationReportError(
                "review receipt is bound to another fix-verification receipt"
            )

    def _render_artifacts(
        self,
        report: FinalRemediationReport,
        *,
        include_pdf: bool,
    ) -> tuple[
        dict[FinalReportFormat, bytes],
        tuple[FinalReportArtifactReference, ...],
        PdfRendererReadiness | None,
    ]:
        payload = report.model_dump(mode="json")
        provenance = (
            report.verification.receipt_id,
            report.retest.receipt_id,
            report.review.receipt_id,
        )
        raw: dict[FinalReportFormat, bytes] = {}
        content_types = {
            FinalReportFormat.JSON: "application/json",
            FinalReportFormat.HTML: "text/html; charset=utf-8",
            FinalReportFormat.PDF: "application/pdf",
        }
        filenames = {
            FinalReportFormat.JSON: f"{report.report_id}.json",
            FinalReportFormat.HTML: f"{report.report_id}.html",
            FinalReportFormat.PDF: f"{report.report_id}.pdf",
        }
        with TemporaryDirectory(prefix="vulnhunter-final-report-") as temporary:
            exporter = ReportExporter(Path(temporary))
            json_artifact = exporter.export_json(
                artifact_id=report.report_id,
                payload=payload,
                provenance=provenance,
            )
            html_artifact = exporter.export_html(
                artifact_id=report.report_id,
                title=f"VulnHunter final remediation report — {report.finding.title}",
                payload=payload,
                provenance=provenance,
            )
            raw[FinalReportFormat.JSON] = Path(json_artifact.path).read_bytes()
            raw[FinalReportFormat.HTML] = Path(html_artifact.path).read_bytes()
        readiness = None
        if include_pdf:
            if self.pdf_renderer is None or not self.pdf_renderer.readiness.enabled:
                raise FinalRemediationReportError("PDF generation was requested but is not ready")
            readiness = self.pdf_renderer.readiness
            raw[FinalReportFormat.PDF] = self.pdf_renderer.render(report)
        references = tuple(
            FinalReportArtifactReference(
                format=format,
                filename=filenames[format],
                content_type=content_types[format],
                sha256=hashlib.sha256(data).hexdigest(),
                size_bytes=len(data),
            )
            for format, data in raw.items()
        )
        return raw, references, readiness


__all__ = [
    "BuiltInPdfRenderer",
    "FinalRemediationReport",
    "FinalRemediationReportError",
    "FinalRemediationReportService",
    "FinalReportArtifactReference",
    "FinalReportBundle",
    "FinalReportEvidenceCitation",
    "FinalReportFormat",
    "FinalReportManifest",
    "FinalReportStore",
    "PdfRendererReadiness",
]
