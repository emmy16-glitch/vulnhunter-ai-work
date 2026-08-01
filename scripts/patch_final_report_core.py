from pathlib import Path


def replace_once(path: Path, old: str, new: str, *, label: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"Expected exactly one {label} block in {path}, found {count}")
    path.write_text(text.replace(old, new), encoding="utf-8")


models = Path("vulnhunter/findings/models.py")
replace_once(
    models,
    '''    READY_FOR_REPORT = "ready_for_report"
    REMEDIATED = "remediated"
''',
    '''    READY_FOR_REPORT = "ready_for_report"
    REPORT_GENERATED = "report_generated"
    REMEDIATED = "remediated"
''',
    label="finding report-generated status",
)
replace_once(
    models,
    '''    REVIEW_APPROVED = "review_approved"
    CANCELLED = "cancelled"
''',
    '''    REVIEW_APPROVED = "review_approved"
    REPORT_GENERATED = "report_generated"
    CANCELLED = "cancelled"
''',
    label="remediation report-generated state",
)
replace_once(
    models,
    '''class RemediationRecord(BaseModel):
''',
    '''class FinalReportReference(BaseModel):
    """Integrity pointer to one signed unreleased final report manifest."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    report_id: str
    manifest_id: str
    report_sha256: str
    manifest_sha256: str
    generator_id: str
    generator_identity_sha256: str
    fixed_revision: str = Field(min_length=1, max_length=256)
    review_receipt_id: str
    formats: tuple[str, ...] = Field(min_length=2, max_length=3)
    created_at: datetime

    @field_validator("report_id", "manifest_id", "generator_id", "review_receipt_id")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("final report references require stable identifiers")
        return value

    @field_validator("report_sha256", "manifest_sha256", "generator_identity_sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        if _SHA256.fullmatch(value) is None:
            raise ValueError("final report references require SHA-256 values")
        return value

    @field_validator("formats")
    @classmethod
    def validate_formats(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        allowed = {"json", "html", "pdf"}
        if len(set(values)) != len(values) or not set(values).issubset(allowed):
            raise ValueError("final report formats must be unique supported values")
        if "json" not in values or "html" not in values:
            raise ValueError("final report references require JSON and HTML")
        return values

    @model_validator(mode="after")
    def validate_reference(self) -> Self:
        if self.created_at.tzinfo is None or self.created_at.utcoffset() is None:
            raise ValueError("final report reference time must be timezone-aware")
        return self


class RemediationRecord(BaseModel):
''',
    label="final report reference model",
)
replace_once(
    models,
    '''    review_history: tuple[RemediationReviewReference, ...] = ()
    created_at: datetime | None = None
''',
    '''    review_history: tuple[RemediationReviewReference, ...] = ()
    report_history: tuple[FinalReportReference, ...] = ()
    created_at: datetime | None = None
''',
    label="remediation report history field",
)
replace_once(
    models,
    '''                self.review_history,
                self.created_at,
''',
    '''                self.review_history,
                self.report_history,
                self.created_at,
''',
    label="legacy report history validation",
)
replace_once(
    models,
    '''        latest_review = self.review_history[-1] if self.review_history else None
        if self.state == RemediationState.READY_FOR_IMPLEMENTATION:
''',
    '''        latest_review = self.review_history[-1] if self.review_history else None
        latest_report = self.report_history[-1] if self.report_history else None
        if self.state == RemediationState.READY_FOR_IMPLEMENTATION:
''',
    label="latest report binding",
)
replace_once(
    models,
    '''        elif self.state == RemediationState.REVIEW_APPROVED:
            if (
                latest_verification is None
                or latest_retest is None
                or latest_review is None
                or latest_review.outcome != RemediationReviewOutcome.APPROVED
                or latest_retest.outcome != RetestOutcome.PASSED
                or latest_retest.fixed_revision != latest_verification.fixed_revision
                or latest_review.fixed_revision != latest_verification.fixed_revision
                or latest_review.retest_receipt_id != latest_retest.receipt_id
            ):
                raise ValueError(
                    "review-approved remediation requires approval of the latest passed retest"
                )

        if self.state == RemediationState.CANCELLED:
''',
    '''        elif self.state == RemediationState.REVIEW_APPROVED:
            if (
                latest_verification is None
                or latest_retest is None
                or latest_review is None
                or latest_review.outcome != RemediationReviewOutcome.APPROVED
                or latest_retest.outcome != RetestOutcome.PASSED
                or latest_retest.fixed_revision != latest_verification.fixed_revision
                or latest_review.fixed_revision != latest_verification.fixed_revision
                or latest_review.retest_receipt_id != latest_retest.receipt_id
                or latest_report is not None
            ):
                raise ValueError(
                    "review-approved remediation requires approval of the latest passed retest"
                )
        elif self.state == RemediationState.REPORT_GENERATED:
            if (
                latest_verification is None
                or latest_retest is None
                or latest_review is None
                or latest_report is None
                or latest_review.outcome != RemediationReviewOutcome.APPROVED
                or latest_retest.outcome != RetestOutcome.PASSED
                or latest_report.fixed_revision != latest_verification.fixed_revision
                or latest_report.fixed_revision != latest_review.fixed_revision
                or latest_report.review_receipt_id != latest_review.receipt_id
            ):
                raise ValueError(
                    "report-generated remediation requires the latest approved review and report"
                )

        if self.state == RemediationState.CANCELLED:
''',
    label="report-generated remediation validation",
)
replace_once(
    models,
    '''    def cancel(self, *, cancelled_at: datetime, reason: str) -> RemediationRecord:
''',
    '''    def record_report(self, reference: FinalReportReference) -> RemediationRecord:
        if self.remediation_id is None or self.state is None:
            raise ValueError("legacy remediation notes cannot record final reports")
        if self.state != RemediationState.REVIEW_APPROVED:
            raise ValueError("the remediation plan is not ready for final report generation")
        if any(item.report_id == reference.report_id for item in self.report_history):
            raise ValueError("the final report is already recorded")
        latest_verification = self.verification_history[-1] if self.verification_history else None
        latest_review = self.review_history[-1] if self.review_history else None
        if latest_verification is None or latest_review is None:
            raise ValueError("final report requires verification and review history")
        if reference.fixed_revision != latest_verification.fixed_revision:
            raise ValueError("final report is bound to another fixed revision")
        if reference.review_receipt_id != latest_review.receipt_id:
            raise ValueError("final report is bound to another review receipt")
        return RemediationRecord.model_validate(
            self.model_copy(
                update={
                    "state": RemediationState.REPORT_GENERATED,
                    "report_history": self.report_history + (reference,),
                }
            ).model_dump()
        )

    def cancel(self, *, cancelled_at: datetime, reason: str) -> RemediationRecord:
''',
    label="record final report method",
)
replace_once(
    models,
    '''            RemediationState.REVIEW_APPROVED,
        }:
''',
    '''            RemediationState.REVIEW_APPROVED,
            RemediationState.REPORT_GENERATED,
        }:
''',
    label="report-generated cancellation boundary",
)
replace_once(
    models,
    '''        if self.status == FindingStatus.READY_FOR_REPORT:
            if (
                self.remediation is None
                or self.remediation.remediation_id is None
                or self.remediation.state != RemediationState.REVIEW_APPROVED
            ):
                raise ValueError("report-ready findings require approved remediation review")
        if self.status == FindingStatus.REMEDIATED:
''',
    '''        if self.status == FindingStatus.READY_FOR_REPORT:
            if (
                self.remediation is None
                or self.remediation.remediation_id is None
                or self.remediation.state != RemediationState.REVIEW_APPROVED
            ):
                raise ValueError("report-ready findings require approved remediation review")
        if self.status == FindingStatus.REPORT_GENERATED:
            if (
                self.remediation is None
                or self.remediation.remediation_id is None
                or self.remediation.state != RemediationState.REPORT_GENERATED
                or not self.remediation.report_history
            ):
                raise ValueError("report-generated findings require an immutable final report")
        if self.status == FindingStatus.REMEDIATED:
''',
    label="finding report-generated validation",
)
replace_once(
    models,
    '''            if (
                new_remediation.review_history[: len(old_remediation.review_history)]
                != old_remediation.review_history
            ):
                raise ValueError("remediation review history is append-only")
            if (
''',
    '''            if (
                new_remediation.review_history[: len(old_remediation.review_history)]
                != old_remediation.review_history
            ):
                raise ValueError("remediation review history is append-only")
            if (
                new_remediation.report_history[: len(old_remediation.report_history)]
                != old_remediation.report_history
            ):
                raise ValueError("remediation report history is append-only")
            if (
''',
    label="append-only report history",
)

service = Path("vulnhunter/findings/service.py")
replace_once(
    service,
    '''    EvidenceReference,
    Finding,
''',
    '''    EvidenceReference,
    FinalReportReference,
    Finding,
''',
    label="final report service import",
)
replace_once(
    service,
    '''    def cancel_remediation(
''',
    '''    def record_final_report(
        self,
        finding_id: str,
        *,
        report: FinalReportReference,
        evidence: EvidenceReference,
        expected_revision: int,
        now: datetime | None = None,
    ) -> Finding:
        """Atomically append one signed unreleased final report without closing."""

        finding = self.store.get(finding_id)
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
        latest_review = (
            remediation.review_history[-1]
            if remediation is not None and remediation.review_history
            else None
        )
        if (
            finding.status != FindingStatus.READY_FOR_REPORT
            or remediation is None
            or remediation.remediation_id is None
            or remediation.state != RemediationState.REVIEW_APPROVED
            or latest_verification is None
            or latest_verification.verdict != "fixed"
            or latest_review is None
            or latest_review.outcome != RemediationReviewOutcome.APPROVED
        ):
            raise FindingLifecycleError(
                "final report requires a ready-for-report approved remediation review"
            )
        if any(item.evidence_id == evidence.evidence_id for item in finding.evidence):
            raise FindingLifecycleError("the final report manifest is already linked")
        if evidence.evidence_id != report.manifest_id:
            raise FindingLifecycleError("final report evidence must identify the signed manifest")
        if evidence.sha256 != report.manifest_sha256:
            raise FindingLifecycleError("final report evidence must match the manifest digest")
        if report.fixed_revision != latest_verification.fixed_revision:
            raise FindingLifecycleError("final report is bound to another fixed revision")
        if report.review_receipt_id != latest_review.receipt_id:
            raise FindingLifecycleError("final report is bound to another review receipt")

        recorded_at = (now or datetime.now(UTC)).astimezone(UTC)
        if recorded_at < finding.updated_at.astimezone(UTC):
            raise FindingLifecycleError(
                "final report timestamp cannot predate the current finding revision"
            )
        if report.created_at.astimezone(UTC) != recorded_at:
            raise FindingLifecycleError(
                "final report reference and finding transition must share one timestamp"
            )
        updated_remediation = remediation.record_report(report)
        updated = Finding.model_validate(
            finding.model_copy(
                update={
                    "status": FindingStatus.REPORT_GENERATED,
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
''',
    label="record final report lifecycle service",
)

findings_init = Path("vulnhunter/findings/__init__.py")
replace_once(
    findings_init,
    '''    EvidenceReference,
    Finding,
''',
    '''    EvidenceReference,
    FinalReportReference,
    Finding,
''',
    label="final report reference import",
)
replace_once(
    findings_init,
    '''    "EvidenceReference",
    "Finding",
''',
    '''    "EvidenceReference",
    "FinalReportReference",
    "Finding",
''',
    label="final report reference export",
)

reports_init = Path("vulnhunter/reports/__init__.py")
replace_once(
    reports_init,
    '''from vulnhunter.reports.export import ReportExporter, ReportExportError
''',
    '''from vulnhunter.reports.export import ReportExporter, ReportExportError
from vulnhunter.reports.final_remediation import (
    BuiltInPdfRenderer,
    FinalRemediationReport,
    FinalRemediationReportError,
    FinalRemediationReportService,
    FinalReportArtifactReference,
    FinalReportBundle,
    FinalReportEvidenceCitation,
    FinalReportFormat,
    FinalReportManifest,
    FinalReportStore,
    PdfRendererReadiness,
)
''',
    label="final remediation report imports",
)
replace_once(
    reports_init,
    '''    "DownloadArtifact",
''',
    '''    "BuiltInPdfRenderer",
    "DownloadArtifact",
''',
    label="built-in PDF export",
)
replace_once(
    reports_init,
    '''    "DownloadFormat",
    "ReportArtifact",
''',
    '''    "DownloadFormat",
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
    "ReportArtifact",
''',
    label="final report public exports",
)

graph = Path("vulnhunter/assessment_graph/remediation.py")
replace_once(
    graph,
    '''_REVIEW_PREFIX = "Independent remediation review: "
''',
    '''_REVIEW_PREFIX = "Independent remediation review: "
_REPORT_PREFIX = "Final remediation report generated: "
''',
    label="report graph marker",
)
replace_once(
    graph,
    '''            "review_approved",
        }:
''',
    '''            "review_approved",
            "report_generated",
        }:
''',
    label="report-generated graph state",
)
replace_once(
    graph,
    '''    def _complete_attempt_stage(
''',
    '''    def project_report_generation(
        self,
        remediation_id: str,
        *,
        report_id: str,
        manifest_id: str,
    ) -> bool:
        """Complete only the report stage for one immutable unreleased manifest."""

        graph = self.core._load_optional(remediation_id)
        if graph is None:
            return False
        report = self.core._stage_node(graph, AssessmentStage.REPORT)
        marker = f"{_REPORT_PREFIX}report={report_id}; manifest={manifest_id}"
        if report.status == NodeStatus.COMPLETED:
            if report.last_error == marker:
                return True
            raise AssessmentGraphError("report stage already contains a different final report")
        if report.status != NodeStatus.READY:
            raise AssessmentGraphError("final report stage is not ready for generation")
        graph = self.core._transition(
            graph,
            node_id=report.node_id,
            status=NodeStatus.RUNNING,
            last_error=None,
        )
        report = self.core._stage_node(graph, AssessmentStage.REPORT)
        self.core._transition(
            graph,
            node_id=report.node_id,
            status=NodeStatus.COMPLETED,
            last_error=marker,
        )
        return True

    def _complete_attempt_stage(
''',
    label="report graph projection",
)
replace_once(
    graph,
    '''        review_error = (
            str(review_node.get("last_error") or "") if isinstance(review_node, dict) else ""
        )
        if review == NodeStatus.COMPLETED.value and report == NodeStatus.READY.value:
''',
    '''        review_error = (
            str(review_node.get("last_error") or "") if isinstance(review_node, dict) else ""
        )
        report_error = (
            str(report_node.get("last_error") or "") if isinstance(report_node, dict) else ""
        )
        if report == NodeStatus.COMPLETED.value and report_error.startswith(_REPORT_PREFIX):
            payload["chat_stage"] = "final_report_generated_awaiting_release"
            payload["report_state"] = "generated_unreleased"
        elif review == NodeStatus.COMPLETED.value and report == NodeStatus.READY.value:
''',
    label="report graph status payload",
)
replace_once(
    graph,
    '''        elif normalized == "review_approved":
            for stage in (
                AssessmentStage.EXECUTION,
                AssessmentStage.EVIDENCE,
                AssessmentStage.VERIFICATION,
                AssessmentStage.REVIEW,
            ):
                statuses[stage] = NodeStatus.COMPLETED
            statuses[AssessmentStage.REPORT] = NodeStatus.READY
        elif normalized == "cancelled":
''',
    '''        elif normalized == "review_approved":
            for stage in (
                AssessmentStage.EXECUTION,
                AssessmentStage.EVIDENCE,
                AssessmentStage.VERIFICATION,
                AssessmentStage.REVIEW,
            ):
                statuses[stage] = NodeStatus.COMPLETED
            statuses[AssessmentStage.REPORT] = NodeStatus.READY
        elif normalized == "report_generated":
            for stage in (
                AssessmentStage.EXECUTION,
                AssessmentStage.EVIDENCE,
                AssessmentStage.VERIFICATION,
                AssessmentStage.REVIEW,
                AssessmentStage.REPORT,
            ):
                statuses[stage] = NodeStatus.COMPLETED
        elif normalized == "cancelled":
''',
    label="report-generated initial graph",
)

web_graph = Path("vulnhunter/web/remediation_assessment_graph.py")
replace_once(
    web_graph,
    '''    if remediation.review_history:
        latest_review = remediation.review_history[-1]
        service.project_review_decision(
            remediation.remediation_id,
            receipt_id=latest_review.receipt_id,
            outcome=latest_review.outcome.value,
        )
    return service.status_payload(remediation.remediation_id)
''',
    '''    if remediation.review_history:
        latest_review = remediation.review_history[-1]
        service.project_review_decision(
            remediation.remediation_id,
            receipt_id=latest_review.receipt_id,
            outcome=latest_review.outcome.value,
        )
    if remediation.report_history:
        latest_report = remediation.report_history[-1]
        service.project_report_generation(
            remediation.remediation_id,
            report_id=latest_report.report_id,
            manifest_id=latest_report.manifest_id,
        )
    return service.status_payload(remediation.remediation_id)
''',
    label="final report web graph projection",
)
