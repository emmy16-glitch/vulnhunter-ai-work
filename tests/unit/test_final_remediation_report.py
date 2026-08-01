from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from governance_test_support import add_identity, make_governance_store, prepare_identities

from vulnhunter.findings import (
    EvidenceReference,
    Finding,
    FindingConflict,
    FindingSeverity,
    FindingStatus,
    FindingStore,
    RemediationRecord,
    RemediationReviewOutcome,
    RemediationReviewReference,
    RemediationState,
    RemediationVerificationReference,
    RetestOutcome,
    RetestPlanRecord,
    RetestReceiptReference,
    VerificationState,
)
from vulnhunter.reports import (
    BuiltInPdfRenderer,
    FinalRemediationReportError,
    FinalRemediationReportService,
    FinalReportStore,
    PdfRendererReadiness,
)

NOW = datetime(2026, 8, 1, 9, 30, tzinfo=UTC)
REPORT_WRITER_SECRET = "report-writer-secret-123"


class _ReceiptStore:
    def __init__(self, bundle):
        self.bundle = bundle

    def load(self, receipt_id: str):
        assert receipt_id == self.bundle.receipt_id
        return self.bundle


def _evidence(evidence_id: str, character: str, provenance: str) -> EvidenceReference:
    return EvidenceReference(
        evidence_id=evidence_id,
        sha256=character * 64,
        provenance=provenance,
        content_type="application/json",
    )


def _world(tmp_path: Path, *, finding_status=FindingStatus.READY_FOR_REPORT):
    finding_store = FindingStore(tmp_path / "findings.sqlite3")
    governance_store = make_governance_store(tmp_path)
    prepare_identities(governance_store)
    add_identity(
        governance_store,
        "report-writer",
        REPORT_WRITER_SECRET,
        ("campaign_admin",),
    )

    original = _evidence(
        "evidence-original",
        "a",
        "independently reviewed original evidence",
    )
    fix = RemediationVerificationReference(
        receipt_id="fix-verification-" + "b" * 24,
        sha256="c" * 64,
        verdict="fixed",
        original_revision="1" * 40,
        fixed_revision="2" * 40,
        created_at=NOW - timedelta(minutes=30),
    )
    retest_plan = RetestPlanRecord.create(
        finding_id="finding-01",
        finding_revision=2,
        finding_fingerprint="d" * 64,
        remediation_id="remediation-" + "e" * 32,
        fix_verification_receipt_id=fix.receipt_id,
        fixed_revision=fix.fixed_revision,
        owner_id="retest-operator",
        check_references=("Run the exact cross-user ownership check.",),
        before_evidence_ids=(original.evidence_id,),
        created_at=NOW - timedelta(minutes=25),
        expires_at=NOW + timedelta(days=1),
    )
    retest = RetestReceiptReference(
        receipt_id="retest-receipt-" + "f" * 24,
        retest_id=retest_plan.retest_id,
        sha256="1" * 64,
        outcome=RetestOutcome.PASSED,
        fixed_revision=fix.fixed_revision,
        created_at=NOW - timedelta(minutes=20),
    )
    review = RemediationReviewReference(
        receipt_id="remediation-review-" + "2" * 24,
        review_id="review-" + "3" * 32,
        sha256="4" * 64,
        outcome=RemediationReviewOutcome.APPROVED,
        reviewer_id="reviewer-a",
        reviewer_identity_sha256="5" * 64,
        fixed_revision=fix.fixed_revision,
        retest_receipt_id=retest.receipt_id,
        created_at=NOW - timedelta(minutes=10),
    )
    remediation = RemediationRecord(
        summary="Enforce object ownership before returning the selected user record.",
        owner_id="developer-owner",
        references=(original.evidence_id,),
        remediation_id=retest_plan.remediation_id,
        state=RemediationState.REVIEW_APPROVED,
        source_finding_revision=0,
        source_finding_fingerprint="d" * 64,
        plan_sha256="6" * 64,
        target_references=("app/users.py",),
        regression_test="A cross-user request must be rejected.",
        verification_recipe="Run the exact cross-user check and regression suite.",
        compatibility_risks=("Existing callers may rely on permissive object lookup.",),
        verification_history=(fix,),
        retest_history=(retest,),
        review_history=(review,),
        created_at=NOW - timedelta(hours=1),
        expires_at=NOW + timedelta(days=7),
    )
    finding = Finding(
        finding_id="finding-01",
        campaign_id="campaign-01",
        fingerprint="d" * 64,
        title="IDOR in user lookup",
        description=(
            "A selected user record may be returned without ownership checks. "
            "Authorization: Bearer test-token must never appear in exports."
        ),
        severity=FindingSeverity.HIGH,
        confidence=90,
        verification=VerificationState.VERIFIED,
        status=finding_status,
        affected_asset="repo-01",
        affected_component="app/users.py",
        evidence=(
            original,
            _evidence(fix.receipt_id, "c", "immutable fix verification"),
            _evidence(retest.receipt_id, "1", "immutable passed retest"),
            _evidence(review.receipt_id, "4", "immutable signed independent review"),
        ),
        remediation=remediation,
        retest_plans=(retest_plan,),
        retest_results=(retest,),
        revision=0,
        created_at=NOW - timedelta(hours=2),
        updated_at=review.created_at,
    )
    finding_store.create(finding)

    fix_bundle = SimpleNamespace(
        receipt_id=fix.receipt_id,
        builder_id="implementation-builder",
        verifier_id="read-only-fix-verifier",
        fixed_snapshot=SimpleNamespace(revision=fix.fixed_revision),
        fingerprint=lambda: fix.sha256,
    )
    retest_bundle = SimpleNamespace(
        receipt_id=retest.receipt_id,
        outcome=RetestOutcome.PASSED,
        plan=SimpleNamespace(owner_id=retest_plan.owner_id, fixed_revision=fix.fixed_revision),
        fingerprint=lambda: retest.sha256,
    )
    review_bundle = SimpleNamespace(
        receipt_id=review.receipt_id,
        outcome=RemediationReviewOutcome.APPROVED,
        rationale="The exact fixed revision and passed retest support the remediation claim.",
        limitations=("Final release and publication remain separate.",),
        plan=SimpleNamespace(
            reviewer_id=review.reviewer_id,
            reviewer_identity_sha256=review.reviewer_identity_sha256,
            fixed_revision=fix.fixed_revision,
            retest_receipt_id=retest.receipt_id,
            fix_verification_receipt_id=fix.receipt_id,
        ),
        fingerprint=lambda: review.sha256,
    )
    report_store = FinalReportStore(
        tmp_path / "final-reports",
        signing_key=b"test-final-report-signing-key-material",
    )
    service = FinalRemediationReportService(
        finding_store=finding_store,
        governance_store=governance_store,
        fix_verification_store=_ReceiptStore(fix_bundle),
        retest_receipt_store=_ReceiptStore(retest_bundle),
        review_receipt_store=_ReceiptStore(review_bundle),
        report_store=report_store,
        pdf_renderer=BuiltInPdfRenderer(
            PdfRendererReadiness(
                enabled=True,
                renderer_id="builtin-minimal-pdf",
                renderer_version="1.0",
                renderer_sha256="7" * 64,
            )
        ),
        clock=lambda: NOW,
    )
    return finding_store, finding, service, report_store


def test_generate_final_report_signs_unreleased_manifest_and_does_not_close(tmp_path):
    finding_store, finding, service, report_store = _world(tmp_path)

    updated, bundle = service.generate(
        finding_id=finding.finding_id,
        expected_revision=finding.revision,
        generator_id="report-writer",
        generator_secret=REPORT_WRITER_SECRET,
        limitations=("Publication requires a separate release authority.",),
        include_pdf=False,
    )

    assert updated.status == FindingStatus.REPORT_GENERATED
    assert updated.status not in {FindingStatus.REMEDIATED, FindingStatus.CLOSED}
    assert updated.remediation is not None
    assert updated.remediation.state == RemediationState.REPORT_GENERATED
    assert bundle.manifest.release_state == "unreleased"
    assert {item.format.value for item in bundle.manifest.artifacts} == {"json", "html"}
    assert report_store.load(bundle.report.report_id) == bundle
    assert finding_store.get(finding.finding_id) == updated

    exported_json = json.loads(report_store.artifact_path(bundle.report.report_id, "json").read_text())
    serialized = json.dumps(exported_json)
    assert "test-token" not in serialized
    assert bundle.report.review.outcome == RemediationReviewOutcome.APPROVED
    assert bundle.report.retest.outcome == RetestOutcome.PASSED
    assert bundle.report.release_state == "unreleased"


def test_pdf_is_generated_only_when_readiness_is_enabled_and_requested(tmp_path):
    _store, finding, service, report_store = _world(tmp_path)

    _updated, bundle = service.generate(
        finding_id=finding.finding_id,
        expected_revision=finding.revision,
        generator_id="report-writer",
        generator_secret=REPORT_WRITER_SECRET,
        include_pdf=True,
    )

    assert {item.format.value for item in bundle.manifest.artifacts} == {"json", "html", "pdf"}
    pdf = report_store.artifact_path(bundle.report.report_id, "pdf").read_bytes()
    assert pdf.startswith(b"%PDF-1.4")
    assert b"%%EOF" in pdf


def test_wrong_generator_secret_fails_without_persisting_artifacts(tmp_path):
    store, finding, service, report_store = _world(tmp_path)

    with pytest.raises(FinalRemediationReportError, match="authentication"):
        service.generate(
            finding_id=finding.finding_id,
            expected_revision=finding.revision,
            generator_id="report-writer",
            generator_secret="wrong-secret",
        )

    assert store.get(finding.finding_id) == finding
    assert tuple(report_store.root.iterdir()) == ()


def test_report_writer_must_be_separate_from_remediation_actors(tmp_path):
    _store, finding, service, report_store = _world(tmp_path)

    with pytest.raises(FinalRemediationReportError, match="remediation owner"):
        service.generate(
            finding_id=finding.finding_id,
            expected_revision=finding.revision,
            generator_id="developer-owner",
            generator_secret="unused",
        )

    assert tuple(report_store.root.iterdir()) == ()


def test_report_generation_requires_ready_for_report_state(tmp_path):
    _store, finding, service, report_store = _world(
        tmp_path,
        finding_status=FindingStatus.AWAITING_REMEDIATION_REVIEW,
    )

    with pytest.raises(FinalRemediationReportError, match="approved remediation review"):
        service.generate(
            finding_id=finding.finding_id,
            expected_revision=finding.revision,
            generator_id="report-writer",
            generator_secret=REPORT_WRITER_SECRET,
        )

    assert tuple(report_store.root.iterdir()) == ()


def test_stale_finding_revision_removes_new_report_directory(tmp_path):
    _store, finding, service, report_store = _world(tmp_path)

    with pytest.raises(FindingConflict):
        service.generate(
            finding_id=finding.finding_id,
            expected_revision=finding.revision + 1,
            generator_id="report-writer",
            generator_secret=REPORT_WRITER_SECRET,
        )

    assert tuple(report_store.root.iterdir()) == ()


def test_tampered_signed_manifest_is_rejected(tmp_path):
    _store, finding, service, report_store = _world(tmp_path)
    _updated, bundle = service.generate(
        finding_id=finding.finding_id,
        expected_revision=finding.revision,
        generator_id="report-writer",
        generator_secret=REPORT_WRITER_SECRET,
    )
    manifest_path = report_store.root / bundle.report.report_id / "manifest.json"
    manifest_path.write_text(
        manifest_path.read_text(encoding="utf-8").replace("unreleased", "published", 1),
        encoding="utf-8",
    )

    with pytest.raises(FinalRemediationReportError, match="signature|integrity"):
        report_store.load(bundle.report.report_id)
