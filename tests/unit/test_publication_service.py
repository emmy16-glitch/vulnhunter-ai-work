from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from governance_test_support import add_identity, make_governance_store, prepare_identities

from vulnhunter.findings import (
    FindingSeverity,
    FindingStatus,
    RemediationReviewOutcome,
    RetestOutcome,
    VerificationState,
)
from vulnhunter.publication import (
    PublicationDestinationConfig,
    PublicationService,
    PublicationServiceError,
    PublicationStore,
    PublicationStoreError,
)
from vulnhunter.reports import (
    FinalRemediationReport,
    FinalReportArtifactReference,
    FinalReportBundle,
    FinalReportEvidenceCitation,
    FinalReportFormat,
    FinalReportManifest,
    FinalReportStore,
)
from vulnhunter.reports.final_remediation import (
    FinalReportFindingSummary,
    FinalReportRemediationSummary,
    FinalReportRetestSummary,
    FinalReportReviewSummary,
    FinalReportVerificationSummary,
)

NOW = datetime(2026, 8, 1, 12, 0, tzinfo=UTC)
SECRETS = {
    "release-requester": "release-requester-secret",
    "release-approver": "release-approver-secret",
    "release-publisher": "release-publisher-secret",
    "release-revoker": "release-revoker-secret",
    "report-writer": "report-writer-secret",
    "ordinary-operator": "ordinary-operator-secret",
}


def _report_bundle(*, generated_at: datetime, marker: str) -> tuple[FinalReportBundle, dict]:
    report = FinalRemediationReport.create(
        source_finding_revision=7,
        finding=FinalReportFindingSummary(
            finding_id="finding-01",
            campaign_id="campaign-01",
            fingerprint="a" * 64,
            title=f"Corrected IDOR finding {marker}",
            description="A cross-user lookup returned another account.",
            severity=FindingSeverity.HIGH,
            confidence=95,
            verification=VerificationState.VERIFIED,
            status_at_generation=FindingStatus.READY_FOR_REPORT,
            affected_asset="repo-01",
            affected_component="app/users.py",
        ),
        remediation=FinalReportRemediationSummary(
            remediation_id="remediation-01",
            summary="Enforce object ownership before returning a user record.",
            owner_id="developer-owner",
            target_references=("app/users.py",),
            regression_test="Cross-user requests must be rejected.",
            verification_recipe="Run the ownership regression suite.",
            compatibility_risks=("Legacy callers may rely on permissive lookup.",),
        ),
        verification=FinalReportVerificationSummary(
            receipt_id="fix-verification-01",
            sha256="b" * 64,
            verdict="fixed",
            original_revision="1" * 40,
            fixed_revision="2" * 40,
            builder_id="implementation-builder",
            verifier_id="read-only-verifier",
        ),
        retest=FinalReportRetestSummary(
            receipt_id="retest-receipt-01",
            sha256="c" * 64,
            outcome=RetestOutcome.PASSED,
            retest_id="retest-01",
            operator_id="retest-operator",
            fixed_revision="2" * 40,
        ),
        review=FinalReportReviewSummary(
            receipt_id="review-receipt-01",
            sha256="d" * 64,
            outcome=RemediationReviewOutcome.APPROVED,
            reviewer_id="independent-reviewer",
            reviewer_identity_sha256="e" * 64,
            rationale="The fixed revision and passed retest support the remediation claim.",
            limitations=("Publication remains separately authorised.",),
            fixed_revision="2" * 40,
            retest_receipt_id="retest-receipt-01",
        ),
        evidence_citations=(
            FinalReportEvidenceCitation(
                evidence_id="evidence-01",
                sha256="f" * 64,
                provenance="independently reviewed evidence",
                content_type="application/json",
            ),
        ),
        limitations=("No production deployment claim is made.",),
        generated_by="report-writer",
        generator_identity_sha256="1" * 64,
        generated_at=generated_at,
    )
    raw = {
        FinalReportFormat.JSON: (f'{{"marker":"{marker}"}}\n').encode(),
        FinalReportFormat.HTML: f"<html><body>{marker}</body></html>\n".encode(),
    }
    content_types = {
        FinalReportFormat.JSON: "application/json",
        FinalReportFormat.HTML: "text/html; charset=utf-8",
    }
    artifacts = tuple(
        FinalReportArtifactReference(
            format=format,
            filename=f"{report.report_id}.{format.value}",
            content_type=content_types[format],
            sha256=hashlib.sha256(data).hexdigest(),
            size_bytes=len(data),
        )
        for format, data in raw.items()
    )
    manifest = FinalReportManifest.create(
        report=report,
        artifacts=artifacts,
        provenance=("fix-verification-01", "retest-receipt-01", "review-receipt-01"),
        pdf_renderer=None,
    )
    return FinalReportBundle(report=report, manifest=manifest), raw


def _world(tmp_path: Path):
    governance_store = make_governance_store(tmp_path)
    prepare_identities(governance_store)
    for actor_id, secret in SECRETS.items():
        add_identity(governance_store, actor_id, secret, ("campaign_admin",))

    report_store = FinalReportStore(
        tmp_path / "final-reports",
        signing_key=b"final-report-signing-key-material",
    )
    bundle, raw = _report_bundle(generated_at=NOW, marker="v1")
    report_store.save(bundle, artifacts=raw)

    publication_store = PublicationStore(
        tmp_path / "publication-state",
        signing_key=b"publication-signing-key-material",
    )
    destination_root = tmp_path / "published"
    service = PublicationService(
        report_store=report_store,
        governance_store=governance_store,
        publication_store=publication_store,
        destinations=(
            PublicationDestinationConfig(
                destination_id="owner-release-vault",
                label="Owner-controlled local release vault",
                root=destination_root,
                allowed_formats=(FinalReportFormat.JSON, FinalReportFormat.HTML),
            ),
        ),
        release_authority_ids=frozenset(
            {
                "release-requester",
                "release-approver",
                "release-publisher",
                "release-revoker",
                "report-writer",
            }
        ),
        clock=lambda: NOW,
    )
    return service, publication_store, report_store, destination_root, bundle


def _publish(service: PublicationService, report_id: str, *, correction_of=None):
    request = service.request_release(
        report_id=report_id,
        destination_id="owner-release-vault",
        formats=("json", "html"),
        requester_id="release-requester",
        requester_secret=SECRETS["release-requester"],
        reason="Release the independently reviewed remediation report.",
        expires_at=NOW + timedelta(hours=1),
        correction_of_publication_id=correction_of,
    )
    approval = service.approve_release(
        request_id=request.request_id,
        approver_id="release-approver",
        approver_secret=SECRETS["release-approver"],
    )
    publication = service.publish(
        request_id=request.request_id,
        approval_id=approval.approval_id,
        publisher_id="release-publisher",
        publisher_secret=SECRETS["release-publisher"],
    )
    return request, approval, publication


def test_separate_release_authority_publishes_exact_signed_artifacts(tmp_path):
    service, store, _report_store, destination_root, bundle = _world(tmp_path)

    request, approval, publication = _publish(service, bundle.report.report_id)

    assert request.requester_id == "release-requester"
    assert approval.approver_id == "release-approver"
    assert publication.publisher_id == "release-publisher"
    assert publication.release_state == "published"
    assert bundle.report.release_state == "unreleased"
    assert store.load_publication(publication.publication_id) == publication
    assert service.status(publication.publication_id) == "published"

    published = destination_root / publication.publication_id
    assert (published / "publication-manifest.json").is_file()
    for artifact in publication.artifacts:
        path = published / artifact.published_filename
        assert path.is_file()
        assert hashlib.sha256(path.read_bytes()).hexdigest() == artifact.sha256


def test_prior_actor_self_approval_and_dual_role_publication_are_blocked(tmp_path):
    service, _store, _report_store, _destination, bundle = _world(tmp_path)

    with pytest.raises(PublicationServiceError, match="not configured"):
        service.request_release(
            report_id=bundle.report.report_id,
            destination_id="owner-release-vault",
            formats=("json",),
            requester_id="ordinary-operator",
            requester_secret=SECRETS["ordinary-operator"],
            reason="Attempt release without dedicated publication authority.",
            expires_at=NOW + timedelta(hours=1),
        )

    with pytest.raises(PublicationServiceError, match="prior remediation/report actor"):
        service.request_release(
            report_id=bundle.report.report_id,
            destination_id="owner-release-vault",
            formats=("json",),
            requester_id="report-writer",
            requester_secret=SECRETS["report-writer"],
            reason="Attempt an invalid release request.",
            expires_at=NOW + timedelta(hours=1),
        )

    request = service.request_release(
        report_id=bundle.report.report_id,
        destination_id="owner-release-vault",
        formats=("json",),
        requester_id="release-requester",
        requester_secret=SECRETS["release-requester"],
        reason="Request a separately approved release.",
        expires_at=NOW + timedelta(hours=1),
    )
    with pytest.raises(PublicationServiceError, match="cannot approve"):
        service.approve_release(
            request_id=request.request_id,
            approver_id="release-requester",
            approver_secret=SECRETS["release-requester"],
        )

    approval = service.approve_release(
        request_id=request.request_id,
        approver_id="release-approver",
        approver_secret=SECRETS["release-approver"],
    )
    with pytest.raises(PublicationServiceError, match="differ"):
        service.publish(
            request_id=request.request_id,
            approval_id=approval.approval_id,
            publisher_id="release-approver",
            publisher_secret=SECRETS["release-approver"],
        )


def test_correction_supersedes_without_deleting_and_revocation_preserves_artifacts(tmp_path):
    service, store, report_store, destination_root, first_bundle = _world(tmp_path)
    _request, _approval, first = _publish(service, first_bundle.report.report_id)

    second_bundle, second_raw = _report_bundle(
        generated_at=NOW,
        marker="v2",
    )
    report_store.save(second_bundle, artifacts=second_raw)
    _request2, _approval2, second = _publish(
        service,
        second_bundle.report.report_id,
        correction_of=first.publication_id,
    )

    assert service.status(first.publication_id) == "superseded"
    correction = store.load_correction(first.publication_id)
    assert correction.replacement_publication_id == second.publication_id
    assert (destination_root / first.publication_id).is_dir()
    assert (destination_root / first.publication_id / "correction.json").is_file()

    revocation = service.revoke(
        publication_id=second.publication_id,
        authority_id="release-revoker",
        authority_secret=SECRETS["release-revoker"],
        reason="A later review found the release destination metadata was incomplete.",
    )
    assert revocation.release_state == "revoked"
    assert service.status(second.publication_id) == "revoked"
    assert (destination_root / second.publication_id).is_dir()
    assert (destination_root / second.publication_id / "revocation.json").is_file()


def test_signed_publication_record_tampering_fails_closed(tmp_path):
    service, store, _report_store, _destination_root, bundle = _world(tmp_path)
    _request, _approval, publication = _publish(service, bundle.report.report_id)
    path = store.root / "publications" / f"{publication.publication_id}.json"
    path.write_text(path.read_text().replace('"published"', '"revoked"', 1))

    with pytest.raises(PublicationStoreError, match="signature"):
        store.load_publication(publication.publication_id)
