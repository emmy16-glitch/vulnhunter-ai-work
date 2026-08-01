from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

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
    PublicationStore,
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
from vulnhunter.web.publication_service import PublicationRuntimeConfig

URL = "/findings/finding-01/remediation/report/publication/"
SECRETS = {
    "release-requester": "release-requester-secret",
    "release-approver": "release-approver-secret",
    "release-publisher": "release-publisher-secret",
    "release-revoker": "release-revoker-secret",
}


def _report_bundle(*, marker: str) -> tuple[FinalReportBundle, dict]:
    generated_at = datetime.now(UTC)
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
            format=artifact_format,
            filename=f"{report.report_id}.{artifact_format.value}",
            content_type=content_types[artifact_format],
            sha256=hashlib.sha256(data).hexdigest(),
            size_bytes=len(data),
        )
        for artifact_format, data in raw.items()
    )
    manifest = FinalReportManifest.create(
        report=report,
        artifacts=artifacts,
        provenance=("fix-verification-01", "retest-receipt-01", "review-receipt-01"),
        pdf_renderer=None,
    )
    return FinalReportBundle(report=report, manifest=manifest), raw


def _report_reference(bundle: FinalReportBundle):
    return SimpleNamespace(
        report_id=bundle.report.report_id,
        manifest_id=bundle.manifest.manifest_id,
        report_sha256=bundle.report.fingerprint(),
        manifest_sha256=bundle.manifest.fingerprint(),
        generator_id=bundle.report.generated_by,
        generator_identity_sha256=bundle.report.generator_identity_sha256,
        fixed_revision=bundle.report.verification.fixed_revision,
        review_receipt_id=bundle.report.review.receipt_id,
        formats=tuple(item.format.value for item in bundle.manifest.artifacts),
        created_at=bundle.report.generated_at,
    )


def _finding(bundle: FinalReportBundle):
    return SimpleNamespace(
        finding_id="finding-01",
        status=SimpleNamespace(value="report_generated"),
        revision=9,
        remediation=SimpleNamespace(report_history=(_report_reference(bundle),)),
    )


def _actor_from_request(request):
    return SimpleNamespace(
        governance_identity=SimpleNamespace(
            reviewer_id=request.user.username,
            roles=("campaign_admin",),
        )
    )


def _create_user(client, username: str):
    from django.contrib.auth import get_user_model

    user = get_user_model().objects.create_user(
        username=username,
        password="browser-password",
    )
    client.force_login(user)
    return user


def _service_world(tmp_path: Path):
    governance_store = make_governance_store(tmp_path)
    prepare_identities(governance_store)
    for actor_id, secret in SECRETS.items():
        add_identity(governance_store, actor_id, secret, ("campaign_admin",))

    report_store = FinalReportStore(
        tmp_path / "final-reports",
        signing_key=b"final-report-browser-acceptance-signing-key",
    )
    first_bundle, first_raw = _report_bundle(marker="v1")
    report_store.save(first_bundle, artifacts=first_raw)

    publication_store = PublicationStore(
        tmp_path / "publication-state",
        signing_key=b"publication-browser-acceptance-signing-key",
    )
    destination_root = tmp_path / "owner-private-published-path"
    destination = PublicationDestinationConfig(
        destination_id="owner-release-vault",
        label="Owner-controlled local release vault",
        root=destination_root,
        allowed_formats=(FinalReportFormat.JSON, FinalReportFormat.HTML),
    )
    authorities = frozenset(SECRETS)
    runtime = PublicationRuntimeConfig(
        destinations=(destination,),
        release_authority_ids=authorities,
    )
    service = PublicationService(
        report_store=report_store,
        governance_store=governance_store,
        publication_store=publication_store,
        destinations=(destination,),
        release_authority_ids=authorities,
    )
    state = SimpleNamespace(finding=_finding(first_bundle))
    finding_store = SimpleNamespace(get=lambda finding_id: state.finding)
    return SimpleNamespace(
        report_store=report_store,
        publication_store=publication_store,
        destination_root=destination_root,
        runtime=runtime,
        service=service,
        state=state,
        finding_store=finding_store,
        first_bundle=first_bundle,
    )


def _patch_world(world):
    return patch.multiple(
        "vulnhunter.web.remediation_publication_views",
        _publication_reader=_actor_from_request,
        _publication_actor=_actor_from_request,
        _project_workspace=Mock(),
        remediation_finding_store=Mock(return_value=world.finding_store),
        publication_runtime_config=Mock(return_value=world.runtime),
        publication_store=Mock(return_value=world.publication_store),
        final_report_store=Mock(return_value=world.report_store),
        publication_service=Mock(return_value=world.service),
    )


def _login(client, users, actor_id: str) -> None:
    client.force_login(users[actor_id])


@pytest.mark.django_db
def test_browser_service_release_correction_and_revocation_are_append_only(
    client,
    tmp_path,
):
    world = _service_world(tmp_path)
    users = {actor_id: _create_user(client, actor_id) for actor_id in SECRETS}

    with _patch_world(world):
        _login(client, users, "release-requester")
        response = client.post(
            URL,
            {
                "action": "request",
                "requester_id": "forged-requester",
                "destination_id": "owner-release-vault",
                "formats": ["json", "html"],
                "reason": "Release the exact independently reviewed report.",
                "expires_in_hours": "24",
                "governance_secret": SECRETS["release-requester"],
            },
        )
        assert response.status_code == 302
        first_request = world.publication_store.list_requests_for_finding("finding-01")[-1]
        assert first_request.requester_id == "release-requester"

        _login(client, users, "release-approver")
        response = client.post(
            URL,
            {
                "action": "approve",
                "approver_id": "forged-approver",
                "request_id": first_request.request_id,
                "governance_secret": SECRETS["release-approver"],
            },
        )
        assert response.status_code == 302
        first_approval = world.publication_store.latest_approval_for_request(
            first_request.request_id
        )
        assert first_approval is not None
        assert first_approval.approver_id == "release-approver"

        _login(client, users, "release-publisher")
        response = client.post(
            URL,
            {
                "action": "publish",
                "publisher_id": "forged-publisher",
                "request_id": first_request.request_id,
                "approval_id": first_approval.approval_id,
                "governance_secret": SECRETS["release-publisher"],
            },
        )
        assert response.status_code == 302
        first_publication = world.publication_store.publication_for_request(
            first_request.request_id
        )
        assert first_publication is not None
        assert first_publication.publisher_id == "release-publisher"
        assert world.publication_store.status(first_publication.publication_id) == "published"
        first_directory = world.destination_root / first_publication.publication_id
        first_artifact_paths = [
            first_directory / item.published_filename for item in first_publication.artifacts
        ]
        assert all(path.is_file() for path in first_artifact_paths)

        second_bundle, second_raw = _report_bundle(marker="v2")
        world.report_store.save(second_bundle, artifacts=second_raw)
        world.state.finding = _finding(second_bundle)

        _login(client, users, "release-requester")
        response = client.post(
            URL,
            {
                "action": "request",
                "requester_id": "forged-requester",
                "destination_id": "owner-release-vault",
                "formats": ["json", "html"],
                "reason": "Publish the new signed report as the correction.",
                "expires_in_hours": "24",
                "correction_of_publication_id": first_publication.publication_id,
                "confirm_correction": "true",
                "governance_secret": SECRETS["release-requester"],
            },
        )
        assert response.status_code == 302
        correction_request = world.publication_store.list_requests_for_finding(
            "finding-01"
        )[-1]
        assert (
            correction_request.correction_of_publication_id
            == first_publication.publication_id
        )

        _login(client, users, "release-approver")
        response = client.post(
            URL,
            {
                "action": "approve",
                "request_id": correction_request.request_id,
                "governance_secret": SECRETS["release-approver"],
            },
        )
        assert response.status_code == 302
        correction_approval = world.publication_store.latest_approval_for_request(
            correction_request.request_id
        )
        assert correction_approval is not None

        _login(client, users, "release-publisher")
        response = client.post(
            URL,
            {
                "action": "publish",
                "request_id": correction_request.request_id,
                "approval_id": correction_approval.approval_id,
                "governance_secret": SECRETS["release-publisher"],
            },
        )
        assert response.status_code == 302
        replacement = world.publication_store.publication_for_request(
            correction_request.request_id
        )
        assert replacement is not None
        assert world.publication_store.status(first_publication.publication_id) == "superseded"
        correction = world.publication_store.correction_for_publication(
            first_publication.publication_id
        )
        assert correction is not None
        assert correction.replacement_publication_id == replacement.publication_id
        assert (first_directory / "correction.json").is_file()
        assert all(path.is_file() for path in first_artifact_paths)

        _login(client, users, "release-revoker")
        response = client.post(
            URL,
            {
                "action": "revoke",
                "authority_id": "release-publisher",
                "publication_id": replacement.publication_id,
                "reason": "A later governance review invalidated the release claim.",
                "confirm_revocation": "true",
                "governance_secret": SECRETS["release-revoker"],
            },
        )
        assert response.status_code == 302
        assert world.publication_store.status(replacement.publication_id) == "revoked"
        revocation = world.publication_store.revocation_for_publication(
            replacement.publication_id
        )
        assert revocation is not None
        assert revocation.authority_id == "release-revoker"
        replacement_directory = world.destination_root / replacement.publication_id
        assert (replacement_directory / "revocation.json").is_file()
        assert all(
            (replacement_directory / item.published_filename).is_file()
            for item in replacement.artifacts
        )

        response = client.get(URL)
        assert response.status_code == 200
        content = response.content.decode()
        assert "SUPERSEDED" in content
        assert "REVOKED" in content
        assert correction.correction_id in content
        assert revocation.revocation_id in content
        assert first_publication.publication_id in content
        assert replacement.publication_id in content
        assert "owner-private-published-path" not in content
