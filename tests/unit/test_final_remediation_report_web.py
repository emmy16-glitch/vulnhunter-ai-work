from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from governance_test_support import add_identity, make_governance_store, prepare_identities

from vulnhunter.findings import (
    EvidenceReference,
    Finding,
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
from vulnhunter.reports import FinalRemediationReportService, FinalReportStore
from vulnhunter.web.remediation_assessment_graph import bind_remediation_assessment_graph
from vulnhunter.web.remediation_conversation_state import remember_remediation_workspace

NOW = datetime(2026, 8, 1, 10, 0, tzinfo=UTC)
REPORT_WRITER_SECRET = "report-writer-secret-123"


class _ReceiptStore:
    def __init__(self, bundle):
        self.bundle = bundle

    def load(self, receipt_id: str):
        assert receipt_id == self.bundle.receipt_id
        return self.bundle


def _configure(settings, tmp_path: Path) -> None:
    settings.PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
    settings.ALLOWED_HOSTS = ["testserver", "localhost", "127.0.0.1"]
    settings.VULNHUNTER_FINDING_DATABASE = tmp_path / "findings.sqlite3"
    settings.VULNHUNTER_GOVERNANCE_DATABASE = str(tmp_path / "governance.db")
    settings.VULNHUNTER_TASK_GRAPH_ROOT = tmp_path / "graphs"
    settings.VULNHUNTER_FINAL_REPORT_ROOT = tmp_path / "final-reports"
    settings.VULNHUNTER_FINAL_REPORT_PDF_ENABLED = False


def _evidence(evidence_id: str, character: str, provenance: str) -> EvidenceReference:
    return EvidenceReference(
        evidence_id=evidence_id,
        sha256=character * 64,
        provenance=provenance,
        content_type="application/json",
    )


def _world(tmp_path: Path, settings):
    store = FindingStore(Path(settings.VULNHUNTER_FINDING_DATABASE))
    governance = make_governance_store(tmp_path)
    prepare_identities(governance)
    add_identity(
        governance,
        "report-writer",
        REPORT_WRITER_SECRET,
        ("campaign_admin",),
    )
    original = _evidence("evidence-original", "a", "reviewed original evidence")
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
        title="IDOR",
        description="User lookup may expose another user's record without ownership checks.",
        severity=FindingSeverity.HIGH,
        confidence=90,
        verification=VerificationState.VERIFIED,
        status=FindingStatus.READY_FOR_REPORT,
        affected_asset="repo-01",
        affected_component="app/users.py",
        evidence=(
            original,
            _evidence(fix.receipt_id, "c", "immutable fix verification"),
            _evidence(retest.receipt_id, "1", "immutable passed retest"),
            _evidence(review.receipt_id, "4", "immutable approved review"),
        ),
        remediation=remediation,
        retest_plans=(retest_plan,),
        retest_results=(retest,),
        revision=0,
        created_at=NOW - timedelta(hours=2),
        updated_at=review.created_at,
    )
    store.create(finding)
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
        limitations=("Release remains separate.",),
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
        Path(settings.VULNHUNTER_FINAL_REPORT_ROOT),
        signing_key=b"test-final-report-signing-key-material",
    )
    service = FinalRemediationReportService(
        finding_store=store,
        governance_store=governance,
        fix_verification_store=_ReceiptStore(fix_bundle),
        retest_receipt_store=_ReceiptStore(retest_bundle),
        review_receipt_store=_ReceiptStore(review_bundle),
        report_store=report_store,
        clock=lambda: NOW,
    )
    return store, finding, service, report_store


def _create_report_writer_user():
    from django.contrib.auth import get_user_model

    from vulnhunter.web.models import WebUserMapping

    user = get_user_model().objects.create_user(
        username="report-writer-web",
        password="password-1234",
    )
    WebUserMapping.objects.create(
        user=user,
        governance_identity_id="report-writer",
        product_roles=["security-auditor"],
    )
    return user


@pytest.mark.django_db
def test_chat_opens_protected_report_without_consuming_secret(client, tmp_path, settings):
    from vulnhunter.web.models import ConversationThread

    _configure(settings, tmp_path)
    user = _create_report_writer_user()
    thread = ConversationThread.objects.create(owner=user, title="Generate final report")
    store, finding, _service, _report_store = _world(tmp_path, settings)
    graph = bind_remediation_assessment_graph(finding, workspace_id=str(thread.thread_id))
    remember_remediation_workspace(
        owner=user,
        workspace_id=str(thread.thread_id),
        finding=finding,
        graph=graph,
    )
    client.force_login(user)

    response = client.post(
        "/workspace/remediation-final-report/",
        {
            "thread_id": str(thread.thread_id),
            "message": "Generate final remediation report",
            "governance_secret": "must-not-be-consumed",
            "include_pdf": "true",
        },
        HTTP_X_VULNHUNTER_THREAD=str(thread.thread_id),
        HTTP_ACCEPT="application/json",
    )

    assert response.status_code == 200
    assert response.json()["redirect_url"] == (
        f"/findings/finding-01/remediation/report/?thread={thread.thread_id}"
    )
    assert store.get(finding.finding_id) == finding


@pytest.mark.django_db
def test_protected_report_generation_updates_graph_thread_and_downloads(
    client,
    tmp_path,
    settings,
):
    from vulnhunter.web.models import ConversationThread

    _configure(settings, tmp_path)
    user = _create_report_writer_user()
    thread = ConversationThread.objects.create(owner=user, title="Generate final report")
    store, finding, service, report_store = _world(tmp_path, settings)
    graph = bind_remediation_assessment_graph(finding, workspace_id=str(thread.thread_id))
    remember_remediation_workspace(
        owner=user,
        workspace_id=str(thread.thread_id),
        finding=finding,
        graph=graph,
    )
    client.force_login(user)

    with (
        patch(
            "vulnhunter.web.remediation_final_report_views.final_report_service",
            return_value=service,
        ),
        patch(
            "vulnhunter.web.remediation_final_report_views.final_report_store",
            return_value=report_store,
        ),
    ):
        response = client.post(
            f"/findings/finding-01/remediation/report/?thread={thread.thread_id}",
            {
                "thread_id": str(thread.thread_id),
                "expected_revision": str(finding.revision),
                "limitations": "Publication remains separate.",
                "governance_secret": REPORT_WRITER_SECRET,
            },
        )

    assert response.status_code == 302
    updated = store.get(finding.finding_id)
    assert updated.status == FindingStatus.REPORT_GENERATED
    assert updated.status not in {FindingStatus.REMEDIATED, FindingStatus.CLOSED}
    assert updated.remediation is not None
    latest = updated.remediation.report_history[-1]

    thread.refresh_from_db()
    state = thread.data["vulnhunter_conversation_remediation"]
    assert state["plan"]["latest_report"]["report_id"] == latest.report_id
    assert state["assessment_graph"]["chat_stage"] == "final_report_generated_awaiting_release"
    assert state["assessment_graph"]["report_state"] == "generated_unreleased"

    with patch(
        "vulnhunter.web.remediation_final_report_views.final_report_store",
        return_value=report_store,
    ):
        download = client.get(
            f"/findings/finding-01/remediation/report/download/json/?thread={thread.thread_id}"
        )
    assert download.status_code == 200
    assert download["X-VulnHunter-Artifact-SHA256"]
    assert download["X-VulnHunter-Manifest-SHA256"] == latest.manifest_sha256
    assert download["X-VulnHunter-Release-State"] == "unreleased"


@pytest.mark.django_db
def test_wrong_governance_secret_does_not_generate_report(client, tmp_path, settings):
    from vulnhunter.web.models import ConversationThread

    _configure(settings, tmp_path)
    user = _create_report_writer_user()
    thread = ConversationThread.objects.create(owner=user, title="Generate final report")
    store, finding, service, report_store = _world(tmp_path, settings)
    client.force_login(user)

    with (
        patch(
            "vulnhunter.web.remediation_final_report_views.final_report_service",
            return_value=service,
        ),
        patch(
            "vulnhunter.web.remediation_final_report_views.final_report_store",
            return_value=report_store,
        ),
    ):
        response = client.post(
            f"/findings/finding-01/remediation/report/?thread={thread.thread_id}",
            {
                "thread_id": str(thread.thread_id),
                "expected_revision": str(finding.revision),
                "governance_secret": "wrong-secret",
            },
        )

    assert response.status_code == 200
    assert b"authentication failed" in response.content.lower()
    assert store.get(finding.finding_id) == finding
    assert tuple(report_store.root.iterdir()) == ()
