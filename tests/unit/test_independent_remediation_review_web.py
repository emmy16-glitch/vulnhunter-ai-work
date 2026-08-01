from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from governance_test_support import (
    REVIEWER_ONE_SECRET,
    make_governance_store,
    prepare_identities,
)

from vulnhunter.findings import (
    EvidenceReference,
    Finding,
    FindingSeverity,
    FindingStatus,
    FindingStore,
    RemediationRecord,
    RemediationReviewReceiptStore,
    RemediationReviewService,
    RemediationState,
    RemediationVerificationReference,
    RetestOutcome,
    RetestPlanRecord,
    RetestReceiptReference,
    VerificationState,
)
from vulnhunter.web.remediation_assessment_graph import bind_remediation_assessment_graph
from vulnhunter.web.remediation_conversation_state import remember_remediation_workspace

NOW = datetime(2026, 8, 1, 7, 30, tzinfo=UTC)


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
    settings.VULNHUNTER_REMEDIATION_REVIEW_ROOT = tmp_path / "review-receipts"
    settings.SECRET_KEY = "test-review-signing-key-that-is-long-enough"


def _evidence(evidence_id: str, character: str, provenance: str) -> EvidenceReference:
    return EvidenceReference(
        evidence_id=evidence_id,
        sha256=character * 64,
        provenance=provenance,
        content_type="application/json",
    )


def _review_world(tmp_path: Path, settings):
    store = FindingStore(Path(settings.VULNHUNTER_FINDING_DATABASE))
    governance = make_governance_store(tmp_path)
    prepare_identities(governance)
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
        created_at=NOW - timedelta(minutes=20),
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
        created_at=NOW - timedelta(minutes=15),
        expires_at=NOW + timedelta(days=1),
    )
    retest = RetestReceiptReference(
        receipt_id="retest-receipt-" + "f" * 24,
        retest_id=retest_plan.retest_id,
        sha256="1" * 64,
        outcome=RetestOutcome.PASSED,
        fixed_revision=fix.fixed_revision,
        created_at=NOW - timedelta(minutes=10),
    )
    remediation = RemediationRecord(
        summary="Enforce object ownership before returning the selected user record.",
        owner_id="developer-owner",
        references=(original.evidence_id,),
        remediation_id=retest_plan.remediation_id,
        state=RemediationState.AWAITING_REVIEW,
        source_finding_revision=0,
        source_finding_fingerprint="d" * 64,
        plan_sha256="3" * 64,
        target_references=("app/users.py",),
        regression_test="A cross-user request must be rejected.",
        verification_recipe="Run the exact cross-user check and regression suite.",
        verification_history=(fix,),
        retest_history=(retest,),
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
        status=FindingStatus.AWAITING_REMEDIATION_REVIEW,
        affected_asset="repo-01",
        affected_component="app/users.py",
        evidence=(
            original,
            _evidence(fix.receipt_id, "c", "immutable fix verification"),
            _evidence(retest.receipt_id, "1", "immutable passed retest"),
        ),
        remediation=remediation,
        retest_plans=(retest_plan,),
        retest_results=(retest,),
        revision=4,
        created_at=NOW - timedelta(hours=2),
        updated_at=retest.created_at,
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
    receipts = RemediationReviewReceiptStore(
        Path(settings.VULNHUNTER_REMEDIATION_REVIEW_ROOT),
        signing_key=str(settings.SECRET_KEY).encode(),
    )
    service = RemediationReviewService(
        finding_store=store,
        governance_store=governance,
        fix_verification_store=_ReceiptStore(fix_bundle),
        retest_receipt_store=_ReceiptStore(retest_bundle),
        receipt_store=receipts,
        clock=lambda: NOW,
    )
    return store, finding, service, receipts


def _create_reviewer_user():
    from django.contrib.auth import get_user_model

    from vulnhunter.web.models import WebUserMapping

    user = get_user_model().objects.create_user(
        username="reviewer-a-web",
        password="password-1234",
    )
    WebUserMapping.objects.create(
        user=user,
        governance_identity_id="reviewer-a",
        product_roles=["reviewer"],
    )
    return user


@pytest.mark.django_db
def test_chat_opens_review_without_consuming_governance_secret(client, tmp_path, settings):
    from vulnhunter.web.models import ConversationThread

    _configure(settings, tmp_path)
    user = _create_reviewer_user()
    thread = ConversationThread.objects.create(owner=user, title="Review remediation")
    store, finding, _service, _receipts = _review_world(tmp_path, settings)
    graph = bind_remediation_assessment_graph(finding, workspace_id=str(thread.thread_id))
    remember_remediation_workspace(
        owner=user,
        workspace_id=str(thread.thread_id),
        finding=finding,
        graph=graph,
    )
    client.force_login(user)

    response = client.post(
        "/workspace/remediation-review/",
        {
            "thread_id": str(thread.thread_id),
            "message": "Open independent remediation review",
            "governance_secret": "must-not-be-consumed",
            "security_claim_supported": "true",
        },
        HTTP_X_VULNHUNTER_THREAD=str(thread.thread_id),
        HTTP_ACCEPT="application/json",
    )

    assert response.status_code == 200
    assert response.json()["redirect_url"] == (
        f"/findings/finding-01/remediation/review/?thread={thread.thread_id}"
    )
    assert store.get(finding.finding_id) == finding


@pytest.mark.django_db
def test_protected_approved_review_updates_graph_and_durable_chat(
    client,
    tmp_path,
    settings,
):
    from vulnhunter.web.models import ConversationThread

    _configure(settings, tmp_path)
    user = _create_reviewer_user()
    thread = ConversationThread.objects.create(owner=user, title="Review remediation")
    store, finding, service, receipts = _review_world(tmp_path, settings)
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
            "vulnhunter.web.remediation_review_views.remediation_review_service",
            return_value=service,
        ),
        patch(
            "vulnhunter.web.remediation_review_views.remediation_review_receipt_store",
            return_value=receipts,
        ),
    ):
        response = client.post(
            f"/findings/finding-01/remediation/review/?thread={thread.thread_id}",
            {
                "thread_id": str(thread.thread_id),
                "expected_revision": str(finding.revision),
                "evidence_lineage_complete": "true",
                "fixed_revision_matches": "true",
                "approved_scope_respected": "true",
                "security_claim_supported": "true",
                "regressions_acceptable": "true",
                "rationale": "The exact fixed revision and passed retest support the claim.",
                "limitations": "Final report and merge remain separate.",
                "blocked_reason": "",
                "governance_secret": REVIEWER_ONE_SECRET,
            },
        )

    assert response.status_code == 302
    updated = store.get(finding.finding_id)
    assert updated.status == FindingStatus.READY_FOR_REPORT
    assert updated.status not in {FindingStatus.REMEDIATED, FindingStatus.CLOSED}
    assert updated.remediation is not None
    assert updated.remediation.state == RemediationState.REVIEW_APPROVED

    thread.refresh_from_db()
    state = thread.data["vulnhunter_conversation_remediation"]
    assert state["plan"]["latest_review"]["outcome"] == "approved"
    assert state["assessment_graph"]["chat_stage"] == (
        "remediation_review_approved_ready_for_report"
    )
    assert state["assessment_graph"]["report_state"] == "ready_for_generation"


@pytest.mark.django_db
def test_wrong_governance_secret_does_not_record_review(client, tmp_path, settings):
    from vulnhunter.web.models import ConversationThread

    _configure(settings, tmp_path)
    user = _create_reviewer_user()
    thread = ConversationThread.objects.create(owner=user, title="Review remediation")
    store, finding, service, receipts = _review_world(tmp_path, settings)
    client.force_login(user)

    with (
        patch(
            "vulnhunter.web.remediation_review_views.remediation_review_service",
            return_value=service,
        ),
        patch(
            "vulnhunter.web.remediation_review_views.remediation_review_receipt_store",
            return_value=receipts,
        ),
    ):
        response = client.post(
            f"/findings/finding-01/remediation/review/?thread={thread.thread_id}",
            {
                "thread_id": str(thread.thread_id),
                "expected_revision": str(finding.revision),
                "evidence_lineage_complete": "true",
                "fixed_revision_matches": "true",
                "approved_scope_respected": "true",
                "security_claim_supported": "true",
                "regressions_acceptable": "true",
                "rationale": "This must not be accepted with a wrong secret.",
                "governance_secret": "wrong-secret",
            },
        )

    assert response.status_code == 200
    assert b"authentication failed" in response.content.lower()
    assert store.get(finding.finding_id) == finding
    assert tuple(receipts.root.glob("*.json")) == ()
