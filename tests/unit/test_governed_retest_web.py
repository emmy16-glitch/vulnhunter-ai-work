from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from vulnhunter.findings import (
    EvidenceReference,
    Finding,
    FindingService,
    FindingSeverity,
    FindingStatus,
    FindingStore,
    RemediationState,
    RemediationVerificationReference,
    VerificationState,
)
from vulnhunter.source_hunt import VerifierReceipt
from vulnhunter.web.remediation_assessment_graph import bind_remediation_assessment_graph
from vulnhunter.web.remediation_conversation_state import remember_remediation_workspace


def _configure(settings, tmp_path: Path) -> None:
    settings.PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
    settings.ALLOWED_HOSTS = ["testserver", "localhost", "127.0.0.1"]
    settings.VULNHUNTER_FINDING_DATABASE = tmp_path / "findings.sqlite3"
    settings.VULNHUNTER_TASK_GRAPH_ROOT = tmp_path / "graphs"
    settings.VULNHUNTER_RETEST_RECEIPT_ROOT = tmp_path / "retest-receipts"


def _actor() -> SimpleNamespace:
    return SimpleNamespace(
        governance_identity=SimpleNamespace(reviewer_id="retest-operator")
    )


def _receipt(name: str) -> VerifierReceipt:
    return VerifierReceipt(
        verifier_id=name,
        passed=True,
        exit_code=0,
        output_sha256=hashlib.sha256(name.encode()).hexdigest(),
        duration_seconds=0.2,
        safe_summary="Deterministic bounded retest receipt.",
    )


def _ready_finding(store: FindingStore, now: datetime):
    original = EvidenceReference(
        evidence_id="evidence-original",
        sha256="a" * 64,
        provenance="independently reviewed original assessment evidence",
        content_type="application/json",
    )
    store.create(
        Finding(
            finding_id="finding-01",
            campaign_id="campaign-01",
            fingerprint=Finding.create_fingerprint(
                campaign_id="campaign-01",
                title="IDOR",
                affected_asset="repo-01",
                affected_component="app/users.py",
            ),
            title="IDOR",
            description=(
                "User lookup may expose another user's record without ownership checks."
            ),
            severity=FindingSeverity.HIGH,
            confidence=90,
            verification=VerificationState.VERIFIED,
            affected_asset="repo-01",
            affected_component="app/users.py",
            evidence=(original,),
            created_at=now - timedelta(hours=1),
            updated_at=now - timedelta(hours=1),
        )
    )
    lifecycle = FindingService(store)
    planned = lifecycle.start_remediation(
        "finding-01",
        owner_id="developer-01",
        summary="Enforce object ownership before returning the selected user record.",
        target_references=("app/users.py",),
        regression_test="A cross-user request must be rejected by the RED security test.",
        verification_recipe="Run the exact cross-user check and the user API regression suite.",
        references=(original.evidence_id,),
        expires_at=now + timedelta(days=7),
        expected_revision=0,
        now=now,
    )
    verified_at = now + timedelta(seconds=1)
    fixed = lifecycle.record_fix_verification(
        "finding-01",
        verification=RemediationVerificationReference(
            receipt_id="fix-verification-" + "b" * 24,
            sha256="c" * 64,
            verdict="fixed",
            original_revision="1" * 40,
            fixed_revision="2" * 40,
            created_at=verified_at,
        ),
        expected_revision=planned.revision,
        now=verified_at,
    )
    return original, fixed


@pytest.mark.django_db
def test_chat_opens_protected_retest_without_consuming_authority(
    client,
    tmp_path,
    settings,
):
    from django.contrib.auth import get_user_model

    from vulnhunter.web.models import ConversationThread

    _configure(settings, tmp_path)
    User = get_user_model()
    operator = User.objects.create_user(
        username="retest-operator",
        password="password-1234",
        is_staff=True,
    )
    thread = ConversationThread.objects.create(owner=operator, title="Retest finding")
    store = FindingStore(settings.VULNHUNTER_FINDING_DATABASE)
    _original, finding = _ready_finding(store, datetime.now(UTC) - timedelta(minutes=1))
    graph = bind_remediation_assessment_graph(finding, workspace_id=str(thread.thread_id))
    remember_remediation_workspace(
        owner=operator,
        workspace_id=str(thread.thread_id),
        finding=finding,
        graph=graph,
    )
    client.force_login(operator)

    with patch(
        "vulnhunter.web.retest_conversation_views.authorized_actor",
        return_value=_actor(),
    ):
        response = client.post(
            "/workspace/retest/",
            {
                "thread_id": str(thread.thread_id),
                "message": "Start retest for this fix",
                "password": "must-not-be-consumed-from-chat",
                "after_evidence_json": "must-not-be-consumed-from-chat",
            },
            HTTP_X_VULNHUNTER_THREAD=str(thread.thread_id),
            HTTP_ACCEPT="application/json",
        )

    assert response.status_code == 200
    assert response.json()["redirect_url"] == (
        f"/findings/finding-01/retest/new/?thread={thread.thread_id}"
    )
    assert store.get("finding-01") == finding


@pytest.mark.django_db
def test_protected_retest_start_binds_child_graph_and_same_workspace(
    client,
    tmp_path,
    settings,
):
    from django.contrib.auth import get_user_model

    from vulnhunter.web.models import ConversationThread

    _configure(settings, tmp_path)
    User = get_user_model()
    operator = User.objects.create_user(
        username="retest-operator",
        password="password-1234",
        is_staff=True,
    )
    thread = ConversationThread.objects.create(owner=operator, title="Retest finding")
    store = FindingStore(settings.VULNHUNTER_FINDING_DATABASE)
    _original, finding = _ready_finding(store, datetime.now(UTC) - timedelta(minutes=1))
    graph = bind_remediation_assessment_graph(finding, workspace_id=str(thread.thread_id))
    remember_remediation_workspace(
        owner=operator,
        workspace_id=str(thread.thread_id),
        finding=finding,
        graph=graph,
    )
    client.force_login(operator)

    with patch("vulnhunter.web.retest_views._operator", return_value=_actor()):
        response = client.post(
            f"/findings/finding-01/retest/new/?thread={thread.thread_id}",
            {
                "thread_id": str(thread.thread_id),
                "expected_revision": str(finding.revision),
                "check_references": (
                    "GET /users/{id} with another authorised test identity\n"
                    "Run the user API regression suite"
                ),
                "password": "password-1234",
            },
        )

    assert response.status_code == 302
    assert response.url == f"/findings/finding-01/retest/?thread={thread.thread_id}"
    updated = store.get("finding-01")
    assert updated.status == FindingStatus.RETESTING
    assert len(updated.retest_plans) == 1
    plan = updated.retest_plans[0]
    assert plan.fixed_revision == "2" * 40
    assert plan.before_evidence_ids == ("evidence-original",)

    thread.refresh_from_db()
    state = thread.data["vulnhunter_conversation_retest"]
    assert state["retest_id"] == plan.retest_id
    assert state["assessment_graph"]["chat_stage"] == "retest_ready_for_evidence"
    assert state["report_state"] == "blocked_pending_retest"


@pytest.mark.django_db
def test_protected_passed_retest_opens_review_but_keeps_report_blocked(
    client,
    tmp_path,
    settings,
):
    from django.contrib.auth import get_user_model

    from vulnhunter.web.models import ConversationThread
    from vulnhunter.web.retest_assessment_graph import bind_retest_assessment_graph
    from vulnhunter.web.retest_conversation_state import remember_retest_workspace
    from vulnhunter.web.retest_service import governed_retest_service

    _configure(settings, tmp_path)
    User = get_user_model()
    operator = User.objects.create_user(
        username="retest-operator",
        password="password-1234",
        is_staff=True,
    )
    thread = ConversationThread.objects.create(owner=operator, title="Retest finding")
    store = FindingStore(settings.VULNHUNTER_FINDING_DATABASE)
    original, finding = _ready_finding(store, datetime.now(UTC) - timedelta(minutes=1))
    remediation_graph = bind_remediation_assessment_graph(
        finding,
        workspace_id=str(thread.thread_id),
    )
    remember_remediation_workspace(
        owner=operator,
        workspace_id=str(thread.thread_id),
        finding=finding,
        graph=remediation_graph,
    )
    started = governed_retest_service().start(
        finding_id="finding-01",
        expected_revision=finding.revision,
        owner_id="retest-operator",
        check_references=("GET /users/{id} with another authorised test identity",),
        expires_at=datetime.now(UTC) + timedelta(days=2),
    )
    retest_graph = bind_retest_assessment_graph(
        started,
        workspace_id=str(thread.thread_id),
    )
    remember_retest_workspace(
        owner=operator,
        workspace_id=str(thread.thread_id),
        finding=started,
        retest_graph=retest_graph,
        remediation_graph=remediation_graph,
    )
    after = EvidenceReference(
        evidence_id="evidence-retest-after",
        sha256="d" * 64,
        provenance="bounded after-fix evidence for the exact fixed revision",
        content_type="application/json",
    )
    client.force_login(operator)

    with patch("vulnhunter.web.retest_views._operator", return_value=_actor()):
        response = client.post(
            f"/findings/finding-01/retest/?thread={thread.thread_id}",
            {
                "thread_id": str(thread.thread_id),
                "expected_revision": str(started.revision),
                "before_evidence_json": json.dumps(
                    [original.model_dump(mode="json")]
                ),
                "after_evidence_json": json.dumps([after.model_dump(mode="json")]),
                "check_receipts_json": json.dumps(
                    [
                        _receipt("idor-security-retest").model_dump(mode="json"),
                        _receipt("user-api-regression").model_dump(mode="json"),
                    ]
                ),
                "original_issue_blocked": "true",
                "regression_free": "true",
                "blocked_reason": "",
                "password": "password-1234",
            },
        )

    assert response.status_code == 302
    updated = store.get("finding-01")
    assert updated.status == FindingStatus.AWAITING_REMEDIATION_REVIEW
    assert updated.status != FindingStatus.REMEDIATED
    assert updated.remediation is not None
    assert updated.remediation.state == RemediationState.AWAITING_REVIEW

    thread.refresh_from_db()
    state = thread.data["vulnhunter_conversation_retest"]
    assert state["result"]["outcome"] == "passed"
    assert state["assessment_graph"]["chat_stage"] == (
        "retest_passed_awaiting_independent_review"
    )
    assert state["report_state"] == "blocked_pending_independent_review"
    assert state["remediation_graph"]["chat_stage"] == (
        "retest_passed_awaiting_independent_review"
    )


@pytest.mark.django_db
def test_bad_password_does_not_start_retest(client, tmp_path, settings):
    from django.contrib.auth import get_user_model

    from vulnhunter.web.models import ConversationThread

    _configure(settings, tmp_path)
    User = get_user_model()
    operator = User.objects.create_user(
        username="retest-operator",
        password="password-1234",
        is_staff=True,
    )
    thread = ConversationThread.objects.create(owner=operator, title="Retest finding")
    store = FindingStore(settings.VULNHUNTER_FINDING_DATABASE)
    _original, finding = _ready_finding(store, datetime.now(UTC) - timedelta(minutes=1))
    client.force_login(operator)

    with patch("vulnhunter.web.retest_views._operator", return_value=_actor()):
        response = client.post(
            f"/findings/finding-01/retest/new/?thread={thread.thread_id}",
            {
                "thread_id": str(thread.thread_id),
                "expected_revision": str(finding.revision),
                "check_references": "Run the exact bounded check",
                "password": "wrong-password",
            },
        )

    assert response.status_code == 200
    assert b"Password re-authentication failed" in response.content
    assert store.get("finding-01") == finding
