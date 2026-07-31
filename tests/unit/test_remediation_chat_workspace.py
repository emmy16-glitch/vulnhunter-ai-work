from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from vulnhunter.assessment_graph import RemediationAssessmentGraphService
from vulnhunter.findings import (
    EvidenceReference,
    Finding,
    FindingSeverity,
    FindingStatus,
    FindingStore,
    RemediationState,
    VerificationState,
)


def _configure(settings, tmp_path: Path) -> None:
    settings.PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
    settings.ALLOWED_HOSTS = ["testserver", "localhost", "127.0.0.1"]
    settings.VULNHUNTER_FINDING_DATABASE = tmp_path / "findings.sqlite3"
    settings.VULNHUNTER_TASK_GRAPH_ROOT = tmp_path / "graphs"


def _finding(*, verified: bool = True) -> Finding:
    return Finding(
        finding_id="finding-01",
        campaign_id="campaign-01",
        fingerprint=Finding.create_fingerprint(
            campaign_id="campaign-01",
            title="IDOR",
            affected_asset="api.example",
            affected_component="/users/{id}",
        ),
        title="IDOR",
        description="User lookup may expose another user's record.",
        severity=FindingSeverity.HIGH,
        confidence=90,
        verification=(VerificationState.VERIFIED if verified else VerificationState.OBSERVED),
        affected_asset="api.example",
        affected_component="/users/{id}",
        evidence=(
            EvidenceReference(
                evidence_id="evidence-01",
                sha256="a" * 64,
                provenance="independently reviewed source evidence",
                content_type="application/json",
            ),
        ),
    )


def _actor() -> SimpleNamespace:
    return SimpleNamespace(governance_identity=SimpleNamespace(reviewer_id="remediation-owner"))


@pytest.mark.django_db
def test_remediation_chat_setup_opens_protected_page_without_creating_authority(
    client,
    tmp_path,
    settings,
):
    from django.contrib.auth import get_user_model

    from vulnhunter.web.models import ConversationThread

    _configure(settings, tmp_path)
    User = get_user_model()
    operator = User.objects.create_user(
        username="remediation-operator",
        password="password-1234",
        is_staff=True,
    )
    thread = ConversationThread.objects.create(owner=operator, title="Remediate finding")
    store = FindingStore(settings.VULNHUNTER_FINDING_DATABASE)
    store.create(_finding())
    client.force_login(operator)

    with patch(
        "vulnhunter.web.remediation_views.authorized_actor",
        return_value=_actor(),
    ):
        response = client.post(
            "/workspace/remediation/",
            {
                "thread_id": str(thread.thread_id),
                "message": "Plan remediation for finding-01",
                "password": "must-not-be-consumed-from-chat",
            },
            HTTP_X_VULNHUNTER_THREAD=str(thread.thread_id),
            HTTP_ACCEPT="application/json",
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["handled"] is True
    assert payload["redirect_url"] == (
        f"/findings/finding-01/remediation/new/?thread={thread.thread_id}"
    )
    finding = store.get("finding-01")
    assert finding.status == FindingStatus.OPEN
    assert finding.remediation is None
    thread.refresh_from_db()
    assert "vulnhunter_conversation_remediation" not in thread.data


@pytest.mark.django_db
def test_protected_remediation_submission_binds_finding_graph_and_chat(
    client,
    tmp_path,
    settings,
):
    from django.contrib.auth import get_user_model

    from vulnhunter.web.models import ConversationThread

    _configure(settings, tmp_path)
    User = get_user_model()
    operator = User.objects.create_user(
        username="remediation-operator",
        password="password-1234",
        is_staff=True,
    )
    thread = ConversationThread.objects.create(owner=operator, title="Remediate finding")
    store = FindingStore(settings.VULNHUNTER_FINDING_DATABASE)
    store.create(_finding())
    client.force_login(operator)

    with patch(
        "vulnhunter.web.remediation_views._remediator",
        return_value=_actor(),
    ):
        response = client.post(
            f"/findings/finding-01/remediation/new/?thread={thread.thread_id}",
            {
                "thread_id": str(thread.thread_id),
                "expected_revision": "0",
                "summary": "Enforce ownership before returning the selected user record.",
                "target_references": "app/users.py\nGET /users/{id}",
                "regression_test": "A cross-user request must be rejected by the RED test.",
                "verification_recipe": (
                    "Run the read-only security test and all supplied regression receipts."
                ),
                "compatibility_risks": "Administrative access must remain available.",
                "password": "password-1234",
            },
        )

    assert response.status_code == 302
    assert response.url == f"/findings/finding-01/remediation/?thread={thread.thread_id}"
    finding = store.get("finding-01")
    assert finding.status == FindingStatus.IN_REMEDIATION
    assert finding.remediation is not None
    remediation = finding.remediation
    assert remediation.state == RemediationState.READY_FOR_IMPLEMENTATION
    assert remediation.remediation_id is not None
    graph = RemediationAssessmentGraphService(
        Path(settings.VULNHUNTER_TASK_GRAPH_ROOT)
    ).status_payload(remediation.remediation_id)
    assert graph is not None
    assert graph["workspace_id"] == str(thread.thread_id)
    assert graph["chat_stage"] == "awaiting_developer_implementation"

    thread.refresh_from_db()
    plan = thread.data["vulnhunter_conversation_remediation"]
    assert plan["finding_id"] == "finding-01"
    assert plan["remediation_id"] == remediation.remediation_id
    assert plan["plan"]["plan_sha256"] == remediation.plan_sha256
    assert plan["assessment_graph"]["workspace_id"] == str(thread.thread_id)
    messages = thread.data["vulnhunter_conversation_messages"]
    assert any(
        item.get("metadata", {}).get("remediation_event")
        == f"remediation:{remediation.remediation_id}:ready_for_implementation:1"
        for item in messages
    )

    with patch(
        "vulnhunter.web.remediation_views.authorized_actor",
        return_value=_actor(),
    ):
        status = client.post(
            "/workspace/remediation/",
            {
                "thread_id": str(thread.thread_id),
                "message": "What is the remediation status?",
            },
            HTTP_X_VULNHUNTER_THREAD=str(thread.thread_id),
            HTTP_ACCEPT="application/json",
        )

    assert status.status_code == 200
    status_payload = status.json()
    assert status_payload["handled"] is True
    assert "ready_for_implementation" in status_payload["message"]["content"]
    assert "awaiting_developer_implementation" in status_payload["message"]["content"]
    assert "No source change" in status_payload["message"]["content"]


@pytest.mark.django_db
def test_remediation_cancellation_returns_finding_graph_and_chat_to_safe_state(
    client,
    tmp_path,
    settings,
):
    from django.contrib.auth import get_user_model

    from vulnhunter.findings import FindingService
    from vulnhunter.web.models import ConversationThread
    from vulnhunter.web.remediation_assessment_graph import bind_remediation_assessment_graph
    from vulnhunter.web.remediation_conversation_state import remember_remediation_workspace

    _configure(settings, tmp_path)
    User = get_user_model()
    operator = User.objects.create_user(
        username="remediation-operator",
        password="password-1234",
        is_staff=True,
    )
    thread = ConversationThread.objects.create(owner=operator, title="Cancel remediation")
    store = FindingStore(settings.VULNHUNTER_FINDING_DATABASE)
    store.create(_finding())
    started = FindingService(store).start_remediation(
        "finding-01",
        owner_id="remediation-owner",
        summary="Enforce ownership before returning the selected user record.",
        target_references=("app/users.py",),
        regression_test="A cross-user request must be rejected.",
        verification_recipe="Run the read-only security and regression receipts.",
        expires_at=datetime.now(UTC) + timedelta(days=7),
        expected_revision=0,
    )
    graph = bind_remediation_assessment_graph(started, workspace_id=str(thread.thread_id))
    remember_remediation_workspace(
        owner=operator,
        workspace_id=str(thread.thread_id),
        finding=started,
        graph=graph,
    )
    client.force_login(operator)

    with patch(
        "vulnhunter.web.remediation_views._remediator",
        return_value=_actor(),
    ):
        response = client.post(
            "/findings/finding-01/remediation/cancel/",
            {
                "thread_id": str(thread.thread_id),
                "expected_revision": str(started.revision),
                "reason": "Owner withdrew the plan before implementation.",
                "password": "password-1234",
            },
        )

    assert response.status_code == 302
    assert response.url == f"/findings/finding-01/remediation/?thread={thread.thread_id}"
    cancelled = store.get("finding-01")
    assert cancelled.status == FindingStatus.TRIAGED
    assert cancelled.remediation is not None
    assert cancelled.remediation.state == RemediationState.CANCELLED
    graph_payload = RemediationAssessmentGraphService(
        Path(settings.VULNHUNTER_TASK_GRAPH_ROOT)
    ).status_payload(cancelled.remediation.remediation_id)
    assert graph_payload is not None
    assert graph_payload["chat_stage"] == "remediation_cancelled"
    thread.refresh_from_db()
    plan = thread.data["vulnhunter_conversation_remediation"]
    assert plan["plan"]["state"] == "cancelled"


@pytest.mark.django_db
def test_unverified_finding_is_not_eligible_for_protected_remediation(
    client,
    tmp_path,
    settings,
):
    from django.contrib.auth import get_user_model

    from vulnhunter.web.models import ConversationThread

    _configure(settings, tmp_path)
    User = get_user_model()
    operator = User.objects.create_user(
        username="remediation-operator",
        password="password-1234",
        is_staff=True,
    )
    thread = ConversationThread.objects.create(owner=operator, title="Blocked remediation")
    store = FindingStore(settings.VULNHUNTER_FINDING_DATABASE)
    store.create(_finding(verified=False))
    client.force_login(operator)

    with patch(
        "vulnhunter.web.remediation_views._remediator",
        return_value=_actor(),
    ):
        response = client.get(f"/findings/finding-01/remediation/new/?thread={thread.thread_id}")

    assert response.status_code == 409
    assert store.get("finding-01").remediation is None
