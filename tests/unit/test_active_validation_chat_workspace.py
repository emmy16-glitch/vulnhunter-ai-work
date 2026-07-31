from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

import pytest

from vulnhunter.adversary_lab.runner import LabWorkerPolicy, SyntheticScenarioRunner
from vulnhunter.adversary_lab.service import AdversaryLabService
from vulnhunter.agent_activity.service import AgentActivityService
from vulnhunter.agent_activity.store import AppendOnlyActivityStore
from vulnhunter.assessment_graph import (
    ActiveValidationAssessmentGraphService,
    AssessmentGraphService,
)
from vulnhunter.web.active_validation_assessment_graph import (
    ProjectingAdversaryLabStore,
    bind_active_validation_assessment_graph,
)

NOW = datetime(2026, 7, 31, 19, 30, tzinfo=UTC)


def _configure(settings, tmp_path: Path) -> None:
    settings.PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
    settings.ALLOWED_HOSTS = ["testserver", "localhost", "127.0.0.1"]
    settings.VULNHUNTER_TASK_GRAPH_ROOT = tmp_path / "graphs"
    settings.VULNHUNTER_ADVERSARY_LAB_DATABASE = tmp_path / "lab.sqlite3"
    settings.VULNHUNTER_ADVERSARY_LAB_WORKSPACE_ROOT = tmp_path / "workspace"
    settings.VULNHUNTER_ADVERSARY_LAB_EVIDENCE_ROOT = tmp_path / "evidence"
    settings.VULNHUNTER_AGENT_ACTIVITY_ROOT = tmp_path / "activity"
    settings.VULNHUNTER_ADVERSARY_LAB_ENABLED = True
    settings.VULNHUNTER_ADVERSARY_LAB_MAX_TRIALS = 10
    settings.VULNHUNTER_ADVERSARY_LAB_STEP_UP_SECONDS = 600


def _parent_graph(settings, *, run_id: str, workspace_id: str) -> None:
    AssessmentGraphService(Path(settings.VULNHUNTER_TASK_GRAPH_ROOT)).create_website_assessment(
        run_id=run_id,
        workspace_id=workspace_id,
        owner_id="validation-operator",
        authorization_id="authorization-active-validation",
        target="http://10.23.0.15:8080/",
        expires_at=datetime.now(UTC) + timedelta(hours=2),
        profile="passive",
        plan_digest="a" * 64,
        readiness_blocked=False,
    )


def _active_graph(settings, lab_id: str) -> dict[str, object] | None:
    return ActiveValidationAssessmentGraphService(
        Path(settings.VULNHUNTER_TASK_GRAPH_ROOT)
    ).status_payload(lab_id)


def _lab_service(settings, *, enabled: bool = True) -> AdversaryLabService:
    return AdversaryLabService(
        store=ProjectingAdversaryLabStore(
            Path(settings.VULNHUNTER_ADVERSARY_LAB_DATABASE)
        ),
        activity_service=AgentActivityService(
            AppendOnlyActivityStore(Path(settings.VULNHUNTER_AGENT_ACTIVITY_ROOT))
        ),
        runner=SyntheticScenarioRunner(
            LabWorkerPolicy(
                enabled=enabled,
                workspace_root=Path(
                    settings.VULNHUNTER_ADVERSARY_LAB_WORKSPACE_ROOT
                ).absolute(),
                evidence_root=Path(
                    settings.VULNHUNTER_ADVERSARY_LAB_EVIDENCE_ROOT
                ).absolute(),
                maximum_trials=10,
            )
        ),
    )


@pytest.mark.django_db
def test_active_validation_submission_binds_child_graph_and_chat_workspace(
    client,
    tmp_path,
    settings,
):
    from django.contrib.auth import get_user_model

    from vulnhunter.web.models import ConversationThread

    _configure(settings, tmp_path)
    User = get_user_model()
    operator = User.objects.create_user(
        username="validation-operator",
        password="password-1234",
        is_staff=True,
    )
    thread = ConversationThread.objects.create(owner=operator, title="Validate finding")
    assessment_id = "assessment-active-validation"
    _parent_graph(settings, run_id=assessment_id, workspace_id=str(thread.thread_id))
    actor = SimpleNamespace(
        governance_identity=SimpleNamespace(reviewer_id="validation-governance-operator")
    )
    run = SimpleNamespace(
        run_id=assessment_id,
        authorization_id="authorization-active-validation",
        scope_summary="http://10.23.0.15:8080/",
        findings=(
            {
                "evidence_id": "evidence-active-validation",
                "title": "Synthetic impact candidate",
                "verification": "candidate",
                "target_reference": "http://10.23.0.15:8080/",
            },
        ),
    )
    client.force_login(operator)

    with (
        patch("vulnhunter.web.lab_views._operator", return_value=actor),
        patch("vulnhunter.web.lab_views._assessment_for_actor", return_value=(actor, run)),
    ):
        response = client.post(
            f"/scans/{assessment_id}/active-validation/new/",
            {
                "finding_reference": "evidence-active-validation",
                "scenario_id": "synthetic-file-impact",
                "maximum_trials": "5",
                "password": "password-1234",
            },
        )

    assert response.status_code == 302
    records = ProjectingAdversaryLabStore(
        Path(settings.VULNHUNTER_ADVERSARY_LAB_DATABASE)
    ).list_for_assessment(assessment_id)
    assert len(records) == 1
    record = records[0]
    graph = _active_graph(settings, record.plan.lab_id)
    assert graph is not None
    assert graph["assessment_kind"] == "active_validation"
    assert graph["workspace_id"] == str(thread.thread_id)
    assert graph["chat_stage"] == "awaiting_independent_approval"

    thread.refresh_from_db()
    plan = thread.data["vulnhunter_conversation_active_validation"]
    assert plan["lab_id"] == record.plan.lab_id
    assert plan["scenario"]["plan_digest"] == record.plan.plan_digest
    assert plan["assessment_graph"]["workspace_id"] == str(thread.thread_id)
    messages = thread.data["vulnhunter_conversation_messages"]
    assert any(
        item.get("metadata", {}).get("active_validation_event")
        == f"active-validation:{record.plan.lab_id}:awaiting_approval:0"
        for item in messages
    )

    with patch(
        "vulnhunter.web.active_validation_conversation_views.authorized_actor",
        return_value=actor,
    ):
        status = client.post(
            "/workspace/active-validation/",
            {
                "thread_id": str(thread.thread_id),
                "message": "What is the Active Validation status?",
            },
            HTTP_X_VULNHUNTER_THREAD=str(thread.thread_id),
            HTTP_ACCEPT="application/json",
        )

    assert status.status_code == 200
    payload = status.json()
    assert payload["handled"] is True
    assert "awaiting_approval" in payload["message"]["content"]
    assert "awaiting_independent_approval" in payload["message"]["content"]


@pytest.mark.django_db
def test_active_validation_chat_setup_preserves_protected_step_up_boundary(
    client,
    tmp_path,
    settings,
):
    from django.contrib.auth import get_user_model

    from vulnhunter.web.models import ConversationThread

    _configure(settings, tmp_path)
    User = get_user_model()
    operator = User.objects.create_user(
        username="validation-chat-operator",
        password="password-1234",
    )
    assessment_id = "assessment-validation-chat"
    thread = ConversationThread.objects.create(
        owner=operator,
        title="Open validation",
        data={"vulnhunter_conversation_state": {"run_id": assessment_id}},
    )
    actor = SimpleNamespace(
        governance_identity=SimpleNamespace(reviewer_id="validation-chat-operator")
    )
    client.force_login(operator)

    with patch(
        "vulnhunter.web.active_validation_conversation_views.authorized_actor",
        return_value=actor,
    ):
        response = client.post(
            "/workspace/active-validation/",
            {
                "thread_id": str(thread.thread_id),
                "message": "Start Active Validation for this finding",
                "password": "must-not-be-used-from-chat",
            },
            HTTP_X_VULNHUNTER_THREAD=str(thread.thread_id),
            HTTP_ACCEPT="application/json",
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["handled"] is True
    assert payload["redirect_url"] == f"/scans/{assessment_id}/active-validation/new/"
    assert "password re-authentication" in payload["message"]["content"]
    assert not ProjectingAdversaryLabStore(
        Path(settings.VULNHUNTER_ADVERSARY_LAB_DATABASE)
    ).list_all()
    thread.refresh_from_db()
    assert "vulnhunter_conversation_active_validation" not in thread.data


@pytest.mark.django_db
def test_active_validation_worker_projects_without_browser_state(tmp_path, settings):
    _configure(settings, tmp_path)
    service = _lab_service(settings)
    record = service.create_plan(
        assessment_id="assessment-worker-validation",
        finding_reference="evidence-worker-validation",
        authorization_id="authorization-worker-validation",
        target_reference="http://10.23.0.15:8080/",
        scenario_id="synthetic-file-impact",
        maximum_trials=5,
        requested_by="operator-a",
    )
    bind_active_validation_assessment_graph(
        record,
        workspace_id=str(uuid4()),
        owner_id="validation-worker",
    )
    service.approve(record.plan.lab_id, approved_by="approver-b")
    service.queue(record.plan.lab_id, queued_by="operator-a")

    completed = service.run_next()

    assert completed is not None
    assert completed.state.value == "completed"
    graph = _active_graph(settings, record.plan.lab_id)
    assert graph is not None
    assert graph["chat_stage"] == "awaiting_human_review"
    statuses = {item["stage"]: item["status"] for item in graph["nodes"]}
    assert statuses["execution"] == "completed"
    assert statuses["evidence"] == "completed"
    assert statuses["verification"] == "completed"
    assert statuses["review"] == "ready"


@pytest.mark.django_db
def test_disabled_active_validation_worker_projects_failed_closed(tmp_path, settings):
    _configure(settings, tmp_path)
    service = _lab_service(settings, enabled=False)
    record = service.create_plan(
        assessment_id="assessment-disabled-validation",
        finding_reference="evidence-disabled-validation",
        authorization_id="authorization-disabled-validation",
        target_reference="http://10.23.0.15:8080/",
        scenario_id="synthetic-file-impact",
        maximum_trials=3,
        requested_by="operator-a",
    )
    bind_active_validation_assessment_graph(
        record,
        workspace_id=str(uuid4()),
        owner_id="validation-worker",
    )
    service.approve(record.plan.lab_id, approved_by="approver-b")
    service.queue(record.plan.lab_id, queued_by="operator-a")

    failed = service.run_next()

    assert failed is not None
    assert failed.state.value == "failed"
    graph = _active_graph(settings, record.plan.lab_id)
    assert graph is not None
    statuses = {item["stage"]: item["status"] for item in graph["nodes"]}
    assert statuses["execution"] == "failed"
    assert all(
        statuses[stage] == "cancelled"
        for stage in ("evidence", "verification", "review", "report")
    )
