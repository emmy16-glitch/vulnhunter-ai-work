from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from django.contrib.auth import get_user_model

from vulnhunter.web import conversation_approval_views


def test_confirmation_copy_reports_queued_and_blocked_states():
    queued = SimpleNamespace(workflow_state="queued")
    blocked = SimpleNamespace(
        workflow_state="execution_blocked",
        execution_blocking_reason="The isolated worker is disabled.",
    )

    assert "continuing" in conversation_approval_views._confirmation_copy(queued)
    blocked_copy = conversation_approval_views._confirmation_copy(blocked)
    assert "execution remains blocked" in blocked_copy
    assert "isolated worker is disabled" in blocked_copy


@pytest.mark.django_db
def test_inline_confirmation_resumes_the_owned_passive_run(client):
    user = get_user_model().objects.create_user(
        username="vulnhunter",
        password="long-test-password-1234",
    )
    client.force_login(user)
    digest = "a" * 64
    actor = SimpleNamespace(governance_identity=SimpleNamespace(reviewer_id="vulnhunter-user"))
    pending = SimpleNamespace(
        request_id="approval-inline-test",
        run_id="assessment-inline-test",
        requested_by="vulnhunter-user",
    )
    run = SimpleNamespace(
        run_id="assessment-inline-test",
        command_plan_summary={"exact_profile": "passive", "plan_digest": digest},
    )
    confirmed = SimpleNamespace(run_id="assessment-inline-test")
    refreshed = SimpleNamespace(
        run_id="assessment-inline-test",
        workflow_state="queued",
    )
    store = Mock()
    store.get.return_value = pending
    store.confirm_exact_passive_plan.return_value = confirmed
    workflow = Mock()
    service = Mock()
    service.get_agent_run.return_value = refreshed
    message = {
        "role": "assistant",
        "kind": "status",
        "content": "Exact passive plan confirmed.",
    }

    with (
        patch.object(conversation_approval_views, "_actor", return_value=actor),
        patch.object(conversation_approval_views, "_confirmation_store", return_value=store),
        patch.object(conversation_approval_views, "_visible_run", return_value=run),
        patch.object(
            conversation_approval_views.AssessmentWorkflowService,
            "from_settings",
            return_value=workflow,
        ),
        patch.object(conversation_approval_views, "product_service", return_value=service),
        patch.object(conversation_approval_views, "_append_message", return_value=message),
        patch.object(
            conversation_approval_views,
            "_run_payload",
            return_value={"run_id": "assessment-inline-test", "state": "queued"},
        ),
    ):
        response = client.post(
            "/workspace/approve/",
            {
                "request_id": "approval-inline-test",
                "plan_digest": digest,
                "reason": "Confirm this exact authorised passive plan.",
            },
        )

    assert response.status_code == 200
    assert response.json()["run"]["state"] == "queued"
    workflow.validate_approval_binding.assert_called_once_with(
        request=pending,
        submitted_plan_digest=digest,
    )
    store.confirm_exact_passive_plan.assert_called_once_with(
        request_id="approval-inline-test",
        actor_id="vulnhunter-user",
        action_manifest_sha256=digest,
        profile="passive",
        reason="Confirm this exact authorised passive plan.",
    )
    workflow.record_approval_decision.assert_called_once_with(
        request=confirmed,
        actor_id="vulnhunter-user",
    )


@pytest.mark.django_db
def test_inline_confirmation_rejects_intrusive_plan_before_state_change(client):
    user = get_user_model().objects.create_user(
        username="vulnhunter",
        password="long-test-password-1234",
    )
    client.force_login(user)
    digest = "b" * 64
    actor = SimpleNamespace(governance_identity=SimpleNamespace(reviewer_id="vulnhunter-user"))
    pending = SimpleNamespace(run_id="assessment-inline-test")
    run = SimpleNamespace(
        run_id="assessment-inline-test",
        command_plan_summary={"exact_profile": "intrusive", "plan_digest": digest},
    )
    store = Mock()
    store.get.return_value = pending

    with (
        patch.object(conversation_approval_views, "_actor", return_value=actor),
        patch.object(conversation_approval_views, "_confirmation_store", return_value=store),
        patch.object(conversation_approval_views, "_visible_run", return_value=run),
    ):
        response = client.post(
            "/workspace/approve/",
            {
                "request_id": "approval-inline-test",
                "plan_digest": digest,
                "reason": "Confirm this exact intrusive plan.",
            },
        )

    assert response.status_code == 409
    assert "limited to the reviewed passive profile" in response.json()["detail"]
    store.confirm_exact_passive_plan.assert_not_called()
