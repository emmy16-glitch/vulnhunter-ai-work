from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model

from vulnhunter.web import conversation_service, conversational_views
from vulnhunter.web.conversation_service import InterpretedRequest, deterministic_intent
from vulnhunter.web.conversation_threads import create_thread


class _Workflow:
    def list_authorizations(self, **_kwargs):
        return ()


@pytest.fixture
def actor():
    return SimpleNamespace(
        governance_identity=SimpleNamespace(reviewer_id="reasoning-user"),
        product_roles=("campaign-operator",),
    )


@pytest.mark.django_db
def test_reasoning_policy_is_high_for_every_workspace(client, settings):
    settings.ALLOWED_HOSTS = ["testserver"]
    user = get_user_model().objects.create_user(
        username="reasoning-owner",
        password="safe-pass-1234",
    )
    first = create_thread(owner=user, title="Deep APK")
    second = create_thread(owner=user, title="Quick question")
    client.force_login(user)

    response = client.post(
        "/workspace/reasoning/",
        {"reasoning_effort": "low", "provider_preference": "auto"},
        HTTP_X_VULNHUNTER_THREAD=str(first.thread_id),
    )
    assert response.status_code == 200
    first.refresh_from_db()
    second.refresh_from_db()
    assert first.reasoning_effort == "high"
    assert first.provider_preference == "groq"
    assert second.reasoning_effort == "high"
    assert second.provider_preference == "groq"


@pytest.mark.django_db
def test_selected_reasoning_takes_effect_on_next_message(client, settings, actor):
    settings.ALLOWED_HOSTS = ["testserver"]
    settings.VULNHUNTER_GROQ_ENABLED = False
    settings.VULNHUNTER_HUGGINGFACE_ENABLED = False
    user = get_user_model().objects.create_user(
        username="reasoning-message",
        password="safe-pass-1234",
    )
    thread = create_thread(owner=user)
    client.force_login(user)
    captured = {}

    def fake_interpret(text, **kwargs):
        captured.update(kwargs)
        return InterpretedRequest(
            intent="chat",
            target=None,
            protocol=None,
            port=None,
            profile=None,
            evidence_reference=None,
            assistant_copy="A direct deep answer.",
            provider="groq",
            provider_detail="test",
            model="openai/gpt-oss-120b",
            reasoning_effort=kwargs["reasoning_effort"],
        )

    with (
        patch.object(conversational_views, "_actor", return_value=actor),
        patch.object(
            conversational_views.AssessmentWorkflowService,
            "from_settings",
            return_value=_Workflow(),
        ),
        patch.object(conversational_views, "interpret_request", side_effect=fake_interpret),
    ):
        response = client.post(
            "/workspace/message/",
            {"message": "Explain this carefully", "reasoning_effort": "medium"},
            HTTP_X_VULNHUNTER_THREAD=str(thread.thread_id),
        )
    assert response.status_code == 200
    assert captured["reasoning_effort"] == "high"
    assert captured["provider_preference"] == "groq"
    assert captured["memory_summary"]
    assert "workspace" in captured["tool_context"]
    assert response.json()["message"]["metadata"]["reasoning_effort"] == "high"


def test_failed_high_reasoning_does_not_fall_back_to_another_provider_or_canned_copy():
    with (
        patch.object(
            conversation_service,
            "_groq_advisory",
            return_value=(None, "configured high-reasoning model unavailable"),
        ) as groq,
        patch.object(conversation_service, "_huggingface_advisory") as huggingface,
    ):
        interpreted = conversation_service.interpret_request(
            "Explain how this security behavior could be a false positive",
            available_profiles=("passive",),
            reasoning_effort="low",
            provider_preference="auto",
        )

    assert interpreted.intent == "chat"
    assert interpreted.provider == "groq"
    assert interpreted.model is None
    assert interpreted.reasoning_effort == "high"
    assert interpreted.assistant_copy is not None
    assert "High-reasoning AI is unavailable" in interpreted.assistant_copy
    assert "did not substitute" in interpreted.assistant_copy
    groq.assert_called_once()
    huggingface.assert_not_called()


@pytest.mark.django_db
def test_workspace_keeps_rolling_memory_beyond_recent_context(client, settings, actor):
    settings.ALLOWED_HOSTS = ["testserver"]
    settings.VULNHUNTER_GROQ_ENABLED = False
    settings.VULNHUNTER_HUGGINGFACE_ENABLED = False
    user = get_user_model().objects.create_user(
        username="memory-owner",
        password="safe-pass-1234",
    )
    thread = create_thread(owner=user)
    client.force_login(user)
    with (
        patch.object(conversational_views, "_actor", return_value=actor),
        patch.object(
            conversational_views.AssessmentWorkflowService,
            "from_settings",
            return_value=_Workflow(),
        ),
    ):
        for index in range(35):
            response = client.post(
                "/workspace/message/",
                {"message": f"Remember investigation detail {index}"},
                HTTP_X_VULNHUNTER_THREAD=str(thread.thread_id),
            )
            assert response.status_code == 200
    thread.refresh_from_db()
    assert "investigation detail 0" in thread.memory_summary
    assert "investigation detail 34" in thread.memory_summary
    assert len(thread.data["vulnhunter_conversation_messages"]) > 50


def test_general_security_questions_are_not_forced_into_scan_flow():
    assert deterministic_intent("Explain how APK static analysis works") == "chat"
    assert deterministic_intent("Can you check my understanding of SQL injection?") == "chat"
    assert deterministic_intent("Scan the target website") == "scan"


def test_reasoning_selector_is_visible_in_workspace_template():
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    template = (root / "vulnhunter/web/templates/web/conversation.html").read_text()
    script = (root / "vulnhunter/web/static/web/conversation.js").read_text()
    assert "data-reasoning-effort" in template
    assert 'value="low"' in template
    assert 'value="medium"' in template
    assert 'value="high"' in template
    assert "initial.reasoning_url" in script
    assert "reasoning_effort" in script
