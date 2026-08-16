from __future__ import annotations

import json
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


def test_failed_groq_falls_through_to_gemini_without_user_visible_provider_switch():
    gemini_answer = json.dumps(
        {
            "message": "This behavior can be a false positive when the evidence is contextual.",
            "recommended_profile": None,
            "model": "gemini-3.6-flash",
        }
    )
    with (
        patch.object(
            conversation_service,
            "_groq_advisory",
            return_value=(None, "Groq free-tier rate limit reached"),
        ) as groq,
        patch(
            "vulnhunter.web.ai_failover._gemini_advisory",
            return_value=(gemini_answer, "Gemini answer normalised"),
        ) as gemini,
        patch("vulnhunter.web.ai_failover._ollama_advisory") as ollama,
    ):
        interpreted = conversation_service.interpret_request(
            "Explain this carefully",
            available_profiles=("passive",),
            provider_preference="auto",
        )

    assert interpreted.provider == "auto"
    assert interpreted.provider_detail == "AI reasoning completed."
    assert interpreted.model == "gemini-3.6-flash"
    assert interpreted.assistant_copy == (
        "This behavior can be a false positive when the evidence is contextual."
    )
    groq.assert_called_once()
    gemini.assert_called_once()
    ollama.assert_not_called()


def test_failed_groq_and_gemini_fall_through_to_ollama():
    ollama_answer = json.dumps(
        {
            "message": "Local fallback answer.",
            "recommended_profile": None,
            "model": "qwen3:1.7b",
        }
    )
    with (
        patch.object(
            conversation_service,
            "_groq_advisory",
            return_value=(None, "Groq timed out"),
        ),
        patch(
            "vulnhunter.web.ai_failover._gemini_advisory",
            return_value=(None, "Gemini unavailable"),
        ),
        patch(
            "vulnhunter.web.ai_failover._ollama_advisory",
            return_value=(ollama_answer, "Ollama answer normalised"),
        ) as ollama,
    ):
        interpreted = conversation_service.interpret_request(
            "Explain this carefully",
            available_profiles=("passive",),
            provider_preference="auto",
        )

    assert interpreted.provider == "auto"
    assert interpreted.provider_detail == "AI reasoning completed."
    assert interpreted.model == "qwen3:1.7b"
    assert interpreted.assistant_copy == "Local fallback answer."
    ollama.assert_called_once()


def test_all_ai_providers_unavailable_returns_generic_retry_copy():
    with (
        patch.object(
            conversation_service,
            "_groq_advisory",
            return_value=(None, "Groq unavailable"),
        ),
        patch(
            "vulnhunter.web.ai_failover._gemini_advisory",
            return_value=(None, "Gemini unavailable"),
        ),
        patch(
            "vulnhunter.web.ai_failover._ollama_advisory",
            return_value=(None, "Ollama unavailable"),
        ),
    ):
        interpreted = conversation_service.interpret_request(
            "Explain this carefully",
            available_profiles=("passive",),
            provider_preference="auto",
        )

    assert interpreted.provider == "auto"
    assert interpreted.model is None
    assert interpreted.assistant_copy == (
        "I couldn't complete that response right now. Please retry in a moment."
    )
    assert "Groq" not in interpreted.provider_detail
    assert "Gemini" not in interpreted.provider_detail
    assert "Ollama" not in interpreted.provider_detail


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
            assistant_copy="I remember the earlier target context.",
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
            {"message": "What did we establish earlier?"},
            HTTP_X_VULNHUNTER_THREAD=str(thread.thread_id),
        )

    assert response.status_code == 200
    assert captured["reasoning_effort"] == "high"
    assert captured["memory_summary"]
    assert "workspace" in captured["tool_context"]


def test_scan_intent_stays_deterministic_when_advisory_changes_its_mind():
    advisory = json.dumps(
        {
            "message": "This looks like a scan request.",
            "recommended_profile": "passive",
            "model": "openai/gpt-oss-120b",
        }
    )
    with patch.object(
        conversation_service,
        "_groq_advisory",
        return_value=(advisory, "Groq answer"),
    ):
        interpreted = conversation_service.interpret_request(
            "Scan https://example.com using the passive profile",
            available_profiles=("passive",),
        )

    assert deterministic_intent("Scan https://example.com using the passive profile") == "scan"
    assert interpreted.intent == "scan"
    assert interpreted.profile == "passive"
