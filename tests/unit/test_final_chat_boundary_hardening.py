from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import Mock

from vulnhunter.web import ai_failover, conversation_service
from vulnhunter.web.conversation_threads import (
    DEFAULT_PROVIDER_PREFERENCE,
    _effective_provider,
    thread_preferences,
    thread_summary,
)
from vulnhunter.web.models import ConversationThread


def test_legacy_provider_preference_cannot_change_effective_route():
    assert _effective_provider("huggingface") == DEFAULT_PROVIDER_PREFERENCE
    assert _effective_provider("auto") == DEFAULT_PROVIDER_PREFERENCE


def test_thread_preferences_ignore_legacy_huggingface():
    thread = ConversationThread(provider_preference="huggingface")
    request = SimpleNamespace(vulnhunter_thread=thread)

    effort, provider = thread_preferences(request)

    assert effort == "high"
    assert provider == "groq"


def test_thread_summary_does_not_expose_provider_preference(monkeypatch):
    thread = ConversationThread(
        title="Legacy workspace",
        data={},
        provider_preference="huggingface",
    )
    thread.updated_at = datetime.now(UTC)
    monkeypatch.setattr(
        "vulnhunter.web.conversation_threads.workspace_url",
        lambda value: f"/workspace?thread={value.thread_id}",
    )

    payload = thread_summary(thread)

    assert "provider_preference" not in payload


def test_remote_router_ignores_legacy_huggingface_preference(monkeypatch):
    ai_failover.install()
    huggingface = Mock(side_effect=AssertionError("legacy provider must not be called"))
    monkeypatch.setattr(conversation_service, "_huggingface_advisory", huggingface)
    monkeypatch.setattr(
        conversation_service,
        "_groq_advisory",
        lambda text, **kwargs: (
            '{"message":"ok","recommended_profile":null,"model":"test"}',
            "ok",
        ),
    )
    monkeypatch.setattr(
        ai_failover,
        "_gemini_advisory",
        lambda *args, **kwargs: (None, "unused"),
    )
    monkeypatch.setattr(
        ai_failover,
        "_ollama_advisory",
        lambda *args, **kwargs: (None, "unused"),
    )

    advisory, detail, provider = conversation_service._remote_advisory(
        "hello",
        available_profiles=(),
        conversation_context=(),
        memory_summary="",
        tool_context="",
        reasoning_effort="high",
        provider_preference="huggingface",
    )

    assert advisory is not None
    assert detail == "AI reasoning completed."
    assert provider == "auto"
    huggingface.assert_not_called()


def test_workspace_runtime_status_hides_provider_inventory():
    ai_failover.install()

    status = conversation_service.advisory_runtime_status()

    assert "providers" not in status
    assert "model" not in status
    assert status["reasoning_effort"] == "high"
    assert status["provider_fallback_allowed"] is True
