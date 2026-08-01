from __future__ import annotations

import json
from io import StringIO
from types import SimpleNamespace

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError

from vulnhunter.web.management.commands import vh_verify_llm


def _interpreted(
    *,
    provider: str = "groq",
    model: str | None = "openai/gpt-oss-20b",
    answer: str = "VULNHUNTER_LLM_READY",
    detail: str = "Groq model: openai/gpt-oss-20b",
):
    return SimpleNamespace(
        provider=provider,
        model=model,
        assistant_copy=answer,
        provider_detail=detail,
        reasoning_effort="low",
    )


def test_verify_llm_uses_exact_conversation_path_and_emits_json(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_interpret_request(text: str, **kwargs):
        captured["text"] = text
        captured.update(kwargs)
        return _interpreted(provider="huggingface", model="openai/gpt-oss-20b:groq")

    monkeypatch.setattr(vh_verify_llm, "interpret_request", fake_interpret_request)
    stdout = StringIO()

    call_command(
        "vh_verify_llm",
        provider="huggingface",
        reasoning="low",
        json_output=True,
        stdout=stdout,
    )

    payload = json.loads(stdout.getvalue())
    assert payload == {
        "detail": "Groq model: openai/gpt-oss-20b",
        "model": "openai/gpt-oss-20b:groq",
        "provider": "huggingface",
        "ready": True,
        "reasoning_effort": "low",
    }
    assert "VULNHUNTER_LLM_READY" in str(captured["text"])
    assert captured["provider_preference"] == "huggingface"
    assert captured["reasoning_effort"] == "low"
    assert captured["available_profiles"] == ("passive",)


def test_verify_llm_fails_when_only_deterministic_fallback_answers(monkeypatch) -> None:
    monkeypatch.setattr(
        vh_verify_llm,
        "interpret_request",
        lambda *args, **kwargs: _interpreted(
            provider="deterministic",
            model=None,
            answer="Local fallback answer",
            detail="Groq is disabled. Hugging Face token is missing.",
        ),
    )

    with pytest.raises(CommandError, match="No configured remote LLM"):
        call_command("vh_verify_llm", provider="auto", reasoning="low")


def test_verify_llm_fails_when_requested_provider_is_not_used(monkeypatch) -> None:
    monkeypatch.setattr(
        vh_verify_llm,
        "interpret_request",
        lambda *args, **kwargs: _interpreted(provider="groq"),
    )

    with pytest.raises(CommandError, match="requested huggingface provider was not used"):
        call_command("vh_verify_llm", provider="huggingface", reasoning="low")


def test_verify_llm_fails_when_answer_misses_marker(monkeypatch) -> None:
    monkeypatch.setattr(
        vh_verify_llm,
        "interpret_request",
        lambda *args, **kwargs: _interpreted(answer="Provider answered without the marker"),
    )

    with pytest.raises(CommandError, match="missed the readiness marker"):
        call_command("vh_verify_llm", provider="groq", reasoning="low")
