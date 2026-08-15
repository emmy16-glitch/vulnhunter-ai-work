from __future__ import annotations

from io import StringIO
from types import SimpleNamespace

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import override_settings

from vulnhunter.providers import ProviderKind, ProviderOutputKind
from vulnhunter.web.management.commands import vh_verify_groq


class _FakeGroqProvider:
    def __init__(self) -> None:
        self.invocation = None

    def health(self):
        return SimpleNamespace(
            reachable=True,
            model="openai/gpt-oss-120b",
            reason="ready",
        )

    def invoke(self, invocation, content: str):
        self.invocation = invocation
        assert "VULNHUNTER_GROQ_READY" in content
        return SimpleNamespace(
            output_kind=ProviderOutputKind.CANDIDATE_ANALYSIS,
            content="VULNHUNTER_GROQ_READY",
            model=invocation.model,
            trusted=False,
            safe_error=None,
        )


@override_settings(
    VULNHUNTER_GROQ_ENABLED=True,
    VULNHUNTER_GROQ_API_KEY_FILE="/tmp/not-read-by-the-test",
    VULNHUNTER_GROQ_API_BASE="https://api.groq.com/openai/v1",
    VULNHUNTER_GROQ_MODEL="openai/gpt-oss-120b",
    VULNHUNTER_GROQ_FALLBACK_MODEL="openai/gpt-oss-20b",
    VULNHUNTER_GROQ_TIMEOUT_SECONDS=30,
)
def test_verify_groq_uses_only_pinned_high_reasoning_model(monkeypatch) -> None:
    provider = _FakeGroqProvider()
    approved_models = None

    def fake_from_key_file(*args, **kwargs):
        nonlocal approved_models
        approved_models = kwargs["approved_models"]
        return provider

    monkeypatch.setattr(vh_verify_groq.GroqProvider, "from_key_file", fake_from_key_file)
    stdout = StringIO()

    call_command(
        "vh_verify_groq",
        model="openai/gpt-oss-120b",
        timeout=30,
        stdout=stdout,
    )

    assert approved_models == ("openai/gpt-oss-120b",)
    assert provider.invocation is not None
    assert provider.invocation.provider is ProviderKind.GROQ_ADVISORY
    assert provider.invocation.model == "openai/gpt-oss-120b"
    assert provider.invocation.reasoning_effort == "high"
    assert "Groq verified" in stdout.getvalue()


@override_settings(
    VULNHUNTER_GROQ_ENABLED=True,
    VULNHUNTER_GROQ_MODEL="openai/gpt-oss-120b",
    VULNHUNTER_GROQ_TIMEOUT_SECONDS=30,
)
def test_verify_groq_rejects_lower_model_before_provider_call(monkeypatch) -> None:
    called = False

    def fake_from_key_file(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("provider must not be created for a downgrade request")

    monkeypatch.setattr(vh_verify_groq.GroqProvider, "from_key_file", fake_from_key_file)

    with pytest.raises(CommandError, match="model downgrade is not allowed"):
        call_command(
            "vh_verify_groq",
            model="openai/gpt-oss-20b",
            timeout=30,
        )

    assert called is False
