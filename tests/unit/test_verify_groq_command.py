from __future__ import annotations

from io import StringIO
from types import SimpleNamespace

from django.core.management import call_command
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
def test_verify_groq_uses_model_neutral_provider_identity(monkeypatch) -> None:
    provider = _FakeGroqProvider()
    monkeypatch.setattr(
        vh_verify_groq.GroqProvider,
        "from_key_file",
        lambda *args, **kwargs: provider,
    )
    stdout = StringIO()

    call_command(
        "vh_verify_groq",
        model="openai/gpt-oss-120b",
        timeout=30,
        stdout=stdout,
    )

    assert provider.invocation is not None
    assert provider.invocation.provider is ProviderKind.GROQ_ADVISORY
    assert "Groq verified" in stdout.getvalue()
