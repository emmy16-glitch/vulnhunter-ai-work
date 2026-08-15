from __future__ import annotations

from io import StringIO
from types import SimpleNamespace

from django.core.management import call_command
from django.test import override_settings

from vulnhunter.providers import ProviderKind, ProviderOutputKind
from vulnhunter.web import conversation_service
from vulnhunter.web.management.commands import vh_verify_huggingface


class _FakeHuggingFaceProvider:
    def __init__(self) -> None:
        self.invocation = None

    def invoke(self, invocation, content: str):
        self.invocation = invocation
        assert "VULNHUNTER_HUGGINGFACE_READY" in content
        return SimpleNamespace(
            output_kind=ProviderOutputKind.CANDIDATE_ANALYSIS,
            content="VULNHUNTER_HUGGINGFACE_READY",
            model=invocation.model,
            trusted=False,
            safe_error=None,
        )


@override_settings(
    VULNHUNTER_HUGGINGFACE_ENABLED=True,
    VULNHUNTER_HUGGINGFACE_TOKEN_FILE="/tmp/not-read-by-the-test",
    VULNHUNTER_HUGGINGFACE_API_BASE="https://router.huggingface.co/v1",
    VULNHUNTER_HUGGINGFACE_MODEL="openai/gpt-oss-120b:groq",
    VULNHUNTER_HUGGINGFACE_FALLBACK_MODEL="openai/gpt-oss-20b:groq",
    VULNHUNTER_HUGGINGFACE_TIMEOUT_SECONDS=30,
)
def test_verify_huggingface_requires_exact_conversation_smoke(monkeypatch) -> None:
    provider = _FakeHuggingFaceProvider()
    monkeypatch.setattr(
        vh_verify_huggingface.HuggingFaceProvider,
        "from_token_file",
        lambda *args, **kwargs: provider,
    )
    monkeypatch.setattr(
        conversation_service,
        "interpret_request",
        lambda *args, **kwargs: SimpleNamespace(
            provider="huggingface",
            model="openai/gpt-oss-120b:groq",
            assistant_copy="VULNHUNTER_CHAT_READY",
            provider_detail="Hugging Face high-reasoning model: openai/gpt-oss-120b:groq",
        ),
    )
    stdout = StringIO()

    call_command(
        "vh_verify_huggingface",
        model="openai/gpt-oss-120b:groq",
        timeout=30,
        stdout=stdout,
    )

    assert provider.invocation is not None
    assert provider.invocation.provider is ProviderKind.HUGGINGFACE_ADVISORY
    assert provider.invocation.reasoning_effort == "high"
    assert "conversation=ready" in stdout.getvalue()
