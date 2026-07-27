import hashlib
import json

import httpx
import pytest

from vulnhunter.providers import (
    HuggingFaceProvider,
    HuggingFaceProviderError,
    ProviderCapability,
    ProviderInvocation,
    ProviderKind,
    ProviderOutputKind,
    load_huggingface_token_file,
)


def _invocation(**updates):
    content = "safe public evidence"
    values = {
        "invocation_id": "invoke-huggingface",
        "request_id": "request-huggingface",
        "provider": ProviderKind.HUGGINGFACE_ADVISORY,
        "model": "openai/gpt-oss-120b:groq",
        "capability": ProviderCapability.CONVERSATION,
        "input_sha256": hashlib.sha256(content.encode()).hexdigest(),
        "maximum_output_tokens": 256,
        "reasoning_effort": "high",
    }
    values.update(updates)
    return ProviderInvocation(**values)


def _transport(seen):
    def handler(request):
        assert request.url.path == "/v1/chat/completions"
        seen.append(json.loads(request.content))
        structured = {
            "output_kind": "CANDIDATE_ANALYSIS",
            "content": json.dumps(
                {"message": "Deep evidence-bound answer.", "recommended_profile": None}
            ),
        }
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": json.dumps(structured)}}]},
        )

    return httpx.MockTransport(handler)


def test_huggingface_token_file_is_owner_private(tmp_path):
    token = tmp_path / "hf-token"
    token.write_text("hf_test_token_value_123456", encoding="utf-8")
    token.chmod(0o644)
    with pytest.raises(HuggingFaceProviderError, match="permissions"):
        load_huggingface_token_file(token)
    token.chmod(0o600)
    assert load_huggingface_token_file(token) == "hf_test_token_value_123456"


def test_huggingface_accepts_only_official_router():
    with pytest.raises(HuggingFaceProviderError):
        HuggingFaceProvider(
            token="hf_test_token_value_123456",
            approved_models=("openai/gpt-oss-120b:groq",),
            api_base="https://example.test/v1",
        )


def test_huggingface_forwards_reasoning_and_keeps_output_advisory():
    seen = []
    provider = HuggingFaceProvider(
        token="hf_test_token_value_123456",
        approved_models=("openai/gpt-oss-120b:groq",),
        transport=_transport(seen),
    )
    response = provider.invoke(_invocation(), "safe public evidence")
    assert response.output_kind == ProviderOutputKind.CANDIDATE_ANALYSIS
    assert response.trusted is False
    assert seen[0]["reasoning_effort"] == "high"
    assert seen[0]["model"] == "openai/gpt-oss-120b:groq"
    assert "tools" not in seen[0]
