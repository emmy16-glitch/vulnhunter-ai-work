from __future__ import annotations

import hashlib
import json
from pathlib import Path

import httpx

from vulnhunter.providers import (
    GroqProvider,
    ProviderCapability,
    ProviderInvocation,
    ProviderKind,
    ProviderOutputKind,
)


def test_conversation_direct_json_shape_is_wrapped_safely():
    def handler(request):
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "message": "A useful live answer.",
                                    "recommended_profile": "passive",
                                }
                            )
                        }
                    }
                ],
                "system_fingerprint": "phone-acceptance",
            },
        )

    content = "safe conversation"
    invocation = ProviderInvocation(
        invocation_id="phone-chat",
        request_id="phone-chat",
        provider=ProviderKind.GROQ_ADVISORY,
        model="openai/gpt-oss-120b",
        capability=ProviderCapability.CONVERSATION,
        input_sha256=hashlib.sha256(content.encode()).hexdigest(),
        maximum_output_tokens=128,
    )
    response = GroqProvider(
        api_key="gsk_test",
        transport=httpx.MockTransport(handler),
    ).invoke(invocation, content)

    assert response.output_kind == ProviderOutputKind.CANDIDATE_ANALYSIS
    assert json.loads(response.content) == {
        "message": "A useful live answer.",
        "recommended_profile": "passive",
    }
    assert response.trusted is False


def test_non_conversation_capability_keeps_strict_outer_schema():
    def handler(request):
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": '{"message":"not allowed"}'}}]},
        )

    content = "classification"
    invocation = ProviderInvocation(
        invocation_id="strict",
        request_id="strict",
        provider=ProviderKind.GROQ_ADVISORY,
        model="openai/gpt-oss-120b",
        capability=ProviderCapability.CLASSIFICATION,
        input_sha256=hashlib.sha256(content.encode()).hexdigest(),
        maximum_output_tokens=128,
    )
    response = GroqProvider(
        api_key="gsk_test",
        transport=httpx.MockTransport(handler),
    ).invoke(invocation, content)
    assert response.output_kind == ProviderOutputKind.ABSTAIN


def test_conversation_prompt_matches_the_provider_envelope():
    root = Path(__file__).resolve().parents[2]
    service = (root / "vulnhunter/web/conversation_service.py").read_text()

    assert "outer JSON object with output_kind and content" in service
    assert "Set output_kind to CANDIDATE_ANALYSIS" in service
    assert "Do not return message and recommended_profile as the outer object" in service


def test_phone_runtime_contracts_are_wired():
    root = Path(__file__).resolve().parents[2]
    start = (root / ".devcontainer/start-vulnhunter.sh").read_text()
    post_create = (root / ".devcontainer/post-create.sh").read_text()
    upload = (root / "vulnhunter/web/static/web/conversation-upload-coordinator.js").read_text()
    conversation = (root / "vulnhunter/web/static/web/conversation.js").read_text()
    template = (root / "vulnhunter/web/templates/web/conversation.html").read_text()
    upload_css = (root / "vulnhunter/web/static/web/background-uploads.css").read_text()

    assert "vh_verify_groq --conversation-smoke" in start
    assert "VULNHUNTER_GROQ_RUNTIME_VERIFIED=true" in start
    assert "VULNHUNTER_WEB_SECRET_KEY_FILE" in start
    assert "WEB_SECRET_KEY" in post_create
    assert "input[name='csrfmiddlewaretoken']" in upload
    assert "refreshSessionProtection" in upload
    assert "VulnHunterUploads = { enqueue, retry, cancel" in upload
    assert "Groq unavailable · deterministic fallback" in conversation
    assert "data-provider-runtime" in template
    assert "bottom: 14rem" in upload_css
