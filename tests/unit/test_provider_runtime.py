import hashlib
import json
import threading

import httpx
import pytest
from pydantic import ValidationError

from vulnhunter.providers import (
    GroqProvider,
    GroqProviderError,
    ProviderCapability,
    ProviderInvocation,
    ProviderKind,
    ProviderOutputKind,
    ProviderRegistry,
    ProviderRequest,
    ProviderResponse,
    ProviderRuntime,
    ProviderRuntimeError,
)


def _invocation(content="safe public evidence", **updates):
    values = {
        "invocation_id": "invoke-groq",
        "request_id": "request-groq",
        "provider": ProviderKind.GROQ_ADVISORY,
        "model": "openai/gpt-oss-120b",
        "capability": ProviderCapability.CLASSIFICATION,
        "input_sha256": hashlib.sha256(content.encode()).hexdigest(),
    }
    values.update(updates)
    return ProviderInvocation(**values)


def _groq_transport(output=None, *, seen=None):
    structured = output or {
        "output_kind": "CANDIDATE_ANALYSIS",
        "content": "Bounded advisory candidate only.",
    }

    def handler(request):
        if request.url.path == "/openai/v1/models":
            return httpx.Response(200, json={"data": [{"id": "openai/gpt-oss-120b"}]})
        if request.url.path == "/openai/v1/chat/completions":
            body = json.loads(request.content)
            if seen is not None:
                seen.append(body)
            return httpx.Response(
                200,
                json={
                    "choices": [{"message": {"content": json.dumps(structured)}}],
                    "system_fingerprint": "groq-test",
                },
            )
        raise AssertionError(f"unexpected Groq path: {request.url.path}")

    return httpx.MockTransport(handler)


def test_provider_runtime_requires_explicit_groq_activation_and_matching_route():
    registry = ProviderRegistry(groq_enabled=True)
    request = ProviderRequest(
        request_id="request-groq",
        purpose="Classify sanitized public evidence for analyst review.",
        content="safe public evidence",
    )
    invocation = _invocation(request.content)
    with pytest.raises(ProviderRuntimeError, match="not activated"):
        ProviderRuntime(registry=registry).invoke(request, invocation)

    runtime = ProviderRuntime(
        registry=registry,
        connectors={ProviderKind.GROQ_ADVISORY: GroqProvider(api_key="test-key", transport=_groq_transport())},
    )
    response = runtime.invoke(request, invocation)
    assert response.output_kind == ProviderOutputKind.CANDIDATE_ANALYSIS
    assert response.trusted is False


def test_private_content_cannot_be_forced_to_groq():
    request = ProviderRequest(
        request_id="request-groq",
        purpose="Analyze private repository source under policy.",
        content="private source code",
        contains_private_source=True,
    )
    with pytest.raises(ProviderRuntimeError, match="denied"):
        ProviderRuntime(
            registry=ProviderRegistry(groq_enabled=True),
            connectors={ProviderKind.GROQ_ADVISORY: GroqProvider(api_key="test-key", transport=_groq_transport())},
        ).invoke(request, _invocation(request.content))


def test_groq_accepts_only_the_official_https_api_base():
    for endpoint in (
        "http://api.groq.com/openai/v1",
        "https://example.test/openai/v1",
        "https://user@api.groq.com/openai/v1",
    ):
        with pytest.raises(GroqProviderError):
            GroqProvider(api_key="test-key", api_base=endpoint)


def test_groq_health_checks_only_the_approved_model_inventory():
    provider = GroqProvider(api_key="test-key", transport=_groq_transport())
    health = provider.health()
    assert health.reachable is True
    assert health.model == "openai/gpt-oss-120b"
    assert health.endpoint_classification == "remote_groqcloud"


def test_groq_structured_output_is_untrusted_and_has_no_tool_access():
    seen = []
    provider = GroqProvider(api_key="test-key", transport=_groq_transport(seen=seen))
    response = provider.invoke(_invocation(), "safe public evidence")
    assert response.output_kind == ProviderOutputKind.CANDIDATE_ANALYSIS
    assert response.trusted is False
    assert response.degraded is False
    assert len(seen) == 1
    assert "tools" not in seen[0]
    assert "tool_choice" not in seen[0]
    assert seen[0]["model"] == "openai/gpt-oss-120b"
    assert seen[0]["stream"] is False


def test_groq_rejects_unapproved_model_and_oversized_prompt():
    provider = GroqProvider(api_key="test-key", transport=_groq_transport())
    with pytest.raises(GroqProviderError, match="allowlist"):
        provider.invoke(_invocation(model="other-model"), "safe public evidence")
    content = "x" * 20
    with pytest.raises(GroqProviderError, match="byte limit"):
        provider.invoke(_invocation(content, maximum_input_bytes=10), content)


def test_groq_timeout_and_cancellation_abstain_without_authority():
    def timeout_handler(request):
        if request.url.path.endswith("/chat/completions"):
            raise httpx.ReadTimeout("bounded timeout", request=request)
        return _groq_transport().handle_request(request)

    response = GroqProvider(
        api_key="test-key",
        transport=httpx.MockTransport(timeout_handler),
    ).invoke(_invocation(), "safe public evidence")
    assert response.output_kind == ProviderOutputKind.ABSTAIN
    assert response.provenance.timed_out is True
    assert response.trusted is False

    calls = []
    event = threading.Event()
    event.set()
    response = GroqProvider(
        api_key="test-key",
        transport=_groq_transport(seen=calls),
    ).invoke(_invocation(), "safe public evidence", cancelled=event.is_set)
    assert response.output_kind == ProviderOutputKind.ABSTAIN
    assert response.provenance.cancelled is True
    assert calls == []


@pytest.mark.parametrize(
    "structured",
    [
        {"output_kind": "VERIFIED", "content": "invalid authority"},
        {"output_kind": "PROPOSAL", "content": "candidate", "tools": ["shell"]},
        {"content": "missing classification"},
    ],
)
def test_groq_invalid_schema_fails_closed_as_abstain(structured):
    response = GroqProvider(
        api_key="test-key",
        transport=_groq_transport(output=structured),
    ).invoke(_invocation(), "safe public evidence")
    assert response.output_kind == ProviderOutputKind.ABSTAIN
    assert response.degraded is True
    assert response.trusted is False


def test_provider_runtime_validates_sanitized_input_binding():
    content = "safe public evidence"
    request = ProviderRequest(
        request_id="request-groq",
        purpose="Analyze bounded sanitized evidence.",
        content=content,
    )
    runtime = ProviderRuntime(
        registry=ProviderRegistry(groq_enabled=True),
        connectors={ProviderKind.GROQ_ADVISORY: GroqProvider(transport=_groq_transport())},
    )
    assert runtime.invoke(request, _invocation(content)).trusted is False
    with pytest.raises(ProviderRuntimeError, match="input binding"):
        runtime.invoke(request, _invocation(content, input_sha256="0" * 64))


def test_provider_response_cannot_be_marked_trusted():
    with pytest.raises(ValidationError, match="never be marked trusted"):
        ProviderResponse(
            invocation_id="invoke-groq",
            provider=ProviderKind.GROQ_ADVISORY,
            model="openai/gpt-oss-120b",
            content="candidate",
            output_sha256=hashlib.sha256(b"candidate").hexdigest(),
            trusted=True,
        )
