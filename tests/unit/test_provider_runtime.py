import hashlib
import json
import threading

import httpx
import pytest
from pydantic import ValidationError

from vulnhunter.providers import (
    OllamaProvider,
    OllamaProviderError,
    ProviderCapability,
    ProviderInvocation,
    ProviderKind,
    ProviderOutputKind,
    ProviderRegistry,
    ProviderRequest,
    ProviderRuntime,
    ProviderRuntimeError,
)


def _invocation(content="safe evidence", **updates):
    values = {
        "invocation_id": "invoke-ollama",
        "request_id": "request-ollama",
        "provider": ProviderKind.LOCAL_OLLAMA,
        "model": "qwen3.5:2b-q4_k_m",
        "capability": ProviderCapability.REPOSITORY_NAVIGATION,
        "input_sha256": hashlib.sha256(content.encode()).hexdigest(),
    }
    values.update(updates)
    return ProviderInvocation(**values)


def _ollama_transport(output=None, *, seen=None):
    structured = output or {
        "output_kind": "CANDIDATE_ANALYSIS",
        "content": "Bounded candidate only.",
    }

    def handler(request):
        if request.url.path == "/api/version":
            return httpx.Response(200, json={"version": "0.31.2"})
        if request.url.path == "/api/tags":
            return httpx.Response(
                200,
                json={"models": [{"name": "qwen3.5:2b-q4_K_M", "digest": "sha256:model"}]},
            )
        if request.url.path == "/api/generate":
            body = json.loads(request.content)
            if seen is not None:
                seen.append(body)
            return httpx.Response(200, json={"response": json.dumps(structured)})
        raise AssertionError(f"unexpected Ollama path: {request.url.path}")

    return httpx.MockTransport(handler)


def test_provider_runtime_requires_explicit_connector_and_matching_route():
    registry = ProviderRegistry(local_enabled=True)
    request = ProviderRequest(
        request_id="request-01",
        purpose="Summarize bounded evidence for analyst review.",
        content="safe evidence",
    )
    invocation = ProviderInvocation(
        invocation_id="invoke-01",
        request_id="request-01",
        provider=ProviderKind.LOCAL_OLLAMA,
        model="qwen-local",
        capability=ProviderCapability.SUMMARIZATION,
        input_sha256=hashlib.sha256(request.content.encode()).hexdigest(),
    )
    with pytest.raises(ProviderRuntimeError, match="not activated"):
        ProviderRuntime(registry=registry).invoke(request, invocation)

    runtime = ProviderRuntime(
        registry=registry,
        connectors={ProviderKind.LOCAL_OLLAMA: lambda _invocation, content: content.upper()},
    )
    response = runtime.invoke(request, invocation)
    assert response.content == "SAFE EVIDENCE"
    assert response.trusted is False


def test_private_content_cannot_be_forced_to_remote_provider():
    registry = ProviderRegistry(local_enabled=False, groq_qwen_enabled=True)
    request = ProviderRequest(
        request_id="request-02",
        purpose="Analyze private repository source under policy.",
        content="private source code",
        contains_private_source=True,
    )
    invocation = ProviderInvocation(
        invocation_id="invoke-02",
        request_id="request-02",
        provider=ProviderKind.GROQ_QWEN,
        model="qwen-cloud",
        capability=ProviderCapability.REPOSITORY_NAVIGATION,
        input_sha256=hashlib.sha256(request.content.encode()).hexdigest(),
    )
    with pytest.raises(ProviderRuntimeError, match="denied"):
        ProviderRuntime(
            registry=registry,
            connectors={ProviderKind.GROQ_QWEN: lambda _invocation, content: content},
        ).invoke(request, invocation)


@pytest.mark.parametrize(
    "endpoint",
    ["http://example.test:11434", "https://127.0.0.1:11434", "http://user@127.0.0.1:11434"],
)
def test_ollama_accepts_only_plain_loopback_by_default(endpoint):
    with pytest.raises(OllamaProviderError):
        OllamaProvider(endpoint=endpoint)
    assert OllamaProvider(endpoint="http://localhost:11434").endpoint_classification == "loopback"


def test_ollama_health_lists_approved_model_without_inference_or_pull():
    seen_paths = []

    def handler(request):
        seen_paths.append((request.method, request.url.path))
        if request.url.path == "/api/version":
            return httpx.Response(200, json={"version": "0.31.2"})
        return httpx.Response(
            200,
            json={"models": [{"name": "qwen3.5:2b-q4_K_M", "digest": "sha256:model"}]},
        )

    health = OllamaProvider(transport=httpx.MockTransport(handler)).health()
    assert health.reachable is True
    assert health.model == "qwen3.5:2b-q4_K_M"
    assert health.model_digest == "sha256:model"
    assert seen_paths == [("GET", "/api/version"), ("GET", "/api/tags")]


def test_ollama_structured_output_remains_untrusted_and_has_no_tools():
    seen = []
    content = "safe evidence"
    provider = OllamaProvider(transport=_ollama_transport(seen=seen))
    response = provider.invoke(_invocation(content), content)
    assert response.output_kind == ProviderOutputKind.CANDIDATE_ANALYSIS
    assert response.trusted is False
    assert response.degraded is False
    assert response.provenance.model_digest == "sha256:model"
    assert response.provenance.input_sha256 == hashlib.sha256(content.encode()).hexdigest()
    assert len(seen) == 1
    assert "tools" not in seen[0]
    assert "tool_choice" not in seen[0]
    assert seen[0]["model"] == "qwen3.5:2b-q4_k_m"
    assert seen[0]["think"] is False
    assert seen[0]["options"]["num_ctx"] == 1_024


def test_ollama_rejects_unapproved_model_and_oversized_prompt():
    provider = OllamaProvider(transport=_ollama_transport())
    with pytest.raises(OllamaProviderError, match="allowlist"):
        provider.invoke(_invocation(model="other:latest"), "safe evidence")
    content = "x" * 20
    with pytest.raises(OllamaProviderError, match="byte limit"):
        provider.invoke(_invocation(content, maximum_input_bytes=10), content)


def test_ollama_timeout_and_unavailable_endpoint_abstain_deterministically():
    def timeout_handler(request):
        if request.url.path == "/api/generate":
            raise httpx.ReadTimeout("bounded timeout", request=request)
        return _ollama_transport().handle_request(request)

    response = OllamaProvider(transport=httpx.MockTransport(timeout_handler)).invoke(
        _invocation(), "safe evidence"
    )
    assert response.output_kind == ProviderOutputKind.ABSTAIN
    assert response.provenance.timed_out is True
    assert response.trusted is False

    def unavailable(request):
        raise httpx.ConnectError("offline", request=request)

    response = OllamaProvider(transport=httpx.MockTransport(unavailable)).invoke(
        _invocation(), "safe evidence"
    )
    assert response.output_kind == ProviderOutputKind.ABSTAIN
    assert response.degraded is True


def test_ollama_cancellation_abstains_without_network_request():
    calls = []
    event = threading.Event()
    event.set()
    provider = OllamaProvider(transport=_ollama_transport(seen=calls))
    response = provider.invoke(_invocation(), "safe evidence", cancelled=event.is_set)
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
def test_ollama_invalid_schema_fails_closed_as_abstain(structured):
    response = OllamaProvider(transport=_ollama_transport(output=structured)).invoke(
        _invocation(), "safe evidence"
    )
    assert response.output_kind == ProviderOutputKind.ABSTAIN
    assert response.degraded is True
    assert response.trusted is False


def test_ollama_oversized_output_is_rejected():
    response = OllamaProvider(
        transport=_ollama_transport(output={"output_kind": "PROPOSAL", "content": "x" * 200})
    ).invoke(_invocation(maximum_output_bytes=20), "safe evidence")
    assert response.output_kind == ProviderOutputKind.ABSTAIN
    assert response.degraded is True


def test_provider_runtime_validates_input_binding_and_carries_structured_response():
    content = "safe evidence"
    request = ProviderRequest(
        request_id="request-ollama",
        purpose="Analyze bounded local repository evidence.",
        content=content,
    )
    runtime = ProviderRuntime(
        registry=ProviderRegistry(local_enabled=True),
        connectors={ProviderKind.LOCAL_OLLAMA: OllamaProvider(transport=_ollama_transport())},
    )
    response = runtime.invoke(request, _invocation(content))
    assert response.output_kind == ProviderOutputKind.CANDIDATE_ANALYSIS
    with pytest.raises(ProviderRuntimeError, match="input binding"):
        runtime.invoke(request, _invocation(content, input_sha256="0" * 64))


def test_provider_response_cannot_be_marked_trusted():
    from vulnhunter.providers import ProviderResponse

    with pytest.raises(ValidationError, match="never be marked trusted"):
        ProviderResponse(
            invocation_id="invoke-01",
            provider=ProviderKind.LOCAL_OLLAMA,
            model="qwen3.5:2b-q4_k_m",
            content="candidate",
            output_sha256=hashlib.sha256(b"candidate").hexdigest(),
            trusted=True,
        )
