import hashlib
import json

import httpx
import pytest

from vulnhunter.providers import (
    GroqProvider,
    GroqProviderError,
    ProviderCapability,
    ProviderInvocation,
    ProviderKind,
    ProviderOutputKind,
    load_groq_api_key_file,
)


def _invocation(content="safe public evidence", **updates):
    values = {
        "invocation_id": "invoke-groq",
        "request_id": "request-groq",
        "provider": ProviderKind.GROQ_ADVISORY,
        "model": "openai/gpt-oss-120b",
        "capability": ProviderCapability.CLASSIFICATION,
        "input_sha256": hashlib.sha256(content.encode()).hexdigest(),
        "maximum_output_tokens": 96,
    }
    values.update(updates)
    return ProviderInvocation(**values)


def _transport(*, output=None, status=200, seen=None):
    structured = output or {
        "output_kind": "CANDIDATE_ANALYSIS",
        "content": "Bounded Groq candidate.",
    }

    def handler(request):
        if request.url.path == "/openai/v1/models":
            return httpx.Response(200, json={"data": [{"id": "openai/gpt-oss-120b"}]})
        if request.url.path == "/openai/v1/chat/completions":
            if seen is not None:
                seen.append(json.loads(request.content))
            if status != 200:
                return httpx.Response(status, json={"error": {"message": "bounded failure"}})
            return httpx.Response(
                200,
                json={
                    "choices": [{"message": {"content": json.dumps(structured)}}],
                    "system_fingerprint": "groq-test",
                },
            )
        raise AssertionError(f"unexpected Groq path: {request.url.path}")

    return httpx.MockTransport(handler)


def test_key_file_requires_owner_private_regular_file(tmp_path):
    key = tmp_path / "groq.key"
    key.write_text("gsk_test_value", encoding="utf-8")
    key.chmod(0o644)
    with pytest.raises(GroqProviderError, match="permissions"):
        load_groq_api_key_file(key)
    key.chmod(0o600)
    assert load_groq_api_key_file(key) == "gsk_test_value"

    link = tmp_path / "link"
    link.symlink_to(key)
    with pytest.raises(GroqProviderError, match="symbolic link"):
        load_groq_api_key_file(link)


def test_groq_accepts_only_official_https_api_base():
    with pytest.raises(GroqProviderError):
        GroqProvider(api_key="gsk_test", api_base="http://api.groq.com/openai/v1")
    with pytest.raises(GroqProviderError):
        GroqProvider(api_key="gsk_test", api_base="https://example.test/openai/v1")
    assert GroqProvider(api_key="gsk_test").api_base == "https://api.groq.com/openai/v1"


def test_groq_health_checks_inventory_without_inference():
    seen = []

    def handler(request):
        seen.append((request.method, request.url.path))
        return httpx.Response(200, json={"data": [{"id": "openai/gpt-oss-120b"}]})

    health = GroqProvider(api_key="gsk_test", transport=httpx.MockTransport(handler)).health()
    assert health.reachable is True
    assert health.model == "openai/gpt-oss-120b"
    assert seen == [("GET", "/openai/v1/models")]


def test_groq_structured_output_is_advisory_and_has_no_tools():
    seen = []
    provider = GroqProvider(api_key="gsk_test", transport=_transport(seen=seen))
    response = provider.invoke(_invocation(), "safe public evidence")
    assert response.output_kind == ProviderOutputKind.CANDIDATE_ANALYSIS
    assert response.trusted is False
    assert response.provenance.endpoint_classification == "remote_groqcloud"
    assert len(seen) == 1
    body = seen[0]
    assert "tools" not in body
    assert "tool_choice" not in body
    assert body["include_reasoning"] is False
    assert body["reasoning_effort"] == "low"
    assert body["response_format"] == {"type": "json_object"}
    assert body["model"] == "openai/gpt-oss-120b"


def test_groq_rejects_unapproved_model_and_oversized_input():
    provider = GroqProvider(api_key="gsk_test", transport=_transport())
    with pytest.raises(GroqProviderError, match="allowlist"):
        provider.invoke(_invocation(model="other-model"), "safe public evidence")
    content = "x" * 20
    with pytest.raises(GroqProviderError, match="byte limit"):
        provider.invoke(_invocation(content, maximum_input_bytes=10), content)


@pytest.mark.parametrize("status", [400, 401, 429, 500])
def test_groq_http_failures_abstain(status):
    response = GroqProvider(api_key="gsk_test", transport=_transport(status=status)).invoke(
        _invocation(), "safe public evidence"
    )
    assert response.output_kind == ProviderOutputKind.ABSTAIN
    assert response.trusted is False
    assert response.degraded is True
    if status == 400:
        assert "bounded failure" in (response.safe_error or "")
    assert "gsk_test" not in (response.safe_error or "")


def test_groq_invalid_schema_abstains():
    response = GroqProvider(
        api_key="gsk_test",
        transport=_transport(output={"output_kind": "VERIFIED", "content": "bad"}),
    ).invoke(_invocation(), "safe public evidence")
    assert response.output_kind == ProviderOutputKind.ABSTAIN
    assert response.trusted is False


def test_groq_key_is_not_written_to_provenance_or_response():
    secret = "gsk_do_not_expose"
    response = GroqProvider(api_key=secret, transport=_transport()).invoke(
        _invocation(), "safe public evidence"
    )
    serialized = response.model_dump_json()
    assert secret not in serialized
