from vulnhunter.providers import PrivacyGate, ProviderRegistry, ProviderRequest


def test_private_source_is_denied_for_remote_provider():
    gate = PrivacyGate().evaluate(
        "```python\n" + ("secret_code = 1\n" * 40) + "```",
        contains_private_source=True,
        contains_customer_data=False,
    )
    assert gate.allowed_for_remote is False


def test_groq_advisory_is_disabled_by_default():
    route = ProviderRegistry().route(
        ProviderRequest(
            request_id="provider-01",
            purpose="Summarise sanitized public evidence for a reviewer.",
            content="Safe sanitized evidence summary.",
        )
    )
    assert route.allowed is False
    assert route.provider.value == "groq_advisory"
    assert "disabled" in route.reason.lower()
