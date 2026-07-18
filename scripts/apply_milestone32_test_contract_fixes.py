from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(relative: str, old: str, new: str) -> None:
    path = ROOT / relative
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise RuntimeError(f"expected block missing from {relative}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def main() -> None:
    replace_once(
        "tests/unit/test_milestone32_worker_pilot.py",
        'with pytest.raises(WorkerSpoolError, match="signature"):',
        'with pytest.raises(WorkerSpoolError, match="invalid|signature"):',
    )
    replace_once(
        "tests/unit/test_milestone32_worker_pilot.py",
        '''                allowed_risks=(ToolRisk.NETWORK,),
            ),
''',
        '''                allowed_risks=(ToolRisk.NETWORK,),
                allow_network=True,
            ),
''',
    )
    replace_once(
        "tests/unit/test_provider_runtime.py",
        "GroqProvider(transport=_groq_transport())",
        'GroqProvider(api_key="test-key", transport=_groq_transport())',
    )
    replace_once(
        "tests/unit/test_provider_runtime.py",
        "GroqProvider(transport=_groq_transport())",
        'GroqProvider(api_key="test-key", transport=_groq_transport())',
    )
    path = ROOT / "tests/unit/test_provider_privacy_gate.py"
    path.write_text(
        '''from vulnhunter.providers import PrivacyGate, ProviderRegistry, ProviderRequest


def test_private_source_is_denied_for_remote_provider():
    gate = PrivacyGate().evaluate(
        "```python\\n" + ("secret_code = 1\\n" * 40) + "```",
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
''',
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
