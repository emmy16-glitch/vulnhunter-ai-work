"""Groq selection without secret handling or authority transfer."""

from __future__ import annotations

from vulnhunter.providers.models import ProviderKind, ProviderRequest, ProviderRoute
from vulnhunter.providers.privacy import PrivacyGate


class ProviderRegistry:
    def __init__(self, *, groq_enabled: bool = False) -> None:
        self.groq_enabled = groq_enabled
        self.privacy_gate = PrivacyGate()

    def route(self, request: ProviderRequest) -> ProviderRoute:
        gate = self.privacy_gate.evaluate(
            request.content,
            contains_private_source=request.contains_private_source,
            contains_customer_data=request.contains_customer_data,
            remote_source_processing_approved=request.remote_source_processing_approved,
        )
        if not gate.allowed_for_remote:
            return ProviderRoute(
                provider=ProviderKind.GROQ_ADVISORY,
                allowed=False,
                reason=gate.reason,
                redacted_content=None,
            )
        if not self.groq_enabled:
            return ProviderRoute(
                provider=ProviderKind.GROQ_ADVISORY,
                allowed=False,
                reason="Groq analysis is disabled by configuration.",
                redacted_content=None,
            )
        return ProviderRoute(
            provider=ProviderKind.GROQ_ADVISORY,
            allowed=True,
            reason=gate.reason,
            redacted_content=gate.redacted_content,
        )
