"""Provider selection without network execution or secret handling."""

from __future__ import annotations

from vulnhunter.providers.models import ProviderKind, ProviderRequest, ProviderRoute
from vulnhunter.providers.privacy import PrivacyGate


class ProviderRegistry:
    def __init__(
        self,
        *,
        local_enabled: bool = True,
        groq_qwen_enabled: bool = False,
        compound_mini_enabled: bool = False,
    ) -> None:
        self.local_enabled = local_enabled
        self.groq_qwen_enabled = groq_qwen_enabled
        self.compound_mini_enabled = compound_mini_enabled
        self.privacy_gate = PrivacyGate()

    def route(self, request: ProviderRequest) -> ProviderRoute:
        if self.local_enabled:
            return ProviderRoute(
                provider=ProviderKind.LOCAL_OLLAMA,
                allowed=True,
                reason="Local Ollama is the primary provider.",
                redacted_content=request.content,
            )

        gate = self.privacy_gate.evaluate(
            request.content,
            contains_private_source=request.contains_private_source,
            contains_customer_data=request.contains_customer_data,
        )
        if self.groq_qwen_enabled and gate.allowed_for_remote:
            return ProviderRoute(
                provider=ProviderKind.GROQ_QWEN,
                allowed=True,
                reason=gate.reason,
                redacted_content=gate.redacted_content,
            )
        if (
            self.compound_mini_enabled
            and request.allow_current_public_information
            and gate.allowed_for_remote
        ):
            return ProviderRoute(
                provider=ProviderKind.GROQ_COMPOUND_MINI,
                allowed=True,
                reason="Approved public-information lookup passed the privacy gate.",
                redacted_content=gate.redacted_content,
            )
        return ProviderRoute(
            provider=ProviderKind.LOCAL_OLLAMA,
            allowed=False,
            reason="No permitted provider is available.",
            redacted_content=None,
        )
