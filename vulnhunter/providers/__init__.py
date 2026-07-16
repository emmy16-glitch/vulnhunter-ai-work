"""Local-first AI provider routing contracts."""

from vulnhunter.providers.groq import GroqProvider, GroqProviderError, load_groq_api_key_file
from vulnhunter.providers.hybrid import (
    HybridProviderCoordinator,
    HybridReviewDisposition,
    HybridReviewResult,
    HybridRoutePlan,
    HybridRoutingMode,
)
from vulnhunter.providers.models import (
    ProviderCapability,
    ProviderHealth,
    ProviderInvocation,
    ProviderKind,
    ProviderOutputKind,
    ProviderProvenance,
    ProviderRequest,
    ProviderResponse,
    ProviderRoute,
)
from vulnhunter.providers.ollama import OllamaProvider, OllamaProviderError
from vulnhunter.providers.privacy import PrivacyGate
from vulnhunter.providers.registry import ProviderRegistry
from vulnhunter.providers.runtime import ProviderRuntime, ProviderRuntimeError

__all__ = [
    "load_groq_api_key_file",
    "GroqProviderError",
    "GroqProvider",
    "HybridProviderCoordinator",
    "HybridReviewDisposition",
    "HybridReviewResult",
    "HybridRoutePlan",
    "HybridRoutingMode",
    "PrivacyGate",
    "OllamaProvider",
    "OllamaProviderError",
    "ProviderCapability",
    "ProviderHealth",
    "ProviderInvocation",
    "ProviderKind",
    "ProviderOutputKind",
    "ProviderProvenance",
    "ProviderRegistry",
    "ProviderRequest",
    "ProviderResponse",
    "ProviderRoute",
    "ProviderRuntime",
    "ProviderRuntimeError",
]
