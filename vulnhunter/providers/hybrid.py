"""Fail-closed hybrid local/cloud review contracts.

This module plans provider use but performs no network request and never reads a
credential. Local and remote model output remains advisory.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from vulnhunter.providers.models import (
    ProviderKind,
    ProviderOutputKind,
    ProviderRequest,
    ProviderResponse,
)
from vulnhunter.providers.privacy import PrivacyGate


class HybridRoutingMode(StrEnum):
    LOCAL_ONLY = "LOCAL_ONLY"
    LOCAL_THEN_GROQ = "LOCAL_THEN_GROQ"
    DUAL_REVIEW = "DUAL_REVIEW"


class HybridReviewDisposition(StrEnum):
    LOCAL_CANDIDATE = "LOCAL_CANDIDATE"
    AGREEMENT_IS_STILL_UNVERIFIED = "AGREEMENT_IS_STILL_UNVERIFIED"
    DISAGREEMENT_REQUIRES_HUMAN = "DISAGREEMENT_REQUIRES_HUMAN"
    ABSTAIN = "ABSTAIN"


class HybridRoutePlan(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    mode: HybridRoutingMode
    local_provider: ProviderKind = ProviderKind.LOCAL_OLLAMA
    remote_provider: ProviderKind | None = None
    remote_permitted: bool = False
    reason: str
    sanitized_remote_content: str | None = None
    trusted: bool = False


class HybridReviewResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    disposition: HybridReviewDisposition
    reason: str
    local_output_sha256: str | None = None
    remote_output_sha256: str | None = None
    trusted: bool = False


class HybridProviderCoordinator:
    """Plan Qwen/Groq use without authorizing either provider.

    Groq is considered only after explicit policy permission and deterministic
    privacy screening. This coordinator never loads a key or invokes a model.
    """

    def __init__(
        self,
        *,
        mode: HybridRoutingMode = HybridRoutingMode.LOCAL_ONLY,
        groq_enabled: bool = False,
    ) -> None:
        self.mode = mode
        self.groq_enabled = groq_enabled
        self.privacy_gate = PrivacyGate()

    def plan(
        self,
        request: ProviderRequest,
        *,
        local_response: ProviderResponse | None = None,
        policy_allows_remote: bool = False,
    ) -> HybridRoutePlan:
        if self.mode == HybridRoutingMode.LOCAL_ONLY:
            return HybridRoutePlan(
                mode=self.mode,
                reason="Sensitive-by-default local-only routing is active.",
            )

        if self.mode == HybridRoutingMode.LOCAL_THEN_GROQ:
            if local_response is None:
                return HybridRoutePlan(
                    mode=self.mode,
                    reason="Run the bounded local provider first.",
                )
            if local_response.output_kind != ProviderOutputKind.ABSTAIN:
                return HybridRoutePlan(
                    mode=self.mode,
                    reason="A bounded local candidate exists; cloud escalation is unnecessary.",
                )

        if not policy_allows_remote:
            return HybridRoutePlan(
                mode=self.mode,
                reason="Remote provider use was not approved by policy.",
            )

        gate = self.privacy_gate.evaluate(
            request.content,
            contains_private_source=request.contains_private_source,
            contains_customer_data=request.contains_customer_data,
        )
        if not gate.allowed_for_remote:
            return HybridRoutePlan(mode=self.mode, reason=gate.reason)
        if not self.groq_enabled:
            return HybridRoutePlan(
                mode=self.mode,
                reason="Groq contracts are present, but network execution is disabled.",
            )
        return HybridRoutePlan(
            mode=self.mode,
            remote_provider=ProviderKind.GROQ_QWEN,
            remote_permitted=True,
            sanitized_remote_content=gate.redacted_content,
            reason="Remote review passed explicit policy and deterministic privacy gates.",
        )

    @staticmethod
    def compare(
        local_response: ProviderResponse,
        remote_response: ProviderResponse | None,
    ) -> HybridReviewResult:
        if remote_response is None:
            if local_response.output_kind == ProviderOutputKind.ABSTAIN:
                return HybridReviewResult(
                    disposition=HybridReviewDisposition.ABSTAIN,
                    reason="The local provider abstained and no remote review exists.",
                    local_output_sha256=local_response.output_sha256,
                )
            return HybridReviewResult(
                disposition=HybridReviewDisposition.LOCAL_CANDIDATE,
                reason="Local output remains an unverified candidate.",
                local_output_sha256=local_response.output_sha256,
            )

        if local_response.trusted or remote_response.trusted:
            raise ValueError("provider comparison cannot accept authoritative model output")
        if (
            local_response.output_kind == remote_response.output_kind
            and local_response.output_sha256 == remote_response.output_sha256
        ):
            return HybridReviewResult(
                disposition=HybridReviewDisposition.AGREEMENT_IS_STILL_UNVERIFIED,
                reason="Provider agreement requires deterministic evidence and human review.",
                local_output_sha256=local_response.output_sha256,
                remote_output_sha256=remote_response.output_sha256,
            )
        return HybridReviewResult(
            disposition=HybridReviewDisposition.DISAGREEMENT_REQUIRES_HUMAN,
            reason="Provider disagreement fails closed to independent human review.",
            local_output_sha256=local_response.output_sha256,
            remote_output_sha256=remote_response.output_sha256,
        )
