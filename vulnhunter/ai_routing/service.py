"""Deterministic-first AI routing policy."""

from __future__ import annotations

from vulnhunter.ai_routing.models import AiRoute, AiRouteDecision, PrivacyClass, RoutingRequest


class AiRoutingError(RuntimeError):
    pass


def decide_route(request: RoutingRequest) -> AiRouteDecision:
    if request.privacy_class == PrivacyClass.UNKNOWN:
        return _decision(request, AiRoute.DENIED, "unknown privacy classification fails closed")
    if request.deterministic_sufficient:
        return _decision(request, AiRoute.DETERMINISTIC, "deterministic processing is sufficient")
    if request.public_freshness_required:
        if request.privacy_class != PrivacyClass.PUBLIC:
            return _decision(
                request, AiRoute.DENIED, "current public lookup cannot receive private data"
            )
        return _decision(
            request, AiRoute.GROQ_COMPOUND_MINI, "approved public-current-information route"
        )
    if request.privacy_class in {PrivacyClass.SECRET, PrivacyClass.CUSTOMER_PRIVATE}:
        return _decision(
            request, AiRoute.HUMAN_ESCALATION, "private data cannot route to cloud providers"
        )
    if request.non_sensitive_reasoning_approved:
        return _decision(request, AiRoute.GROQ_QWEN, "approved difficult non-sensitive reasoning")
    if request.escalation_reason:
        return _decision(request, AiRoute.LOCAL_QWEN_STRONG, request.escalation_reason)
    if request.route_history.count(AiRoute.LOCAL_QWEN_SMALL) >= 1:
        return _decision(request, AiRoute.HUMAN_ESCALATION, "repeated local model loop blocked")
    return _decision(request, AiRoute.LOCAL_QWEN_SMALL, "bounded local candidate generation")


def _decision(request: RoutingRequest, route: AiRoute, reason: str) -> AiRouteDecision:
    provider = "none"
    if route in {AiRoute.LOCAL_QWEN_SMALL, AiRoute.LOCAL_QWEN_STRONG}:
        provider = "local-disabled-contract"
    elif route in {AiRoute.GROQ_QWEN, AiRoute.GROQ_COMPOUND_MINI}:
        provider = "groq-disabled-contract"
    return AiRouteDecision(
        task_id=request.task_id,
        route=route,
        provider=provider,
        model_role=route.value,
        reason=reason,
        input_sha256=request.input_sha256,
        privacy_class=request.privacy_class,
        deterministic_alternatives=("rules", "hashing", "schema_validation"),
        output_trusted=False,
        stop_condition="no provider activation performed",
    )
