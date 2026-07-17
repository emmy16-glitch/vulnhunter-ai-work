"""Deterministic-first advisory routing policy."""

from __future__ import annotations

from vulnhunter.ai_routing.models import AiRoute, AiRouteDecision, PrivacyClass, RoutingRequest


class AiRoutingError(RuntimeError):
    pass


def decide_route(request: RoutingRequest) -> AiRouteDecision:
    if request.privacy_class == PrivacyClass.UNKNOWN:
        return _decision(request, AiRoute.DENIED, "unknown privacy classification")
    if request.deterministic_sufficient:
        return _decision(request, AiRoute.DETERMINISTIC, "deterministic processing is sufficient")
    if request.privacy_class in {PrivacyClass.SECRET, PrivacyClass.CUSTOMER_PRIVATE}:
        return _decision(request, AiRoute.HUMAN_ESCALATION, "human review is required")
    if request.non_sensitive_reasoning_approved:
        if request.route_history.count(AiRoute.GROQ_ADVISORY) >= 1:
            return _decision(request, AiRoute.HUMAN_ESCALATION, "advisory retry limit reached")
        return _decision(request, AiRoute.GROQ_ADVISORY, "bounded advisory analysis approved")
    return _decision(
        request,
        AiRoute.HUMAN_ESCALATION,
        request.escalation_reason or "deterministic processing was insufficient",
    )


def _decision(request: RoutingRequest, route: AiRoute, reason: str) -> AiRouteDecision:
    return AiRouteDecision(
        task_id=request.task_id,
        route=route,
        provider="groq-advisory" if route == AiRoute.GROQ_ADVISORY else "none",
        model_role=route.value,
        reason=reason,
        input_sha256=request.input_sha256,
        privacy_class=request.privacy_class,
        deterministic_alternatives=("rules", "hashing", "schema_validation", "human_review"),
        output_trusted=False,
        stop_condition="one advisory attempt maximum",
    )
