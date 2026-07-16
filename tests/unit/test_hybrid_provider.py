import hashlib

from vulnhunter.providers import (
    HybridProviderCoordinator,
    HybridReviewDisposition,
    HybridRoutingMode,
    ProviderKind,
    ProviderOutputKind,
    ProviderRequest,
    ProviderResponse,
)


def _request(**updates):
    values = {
        "request_id": "hybrid-request",
        "purpose": "Review bounded candidate output safely.",
        "content": "public non-sensitive candidate",
    }
    values.update(updates)
    return ProviderRequest(**values)


def _response(provider, content, kind=ProviderOutputKind.CANDIDATE_ANALYSIS):
    return ProviderResponse(
        invocation_id=f"invoke-{provider.value}",
        provider=provider,
        model="approved-model",
        content=content,
        output_sha256=hashlib.sha256(content.encode()).hexdigest(),
        output_kind=kind,
        trusted=False,
    )


def test_local_only_never_routes_to_groq():
    plan = HybridProviderCoordinator(
        mode=HybridRoutingMode.LOCAL_ONLY,
        groq_enabled=True,
    ).plan(_request(), policy_allows_remote=True)
    assert plan.remote_permitted is False
    assert plan.remote_provider is None


def test_local_then_groq_requires_abstain_policy_and_privacy():
    coordinator = HybridProviderCoordinator(
        mode=HybridRoutingMode.LOCAL_THEN_GROQ,
        groq_enabled=True,
    )
    local = _response(ProviderKind.LOCAL_OLLAMA, "ABSTAIN", ProviderOutputKind.ABSTAIN)
    denied = coordinator.plan(_request(), local_response=local, policy_allows_remote=False)
    assert denied.remote_permitted is False

    private = coordinator.plan(
        _request(content="```private source code```", contains_private_source=True),
        local_response=local,
        policy_allows_remote=True,
    )
    assert private.remote_permitted is False

    allowed = coordinator.plan(_request(), local_response=local, policy_allows_remote=True)
    assert allowed.remote_permitted is True
    assert allowed.remote_provider == ProviderKind.GROQ_QWEN


def test_disabled_groq_never_breaks_local_operation():
    local = _response(ProviderKind.LOCAL_OLLAMA, "ABSTAIN", ProviderOutputKind.ABSTAIN)
    plan = HybridProviderCoordinator(
        mode=HybridRoutingMode.LOCAL_THEN_GROQ,
        groq_enabled=False,
    ).plan(_request(), local_response=local, policy_allows_remote=True)
    assert plan.remote_permitted is False
    assert "disabled" in plan.reason.lower()


def test_dual_review_agreement_is_not_verification_and_disagreement_escalates():
    local = _response(ProviderKind.LOCAL_OLLAMA, "same")
    remote_same = _response(ProviderKind.GROQ_QWEN, "same")
    agreement = HybridProviderCoordinator.compare(local, remote_same)
    assert agreement.disposition == HybridReviewDisposition.AGREEMENT_IS_STILL_UNVERIFIED
    assert agreement.trusted is False

    remote_different = _response(ProviderKind.GROQ_QWEN, "different")
    disagreement = HybridProviderCoordinator.compare(local, remote_different)
    assert disagreement.disposition == HybridReviewDisposition.DISAGREEMENT_REQUIRES_HUMAN
