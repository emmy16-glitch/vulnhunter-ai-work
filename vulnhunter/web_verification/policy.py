"""Independent source validation and structural predicate reproduction."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from vulnhunter.actions.models import sha256_json
from vulnhunter.web_hunters.errors import WebHunterContractError
from vulnhunter.web_hunters.models import (
    HunterContext,
    HunterHypothesis,
    HunterRunResult,
    HypothesisState,
    VerificationStrategy,
)
from vulnhunter.web_hunters.policy import build_hunter_context, validate_hypothesis
from vulnhunter.web_perception.models import (
    PerceivedForm,
    SurfaceNode,
    SurfaceNodeKind,
    WebPerceptionResult,
)
from vulnhunter.web_verification.errors import WebVerificationContractError

_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_OBJECT_ID = re.compile(
    r"^(?:[0-9]{1,18}|[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12})$",
    re.IGNORECASE,
)
_CSRF_NAMES = frozenset(
    {
        "csrf",
        "csrftoken",
        "csrfmiddlewaretoken",
        "xsrf",
        "xsrftoken",
        "authenticitytoken",
        "requestverificationtoken",
    }
)


@dataclass(frozen=True)
class VerificationContract:
    hunter_id: str
    vulnerability_class: str
    required_evidence: tuple[str, ...]


_CONTRACTS = {
    VerificationStrategy.OBJECT_AUTHORIZATION_REVIEW: VerificationContract(
        hunter_id="authorization-object",
        vulnerability_class="object_authorization_candidate",
        required_evidence=(
            "explicit_test_identity_scope",
            "read_only_access_comparison",
            "independent_human_review",
        ),
    ),
    VerificationStrategy.REQUEST_INTEGRITY_REVIEW: VerificationContract(
        hunter_id="request-integrity",
        vulnerability_class="csrf_control_candidate",
        required_evidence=(
            "server_side_request_integrity_controls",
            "same_site_cookie_policy",
            "independent_human_review",
        ),
    ),
    VerificationStrategy.FILE_UPLOAD_REVIEW: VerificationContract(
        hunter_id="file-upload",
        vulnerability_class="file_upload_validation_candidate",
        required_evidence=(
            "documented_upload_policy",
            "storage_and_serving_controls",
            "independent_human_review",
        ),
    ),
    VerificationStrategy.AUTHENTICATION_REVIEW: VerificationContract(
        hunter_id="authentication",
        vulnerability_class="authentication_control_candidate",
        required_evidence=(
            "authentication_policy",
            "session_control_evidence",
            "independent_human_review",
        ),
    ),
    VerificationStrategy.API_ACCESS_REVIEW: VerificationContract(
        hunter_id="api-access",
        vulnerability_class="api_access_control_candidate",
        required_evidence=(
            "api_authorization_policy",
            "role_or_tenant_boundary_evidence",
            "independent_human_review",
        ),
    ),
}


def validate_verification_source(
    perception: WebPerceptionResult,
    hunter_run: HunterRunResult,
) -> HunterContext:
    """Re-verify both source layers before independent verification starts."""

    try:
        context = build_hunter_context(perception)
    except WebHunterContractError as exc:
        raise WebVerificationContractError(
            "web perception source failed verifier integrity checks"
        ) from exc

    expected_run_sha256 = sha256_json(hunter_run.model_dump(mode="json", exclude={"result_sha256"}))
    if expected_run_sha256 != hunter_run.result_sha256:
        raise WebVerificationContractError("hunter result integrity check failed")

    bindings = (
        (hunter_run.target_url, context.target_url, "target"),
        (
            hunter_run.perception_plan_sha256,
            context.perception_plan_sha256,
            "perception plan",
        ),
        (
            hunter_run.perception_evidence_sha256,
            context.perception_evidence_sha256,
            "perception evidence",
        ),
        (hunter_run.graph_sha256, context.graph_sha256, "surface graph"),
    )
    for source_value, expected_value, label in bindings:
        if source_value != expected_value:
            raise WebVerificationContractError(
                f"hunter result {label} does not match the perception source"
            )

    emitted = sum(summary.emitted_hypotheses for summary in hunter_run.hunter_summaries)
    if emitted != len(hunter_run.hypotheses):
        raise WebVerificationContractError(
            "hunter execution summaries do not match emitted hypotheses"
        )

    for hypothesis in hunter_run.hypotheses:
        if hypothesis.state is not HypothesisState.SUSPECTED:
            raise WebVerificationContractError(
                "independent verifier accepts suspected hypotheses only"
            )
        try:
            validate_hypothesis(context, hypothesis)
        except WebHunterContractError as exc:
            raise WebVerificationContractError(
                "hunter hypothesis failed independent source validation"
            ) from exc
    return context


def verification_contract_matches(hypothesis: HunterHypothesis) -> bool:
    """Check strategy-to-hunter semantics independently from hunter fingerprints."""

    contract = _CONTRACTS[hypothesis.verification_intent.strategy]
    return (
        hypothesis.hunter_id == contract.hunter_id
        and hypothesis.vulnerability_class == contract.vulnerability_class
        and hypothesis.verification_intent.required_evidence == contract.required_evidence
    )


def structural_predicate_reproduced(
    context: HunterContext,
    hypothesis: HunterHypothesis,
) -> bool:
    """Reproduce the passive rule without importing hunter implementation helpers."""

    node = _target_node(context, hypothesis.target_node_id)
    strategy = hypothesis.verification_intent.strategy

    if strategy is VerificationStrategy.OBJECT_AUTHORIZATION_REVIEW:
        return node.kind is SurfaceNodeKind.ENDPOINT and _contains_object_identifier(node.url)

    if strategy is VerificationStrategy.API_ACCESS_REVIEW:
        return node.kind is SurfaceNodeKind.ENDPOINT and _looks_like_api(node.url)

    form = _matching_form(context, node)
    if form is None:
        return False

    if strategy is VerificationStrategy.REQUEST_INTEGRITY_REVIEW:
        if form.method not in _MUTATING_METHODS:
            return False
        names = {_normalize_field_name(field.name) for field in form.fields}
        return not bool(names & _CSRF_NAMES)

    if strategy is VerificationStrategy.FILE_UPLOAD_REVIEW:
        return any(field.input_type.casefold() == "file" for field in form.fields)

    if strategy is VerificationStrategy.AUTHENTICATION_REVIEW:
        return any(field.input_type.casefold() == "password" for field in form.fields)

    return False


def _target_node(context: HunterContext, target_node_id: str) -> SurfaceNode:
    for node in context.graph.nodes:
        if node.node_id == target_node_id:
            return node
    raise WebVerificationContractError("verification target node is absent from the graph")


def _matching_form(context: HunterContext, node: SurfaceNode) -> PerceivedForm | None:
    if node.kind is not SurfaceNodeKind.FORM or node.method is None or node.detail_sha256 is None:
        return None
    for page in context.evidence.pages:
        for form in page.forms:
            if (
                form.action_url == node.url
                and form.method == node.method
                and form.form_sha256 == node.detail_sha256
            ):
                return form
    return None


def _normalize_field_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.casefold())


def _contains_object_identifier(url: str) -> bool:
    try:
        segments = [segment for segment in urlsplit(url).path.split("/") if segment]
    except ValueError:
        return False
    return any(_OBJECT_ID.fullmatch(segment) is not None for segment in segments)


def _looks_like_api(url: str) -> bool:
    try:
        segments = [segment.casefold() for segment in urlsplit(url).path.split("/") if segment]
    except ValueError:
        return False
    return bool(segments) and (segments[0] == "api" or "api" in segments[:2])
