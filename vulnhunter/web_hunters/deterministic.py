"""Deterministic specialist hunters over sanitized browser perception structure."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from vulnhunter.web_hunters.models import (
    HunterContext,
    HunterEvidenceReference,
    HunterHypothesis,
    VerificationIntent,
    VerificationStrategy,
    hypothesis_id_for,
    semantic_fingerprint,
    verification_intent_id_for,
)
from vulnhunter.web_perception.models import SurfaceNode, SurfaceNodeKind

_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_OBJECT_ID = re.compile(
    r"^(?:[0-9]{1,18}|[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$",
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


def _normalize_field_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.casefold())


def _related_edges(context: HunterContext, target_node_id: str) -> tuple[str, ...]:
    return tuple(
        sorted(
            edge.edge_id
            for edge in context.graph.edges
            if edge.target_node_id == target_node_id or edge.source_node_id == target_node_id
        )
    )


def _related_nodes(context: HunterContext, target_node_id: str) -> tuple[str, ...]:
    related = {target_node_id}
    for edge in context.graph.edges:
        if edge.target_node_id == target_node_id:
            related.add(edge.source_node_id)
        elif edge.source_node_id == target_node_id:
            related.add(edge.target_node_id)
    return tuple(sorted(related))


def _form_node(
    context: HunterContext,
    *,
    action_url: str,
    method: str,
    detail_sha256: str,
) -> SurfaceNode | None:
    return next(
        (
            node
            for node in context.graph.nodes
            if node.kind is SurfaceNodeKind.FORM
            and node.url == action_url
            and node.method == method
            and node.detail_sha256 == detail_sha256
        ),
        None,
    )


def _build_hypothesis(
    context: HunterContext,
    *,
    hunter_id: str,
    vulnerability_class: str,
    title: str,
    observation: str,
    rationale: str,
    target_node_id: str,
    priority_score: int,
    strategy: VerificationStrategy,
    required_evidence: tuple[str, ...],
) -> HunterHypothesis:
    fingerprint = semantic_fingerprint(
        hunter_id=hunter_id,
        vulnerability_class=vulnerability_class,
        target_node_id=target_node_id,
        strategy=strategy,
    )
    hypothesis_id = hypothesis_id_for(
        graph_sha256=context.graph_sha256,
        semantic_fingerprint_value=fingerprint,
    )
    intent = VerificationIntent(
        intent_id=verification_intent_id_for(
            hypothesis_id=hypothesis_id,
            strategy=strategy,
            target_node_id=target_node_id,
        ),
        hypothesis_id=hypothesis_id,
        strategy=strategy,
        target_node_id=target_node_id,
        required_evidence=required_evidence,
    )
    return HunterHypothesis(
        hypothesis_id=hypothesis_id,
        semantic_fingerprint=fingerprint,
        hunter_id=hunter_id,
        vulnerability_class=vulnerability_class,
        title=title,
        observation=observation,
        rationale=rationale,
        target_node_id=target_node_id,
        priority_score=priority_score,
        evidence=HunterEvidenceReference(
            graph_sha256=context.graph_sha256,
            node_ids=_related_nodes(context, target_node_id),
            edge_ids=_related_edges(context, target_node_id),
        ),
        verification_intent=intent,
    )


@dataclass(frozen=True)
class ObjectAuthorizationHunter:
    hunter_id: str = "authorization-object"

    def applicable(self, context: HunterContext) -> bool:
        return any(
            node.kind is SurfaceNodeKind.ENDPOINT and _contains_object_identifier(node.url)
            for node in context.graph.nodes
        )

    def analyze(self, context: HunterContext) -> tuple[HunterHypothesis, ...]:
        hypotheses = []
        for node in context.graph.nodes:
            if node.kind is not SurfaceNodeKind.ENDPOINT or not _contains_object_identifier(
                node.url
            ):
                continue
            hypotheses.append(
                _build_hypothesis(
                    context,
                    hunter_id=self.hunter_id,
                    vulnerability_class="object_authorization_candidate",
                    title="Object authorization requires independent review",
                    observation="A read-only endpoint path contains a concrete object identifier.",
                    rationale=(
                        "Object identifiers in client-visible paths can mark "
                        "authorization-sensitive resources, but the surface graph alone "
                        "cannot prove an access-control flaw."
                    ),
                    target_node_id=node.node_id,
                    priority_score=65,
                    strategy=VerificationStrategy.OBJECT_AUTHORIZATION_REVIEW,
                    required_evidence=(
                        "explicit_test_identity_scope",
                        "read_only_access_comparison",
                        "independent_human_review",
                    ),
                )
            )
        return tuple(hypotheses)


@dataclass(frozen=True)
class RequestIntegrityHunter:
    hunter_id: str = "request-integrity"

    def applicable(self, context: HunterContext) -> bool:
        return any(
            form.method in _MUTATING_METHODS
            for page in context.evidence.pages
            for form in page.forms
        )

    def analyze(self, context: HunterContext) -> tuple[HunterHypothesis, ...]:
        hypotheses = []
        for page in context.evidence.pages:
            for form in page.forms:
                if form.method not in _MUTATING_METHODS:
                    continue
                normalized_names = {_normalize_field_name(field.name) for field in form.fields}
                if normalized_names & _CSRF_NAMES:
                    continue
                node = _form_node(
                    context,
                    action_url=form.action_url,
                    method=form.method,
                    detail_sha256=form.form_sha256,
                )
                if node is None:
                    continue
                hypotheses.append(
                    _build_hypothesis(
                        context,
                        hunter_id=self.hunter_id,
                        vulnerability_class="csrf_control_candidate",
                        title="State-changing form integrity requires review",
                        observation=(
                            "A state-changing form declaration has no recognizable "
                            "request-integrity field in the sanitized structure."
                        ),
                        rationale=(
                            "Framework-level or header-based protections may still exist; "
                            "this is a review candidate, not proof of cross-site request forgery."
                        ),
                        target_node_id=node.node_id,
                        priority_score=50,
                        strategy=VerificationStrategy.REQUEST_INTEGRITY_REVIEW,
                        required_evidence=(
                            "server_side_request_integrity_controls",
                            "same_site_cookie_policy",
                            "independent_human_review",
                        ),
                    )
                )
        return tuple(hypotheses)


@dataclass(frozen=True)
class FileUploadHunter:
    hunter_id: str = "file-upload"

    def applicable(self, context: HunterContext) -> bool:
        return any(
            field.input_type.casefold() == "file"
            for page in context.evidence.pages
            for form in page.forms
            for field in form.fields
        )

    def analyze(self, context: HunterContext) -> tuple[HunterHypothesis, ...]:
        hypotheses = []
        for page in context.evidence.pages:
            for form in page.forms:
                if not any(field.input_type.casefold() == "file" for field in form.fields):
                    continue
                node = _form_node(
                    context,
                    action_url=form.action_url,
                    method=form.method,
                    detail_sha256=form.form_sha256,
                )
                if node is None:
                    continue
                hypotheses.append(
                    _build_hypothesis(
                        context,
                        hunter_id=self.hunter_id,
                        vulnerability_class="file_upload_validation_candidate",
                        title="File upload handling requires specialized review",
                        observation="The application surface declares a file-upload control.",
                        rationale=(
                            "Upload surfaces deserve dedicated validation of type, size, "
                            "storage, and serving controls; no file is uploaded by this hunter."
                        ),
                        target_node_id=node.node_id,
                        priority_score=40,
                        strategy=VerificationStrategy.FILE_UPLOAD_REVIEW,
                        required_evidence=(
                            "documented_upload_policy",
                            "storage_and_serving_controls",
                            "independent_human_review",
                        ),
                    )
                )
        return tuple(hypotheses)


@dataclass(frozen=True)
class AuthenticationSurfaceHunter:
    hunter_id: str = "authentication"

    def applicable(self, context: HunterContext) -> bool:
        return any(
            field.input_type.casefold() == "password"
            for page in context.evidence.pages
            for form in page.forms
            for field in form.fields
        )

    def analyze(self, context: HunterContext) -> tuple[HunterHypothesis, ...]:
        hypotheses = []
        for page in context.evidence.pages:
            for form in page.forms:
                if not any(field.input_type.casefold() == "password" for field in form.fields):
                    continue
                node = _form_node(
                    context,
                    action_url=form.action_url,
                    method=form.method,
                    detail_sha256=form.form_sha256,
                )
                if node is None:
                    continue
                hypotheses.append(
                    _build_hypothesis(
                        context,
                        hunter_id=self.hunter_id,
                        vulnerability_class="authentication_control_candidate",
                        title="Authentication control surface requires review",
                        observation=(
                            "The application surface contains a password-bearing form declaration."
                        ),
                        rationale=(
                            "Authentication surfaces need separate session, rate-limit, "
                            "recovery, and identity-control review; this hunter does not "
                            "submit credentials."
                        ),
                        target_node_id=node.node_id,
                        priority_score=35,
                        strategy=VerificationStrategy.AUTHENTICATION_REVIEW,
                        required_evidence=(
                            "authentication_policy",
                            "session_control_evidence",
                            "independent_human_review",
                        ),
                    )
                )
        return tuple(hypotheses)


@dataclass(frozen=True)
class ApiAccessHunter:
    hunter_id: str = "api-access"

    def applicable(self, context: HunterContext) -> bool:
        return any(
            node.kind is SurfaceNodeKind.ENDPOINT and _looks_like_api(node.url)
            for node in context.graph.nodes
        )

    def analyze(self, context: HunterContext) -> tuple[HunterHypothesis, ...]:
        return tuple(
            _build_hypothesis(
                context,
                hunter_id=self.hunter_id,
                vulnerability_class="api_access_control_candidate",
                title="API access-control surface requires review",
                observation="A browser-observed read-only endpoint is part of an API-like path.",
                rationale=(
                    "API endpoints often enforce object, role, or tenant authorization "
                    "outside the browser UI; the current passive graph cannot establish "
                    "whether those controls fail."
                ),
                target_node_id=node.node_id,
                priority_score=30,
                strategy=VerificationStrategy.API_ACCESS_REVIEW,
                required_evidence=(
                    "api_authorization_policy",
                    "role_or_tenant_boundary_evidence",
                    "independent_human_review",
                ),
            )
            for node in context.graph.nodes
            if node.kind is SurfaceNodeKind.ENDPOINT and _looks_like_api(node.url)
        )


def default_hunters() -> tuple[object, ...]:
    return (
        ObjectAuthorizationHunter(),
        RequestIntegrityHunter(),
        FileUploadHunter(),
        AuthenticationSurfaceHunter(),
        ApiAccessHunter(),
    )


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
