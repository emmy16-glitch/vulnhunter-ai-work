"""Evidence-backed detail workspaces for findings, reviews, releases and datasets."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.views.decorators.cache import cache_control
from django.views.decorators.http import require_GET, require_http_methods

from vulnhunter.exceptions import GovernanceError, GovernanceNotFoundError
from vulnhunter.governance.service import adjudicate_governed_review, submit_governed_review
from vulnhunter.observations.storage import ScanRepository
from vulnhunter.product import ProductServiceError
from vulnhunter.web.services import (
    WebPermissionDenied,
    authorized_actor,
    governance_store,
    intelligence_status,
    navigation_for,
    product_service,
    run_visible_to_actor,
)
from vulnhunter.web.workspace_forms import GovernedAdjudicationForm, GovernedReviewForm

_ASSIGNMENT_REFERENCE = re.compile(r"^[0-9a-f]{16,64}$")
_MODEL_COMPONENTS = {
    "graph-context": {
        "index": 0,
        "title": "Repository graph context",
        "authority": "Context only. It cannot authorize, scope, execute or modify policy.",
        "inputs": "Validated graph artifacts and bounded source excerpts.",
    },
    "advisory-analysis": {
        "index": 1,
        "title": "Advisory analysis",
        "authority": "Proposal only. Deterministic verification and human review remain authoritative.",
        "inputs": "Sanitized, bounded, non-secret evidence only when explicitly enabled.",
    },
    "deterministic-verification": {
        "index": 2,
        "title": "Deterministic verification",
        "authority": "Evidence-backed verification inside an assessment; it cannot publish a finding.",
        "inputs": "Persisted scanner evidence, reviewed recipes and proof-capsule state.",
    },
}


def _render(request: HttpRequest, template_name: str, context: dict[str, object], *, parent_route: str, status: int = 200) -> HttpResponse:
    return render(request, template_name, {"navigation": navigation_for(request.user), "current_route": parent_route, **context}, status=status)


def _denied(request: HttpRequest, message: str, *, parent_route: str) -> HttpResponse:
    return _render(request, "web/denied.html", {"page_title": "Access Denied", "denied_message": message}, parent_route=parent_route, status=403)


def _assignment_reference(assignment: Any) -> str:
    return str(assignment.record_sha256)[:24]


def _resolve_assignment(reference: str):
    if _ASSIGNMENT_REFERENCE.fullmatch(reference) is None:
        raise Http404("Review assignment does not exist.")
    store = governance_store()
    store.initialize()
    matches: list[tuple[Any, Any]] = []
    for campaign in store.list_campaigns():
        for assignment in store.list_assignments(campaign.campaign_id):
            if assignment.record_sha256.startswith(reference):
                matches.append((campaign, assignment))
    if len(matches) != 1:
        raise Http404("Review assignment does not exist.")
    return store, matches[0][0], matches[0][1]


def _repository_for_assignment(assignment: Any) -> ScanRepository:
    database_path = Path(assignment.scan_database).expanduser().resolve()
    if not database_path.is_file():
        raise ValueError("The linked evidence database is unavailable.")
    return ScanRepository.from_path(database_path)


def _review_workspace_context(store: Any, campaign: Any, assignment: Any) -> dict[str, object]:
    repository = _repository_for_assignment(assignment)
    application = store.get_application(assignment.application_id)
    observation = repository.get_observation(assignment.observation_id)
    case = repository.get_review_case(assignment.observation_id)
    attestations = store.list_attestations(campaign.campaign_id, scan_database=assignment.scan_database, observation_id=assignment.observation_id)
    return {"campaign": campaign, "application": application, "assignment": assignment, "assignment_reference": _assignment_reference(assignment), "observation": observation, "review_case": case, "attestations": attestations, "repository": repository}


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def finding_detail_view(request: HttpRequest, finding_id: str) -> HttpResponse:
    try:
        actor = authorized_actor(request.user, required_actions=("finding.read", "scan.read", "audit.read"))
    except WebPermissionDenied as exc:
        return _denied(request, str(exc), parent_route="web-findings-overview")
    try:
        service = product_service()
        for summary in service.list_agent_runs():
            if not run_visible_to_actor(summary, actor):
                continue
            run = service.get_agent_run(summary.run_id)
            for finding in run.findings:
                identifier = str(finding.get("evidence_id") or finding.get("finding_id") or finding.get("id") or "")
                if identifier != finding_id:
                    continue
                lifecycle = (
                    ("Candidate recorded", bool(identifier)),
                    ("Evidence available", bool(run.artifacts)),
                    ("Deterministic verification", bool(run.evaluation_result)),
                    ("Independent review", str(finding.get("review_state", "")).lower() in {"reviewed", "confirmed", "rejected", "complete"}),
                    ("Governed release", str(finding.get("release_state", "")).lower() in {"released", "published"}),
                )
                return _render(request, "web/finding_detail.html", {"page_title": str(finding.get("title") or identifier), "finding": finding, "finding_id": identifier, "run": run, "lifecycle": lifecycle}, parent_route="web-findings-overview")
    except ProductServiceError as exc:
        raise Http404(str(exc)) from exc
    raise Http404("Finding does not exist.")


@cache_control(private=True, no_store=True)
@login_required
@require_http_methods(["GET", "POST"])
def review_workspace_view(request: HttpRequest, assignment_reference: str) -> HttpResponse:
    try:
        actor = authorized_actor(request.user, required_actions=("review.read", "review.read_assigned"))
        store, campaign, assignment = _resolve_assignment(assignment_reference)
        if actor.governance_identity.reviewer_id not in assignment.primary_reviewers:
            raise WebPermissionDenied("This review is not assigned to your governed identity.")
        context = _review_workspace_context(store, campaign, assignment)
    except WebPermissionDenied as exc:
        return _denied(request, str(exc), parent_route="web-review-queue")
    except (GovernanceError, OSError, RuntimeError, ValueError) as exc:
        return _render(request, "web/review_workspace.html", {"page_title": "Review unavailable", "workspace_error": str(exc), "form": GovernedReviewForm()}, parent_route="web-review-queue", status=503)

    case = context["review_case"]
    actor_id = actor.governance_identity.reviewer_id
    actor_attestation = next((item for item in context["attestations"] if item.role == "primary" and item.actor_id == actor_id), None)
    submitted = actor_attestation is not None
    form = GovernedReviewForm(request.POST or None)
    if request.method == "POST":
        if submitted:
            messages.error(request, "Your immutable review decision has already been submitted.")
        elif form.is_valid():
            try:
                submit_governed_review(store, context["repository"], actor_id=actor_id, actor_secret=form.cleaned_data["governance_secret"], campaign_id=campaign.campaign_id, scan_database=Path(assignment.scan_database), observation_id=assignment.observation_id, outcome=form.cleaned_data["outcome"], note=form.cleaned_data["note"] or None)
            except (GovernanceError, OSError, RuntimeError, ValueError) as exc:
                messages.error(request, str(exc))
            else:
                messages.success(request, "Your governed review decision was recorded and attested.")
                return redirect("web-review-detail", assignment_reference=_assignment_reference(assignment))

    decisions = tuple(case.decisions)
    visible_decisions = decisions if submitted else tuple(item for item in decisions if item.reviewer_id == actor_id)
    context.update({"page_title": f"Review observation {assignment.observation_id}", "form": form, "submitted": submitted, "visible_decisions": visible_decisions, "other_decisions_hidden": not submitted and len(decisions) > len(visible_decisions), "actor_id": actor_id})
    return _render(request, "web/review_workspace.html", context, parent_route="web-review-queue")


@cache_control(private=True, no_store=True)
@login_required
@require_http_methods(["GET", "POST"])
def adjudication_workspace_view(request: HttpRequest, assignment_reference: str) -> HttpResponse:
    try:
        actor = authorized_actor(request.user, required_actions=("adjudication.read", "adjudication.read_assigned"))
        store, campaign, assignment = _resolve_assignment(assignment_reference)
        if actor.governance_identity.reviewer_id != assignment.adjudicator_id:
            raise WebPermissionDenied("This adjudication is not assigned to your governed identity.")
        context = _review_workspace_context(store, campaign, assignment)
    except WebPermissionDenied as exc:
        return _denied(request, str(exc), parent_route="web-adjudication-queue")
    except (GovernanceError, OSError, RuntimeError, ValueError) as exc:
        return _render(request, "web/adjudication_workspace.html", {"page_title": "Adjudication unavailable", "workspace_error": str(exc), "form": GovernedAdjudicationForm()}, parent_route="web-adjudication-queue", status=503)

    case = context["review_case"]
    decisions = tuple(case.decisions)
    disputed = len(decisions) == 2 and decisions[0].outcome != decisions[1].outcome
    submitted = case.adjudication is not None
    form = GovernedAdjudicationForm(request.POST or None)
    if request.method == "POST":
        if submitted:
            messages.error(request, "This adjudication is already locked.")
        elif not disputed:
            messages.error(request, "Adjudication requires two conflicting primary decisions.")
        elif form.is_valid():
            try:
                adjudicate_governed_review(store, context["repository"], actor_id=actor.governance_identity.reviewer_id, actor_secret=form.cleaned_data["governance_secret"], campaign_id=campaign.campaign_id, scan_database=Path(assignment.scan_database), observation_id=assignment.observation_id, outcome=form.cleaned_data["outcome"], rationale=form.cleaned_data["rationale"])
            except (GovernanceError, OSError, RuntimeError, ValueError) as exc:
                messages.error(request, str(exc))
            else:
                messages.success(request, "The independent adjudication was recorded and attested.")
                return redirect("web-adjudication-detail", assignment_reference=_assignment_reference(assignment))

    context.update({"page_title": f"Adjudicate observation {assignment.observation_id}", "form": form, "decisions": tuple(sorted(decisions, key=lambda item: item.reviewer_id)), "disputed": disputed, "submitted": submitted})
    return _render(request, "web/adjudication_workspace.html", context, parent_route="web-adjudication-queue")


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def release_detail_view(request: HttpRequest, campaign_id: str) -> HttpResponse:
    try:
        authorized_actor(request.user, required_actions=("release.read",))
    except WebPermissionDenied as exc:
        return _denied(request, str(exc), parent_route="web-release-list")
    try:
        campaign = product_service().get_campaign(campaign_id)
        store = governance_store()
        store.initialize()
        try:
            manifest = store.get_release(campaign_id)
        except GovernanceNotFoundError:
            manifest = None
        events = store.list_events(subject_type="campaign", subject_id=campaign_id, limit=100)
    except (ProductServiceError, GovernanceError, OSError, RuntimeError, ValueError) as exc:
        raise Http404(str(exc)) from exc
    readiness = campaign.readiness
    blockers = readiness.hard_release_blockers if readiness else ("Readiness report unavailable.",)
    state = "published" if manifest else "blocked" if blockers else "eligible"
    return _render(request, "web/release_detail.html", {"page_title": f"Release assessment {campaign.title}", "campaign": campaign, "manifest": manifest, "events": events, "blockers": blockers, "release_state": state}, parent_route="web-release-list")


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def dataset_detail_view(request: HttpRequest, campaign_id: str) -> HttpResponse:
    try:
        authorized_actor(request.user, required_actions=("dataset.read",))
    except WebPermissionDenied as exc:
        return _denied(request, str(exc), parent_route="web-dataset-list")
    try:
        campaign = product_service().get_campaign(campaign_id)
        store = governance_store()
        store.initialize()
        try:
            manifest = store.get_release(campaign_id)
        except GovernanceNotFoundError:
            manifest = None
    except (ProductServiceError, GovernanceError, OSError, RuntimeError, ValueError) as exc:
        raise Http404(str(exc)) from exc
    return _render(request, "web/dataset_detail.html", {"page_title": f"Dataset quality {campaign.title}", "campaign": campaign, "manifest": manifest, "readiness": campaign.readiness, "is_released": manifest is not None}, parent_route="web-dataset-list")


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def model_detail_view(request: HttpRequest, component_id: str) -> HttpResponse:
    try:
        authorized_actor(request.user, required_actions=("model.read", "audit.read"))
    except WebPermissionDenied as exc:
        return _denied(request, str(exc), parent_route="web-model-list")
    definition = _MODEL_COMPONENTS.get(component_id)
    if definition is None:
        raise Http404("Intelligence component does not exist.")
    status_row = intelligence_status()[int(definition["index"])]
    return _render(request, "web/model_detail.html", {"page_title": str(definition["title"]), "component_id": component_id, "component": definition, "status_row": status_row}, parent_route="web-model-list")
