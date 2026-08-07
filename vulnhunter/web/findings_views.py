from __future__ import annotations

from collections.abc import Mapping

from django.contrib.auth.decorators import login_required
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import render
from django.views.decorators.cache import cache_control
from django.views.decorators.http import require_GET

from vulnhunter.product import ProductServiceError
from vulnhunter.web.services import (
    WebPermissionDenied,
    authorized_actor,
    product_service,
    run_readable_to_actor,
)

_CONVERSATION_STATE_SESSION_KEY = "vulnhunter_conversation_state"


def _requested_assessment(request: HttpRequest) -> str | None:
    if str(request.GET.get("scope") or "").casefold() == "all":
        return None
    explicit = str(request.GET.get("assessment") or "").strip()
    if explicit:
        return explicit
    state = request.session.get(_CONVERSATION_STATE_SESSION_KEY, {})
    if not isinstance(state, Mapping):
        return None
    selected = str(state.get("run_id") or "").strip()
    return selected or None


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def findings_overview_view(request: HttpRequest) -> HttpResponse:
    """List persisted findings for the selected assessment or explicit global scope."""

    try:
        actor = authorized_actor(
            request.user,
            required_actions=("finding.read", "scan.read", "audit.read"),
        )
    except WebPermissionDenied as exc:
        return render(
            request,
            "web/denied.html",
            {
                "page_title": "Access Denied",
                "denied_message": str(exc),
                "current_route": "web-findings-overview",
            },
            status=403,
        )

    requested_assessment = _requested_assessment(request)
    selected_assessment: dict[str, str] | None = None
    findings: list[dict[str, object]] = []
    error_message = None
    try:
        service = product_service()
        readable_runs = tuple(
            run for run in service.list_agent_runs() if run_readable_to_actor(run, actor)
        )
        if requested_assessment is not None:
            matched = next(
                (
                    run
                    for run in readable_runs
                    if str(getattr(run, "run_id", "")) == requested_assessment
                ),
                None,
            )
            if matched is None:
                # Preserve the private-not-found boundary: an unknown assessment and an
                # existing assessment the current actor cannot read are indistinguishable.
                raise Http404("Assessment not found.")
            readable_runs = (matched,)

        for summary in readable_runs:
            detail = service.get_agent_run(summary.run_id)
            if requested_assessment is not None:
                selected_assessment = {
                    "run_id": str(detail.run_id),
                    "label": str(getattr(detail, "objective", "") or detail.run_id),
                }
            for finding in detail.findings:
                findings.append(
                    {
                        **finding,
                        "run_id": detail.run_id,
                        "assessment": detail.objective,
                        "scanner": detail.requested_tool,
                        "run_state": detail.current_state,
                        "updated_at": detail.updated_at,
                    }
                )
    except ProductServiceError as exc:
        error_message = str(exc)

    findings.sort(key=lambda item: str(item.get("updated_at", "")), reverse=True)
    return render(
        request,
        "web/findings_overview.html",
        {
            "page_title": "Findings",
            "current_route": "web-findings-overview",
            "findings": tuple(findings),
            "error_message": error_message,
            "selected_assessment": selected_assessment,
        },
    )
