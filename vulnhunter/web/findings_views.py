from __future__ import annotations

from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render
from django.views.decorators.cache import cache_control
from django.views.decorators.http import require_GET

from vulnhunter.product import ProductServiceError
from vulnhunter.web.services import (
    WebPermissionDenied,
    authorized_actor,
    product_service,
    run_visible_to_actor,
)


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def findings_overview_view(request: HttpRequest) -> HttpResponse:
    """List only findings backed by persisted assessment evidence."""

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

    findings: list[dict[str, object]] = []
    error_message = None
    try:
        service = product_service()
        runs = tuple(run for run in service.list_agent_runs() if run_visible_to_actor(run, actor))
        for summary in runs:
            detail = service.get_agent_run(summary.run_id)
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
        },
    )
