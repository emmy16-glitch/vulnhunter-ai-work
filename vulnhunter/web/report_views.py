from __future__ import annotations

from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render
from django.views.decorators.cache import cache_control
from django.views.decorators.http import require_GET

from vulnhunter.web.services import (
    WebPermissionDenied,
    authorized_actor,
    list_pilot_plan_records,
)


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def reports_overview_view(request: HttpRequest) -> HttpResponse:
    """Show real report inputs and supported renderer state."""

    try:
        authorized_actor(request.user, required_actions=("campaign.read", "report.read"))
    except WebPermissionDenied as exc:
        return render(
            request,
            "web/denied.html",
            {
                "page_title": "Access Denied",
                "denied_message": str(exc),
                "current_route": "web-reports-overview",
            },
            status=403,
        )

    formats = (
        {"name": "HTML", "state": "available"},
        {"name": "JSON", "state": "available"},
        {"name": "SARIF", "state": "available"},
        {"name": "Evidence ZIP", "state": "available"},
        {"name": "Attack-path SVG", "state": "available"},
        {"name": "PDF", "state": "renderer not active"},
    )
    return render(
        request,
        "web/reports_overview.html",
        {
            "page_title": "Reports",
            "current_route": "web-reports-overview",
            "records": list_pilot_plan_records(),
            "report_formats": formats,
        },
    )
