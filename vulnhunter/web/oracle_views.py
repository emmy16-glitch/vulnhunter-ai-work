from __future__ import annotations

from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render
from django.views.decorators.cache import cache_control
from django.views.decorators.http import require_GET

from vulnhunter.web.services import (
    WebPermissionDenied,
    authorized_actor,
    intelligence_status,
)


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def oracle_overview_view(request: HttpRequest) -> HttpResponse:
    """Show current provider state without implying that verification ran."""

    try:
        authorized_actor(request.user, required_actions=("model.read", "scan.read", "audit.read"))
    except WebPermissionDenied as exc:
        return render(
            request,
            "web/denied.html",
            {
                "page_title": "Access Denied",
                "denied_message": str(exc),
                "current_route": "web-oracle-overview",
            },
            status=403,
        )

    return render(
        request,
        "web/oracle_overview.html",
        {
            "page_title": "Machine Oracle",
            "current_route": "web-oracle-overview",
            "provider_status": intelligence_status(),
        },
    )
