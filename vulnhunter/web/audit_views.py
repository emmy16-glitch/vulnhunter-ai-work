from __future__ import annotations

from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render
from django.views.decorators.cache import cache_control
from django.views.decorators.http import require_GET

from vulnhunter.web.services import WebPermissionDenied, authorized_actor, product_service


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def audit_overview_view(request: HttpRequest) -> HttpResponse:
    """Render recent immutable audit activity without duplicating System Status."""

    try:
        authorized_actor(request.user, required_actions=("audit.read",))
    except WebPermissionDenied as exc:
        return render(
            request,
            "web/denied.html",
            {
                "page_title": "Access Denied",
                "denied_message": str(exc),
                "current_route": "web-audit-overview",
            },
            status=403,
        )

    dashboard = product_service().load_dashboard()
    return render(
        request,
        "web/audit_overview.html",
        {
            "page_title": "Audit Log",
            "current_route": "web-audit-overview",
            "audit_status": dashboard.status.audit_evidence,
            "audit_events": dashboard.recent_audit_activity,
        },
    )
