"""Capability-aware root dispatch for the conversational VulnHunter workspace."""

from __future__ import annotations

from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, HttpResponse
from django.views.decorators.cache import cache_control
from django.views.decorators.http import require_GET

from vulnhunter.web import conversational_views, views
from vulnhunter.web.services import WebPermissionDenied, authorized_actor


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def dashboard_view(request: HttpRequest) -> HttpResponse:
    """Use chat whenever the mapped account can create and read assessments."""

    try:
        authorized_actor(request.user, required_actions=("scan.create", "scan.read"))
    except WebPermissionDenied:
        return views.dashboard_view(request)
    return conversational_views.workspace_view(request)
