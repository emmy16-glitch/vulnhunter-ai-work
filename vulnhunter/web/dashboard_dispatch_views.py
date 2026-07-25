"""Capability-aware root dispatch for the conversational VulnHunter workspace."""

from __future__ import annotations

from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, HttpResponse
from django.views.decorators.cache import cache_control
from django.views.decorators.http import require_GET

from vulnhunter.web import conversational_views, views
from vulnhunter.web.models import WebUserMapping
from vulnhunter.web.services import role_policy


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def dashboard_view(request: HttpRequest) -> HttpResponse:
    """Use chat whenever any mapped role can create an assessment."""

    try:
        mapping = request.user.vulnhunter_mapping
    except WebUserMapping.DoesNotExist:
        return views.dashboard_view(request)
    roles = tuple(str(item) for item in mapping.product_roles if isinstance(item, str))
    if role_policy().any_role_allows(roles, "scan.create"):
        return conversational_views.workspace_view(request)
    return views.dashboard_view(request)
