"""Capability-aware root dispatch for the conversational VulnHunter workspace."""

from __future__ import annotations

from collections.abc import Iterable

from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect
from django.views.decorators.cache import cache_control
from django.views.decorators.http import require_GET

from vulnhunter.web import conversational_views, views
from vulnhunter.web.models import WebUserMapping
from vulnhunter.web.services import role_policy

_ROLE_ENTRY_ROUTES = (
    ("adjudicator", "web-adjudication-queue"),
    ("reviewer", "web-review-queue"),
    ("campaign-operator", "web-campaign-list"),
    ("campaign-approver", "web-campaign-list"),
    ("model-analyst", "web-model-list"),
    ("security-auditor", "web-audit-overview"),
    ("read-only-observer", "web-status"),
)


def entry_route_for_roles(roles: Iterable[str]) -> str | None:
    """Return the most task-relevant safe landing route for non-creators."""

    role_set = frozenset(str(role) for role in roles)
    for role, route_name in _ROLE_ENTRY_ROUTES:
        if role in role_set:
            return route_name
    return None


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def dashboard_view(request: HttpRequest) -> HttpResponse:
    """Open the most relevant server-authorised workspace for the mapped roles."""

    try:
        mapping = request.user.vulnhunter_mapping
    except WebUserMapping.DoesNotExist:
        return views.dashboard_view(request)
    roles = tuple(str(item) for item in mapping.product_roles if isinstance(item, str))
    if role_policy().any_role_allows(roles, "scan.create"):
        return conversational_views.workspace_view(request)
    entry_route = entry_route_for_roles(roles)
    if entry_route is not None:
        return redirect(entry_route)
    return views.dashboard_view(request)
