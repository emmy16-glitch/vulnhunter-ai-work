"""Stable, model-neutral intelligence status pages."""

from __future__ import annotations

from typing import Any

from django.contrib.auth.decorators import login_required
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import render
from django.views.decorators.cache import cache_control
from django.views.decorators.http import require_GET

from vulnhunter.web.services import (
    WebPermissionDenied,
    authorized_actor,
    intelligence_status,
)

_COMPONENTS: tuple[dict[str, str], ...] = (
    {
        "component_id": "graph-context",
        "kind": "Context",
        "title": "Repository graph context",
        "status_name": "Graphify advisory graph",
        "authority": "Context only. It cannot authorize, scope, execute, or modify policy.",
        "inputs": "Validated graph artifacts and bounded source excerpts.",
    },
    {
        "component_id": "advisory-analysis",
        "kind": "Advisory",
        "title": "Advisory analysis",
        "status_name": "Groq advisory",
        "authority": (
            "Proposal only. Deterministic verification and human review remain authoritative."
        ),
        "inputs": "Sanitized, bounded, non-secret evidence only when explicitly enabled.",
    },
    {
        "component_id": "deterministic-verification",
        "kind": "Verification",
        "title": "Deterministic verification",
        "status_name": "Deterministic verification",
        "authority": (
            "Evidence-backed verification inside an assessment; it cannot publish a finding."
        ),
        "inputs": "Persisted scanner evidence, reviewed recipes, and proof-capsule state.",
    },
)
_COMPONENT_BY_ID = {item["component_id"]: item for item in _COMPONENTS}


def _status_by_name() -> dict[str, dict[str, str]]:
    return {
        str(item.get("name", "")): {
            "name": str(item.get("name", "Status unavailable")),
            "state": str(item.get("state", "NOT_READY")),
            "detail": str(item.get("detail", "No current status detail is available.")),
        }
        for item in intelligence_status()
    }


def _component_rows() -> tuple[dict[str, str], ...]:
    statuses = _status_by_name()
    rows: list[dict[str, str]] = []
    for component in _COMPONENTS:
        status_name = component["status_name"]
        status = statuses.get(
            status_name,
            {
                "name": status_name,
                "state": "NOT_READY",
                "detail": "This component did not return a current backend status.",
            },
        )
        rows.append({**component, **status})
    return tuple(rows)


def _denied(request: HttpRequest, message: str) -> HttpResponse:
    return render(
        request,
        "web/denied.html",
        {
            "page_title": "Access Denied",
            "current_route": "web-model-list",
            "denied_message": message,
        },
        status=403,
    )


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def model_list_view(request: HttpRequest) -> HttpResponse:
    try:
        authorized_actor(request.user, required_actions=("model.read", "audit.read"))
    except WebPermissionDenied as exc:
        return _denied(request, str(exc))

    return render(
        request,
        "web/models_overview.html",
        {
            "page_title": "Intelligence components",
            "current_route": "web-model-list",
            "intelligence_status": _component_rows(),
        },
    )


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def model_detail_view(request: HttpRequest, component_id: str) -> HttpResponse:
    try:
        authorized_actor(request.user, required_actions=("model.read", "audit.read"))
    except WebPermissionDenied as exc:
        return _denied(request, str(exc))

    definition: dict[str, Any] | None = _COMPONENT_BY_ID.get(component_id)
    if definition is None:
        raise Http404("Intelligence component does not exist.")

    status_row = next(
        item for item in _component_rows() if item["component_id"] == component_id
    )
    return render(
        request,
        "web/model_detail.html",
        {
            "page_title": definition["title"],
            "current_route": "web-model-list",
            "component_id": component_id,
            "component": definition,
            "status_row": status_row,
        },
    )
