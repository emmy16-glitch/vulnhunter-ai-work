from __future__ import annotations

from math import ceil

from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, JsonResponse
from django.views.decorators.cache import cache_control
from django.views.decorators.http import require_GET

from vulnhunter.web.assessment_projection import mobile_assessment_projection
from vulnhunter.web.conversation_mobile_views import _actor
from vulnhunter.web.mobile_conversation_state import current_mobile_plan
from vulnhunter.web.services import WebPermissionDenied

_PAGE_SIZES = {10, 25, 50, 100}
_RECORD_SOURCES = {
    "components": ("intelligence", "exported_component_surfaces"),
    "endpoints": ("intelligence", "endpoint_references"),
    "findings": ("intelligence", "verified_findings"),
    "candidates": ("intelligence", "candidates"),
    "tool_executions": ("intelligence", "tool_executions"),
    "source_hunt": ("source_hunt", "results"),
    "attack_paths": ("source_hunt", "graph.edges"),
}


def _integer(value: object, default: int) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return default


def _row_value(row: dict[str, object], key: str) -> str:
    value = row.get(key)
    if value is None:
        return ""
    return str(value).casefold()


def _rows_for(projection: dict[str, object], record_type: str) -> list[dict[str, object]]:
    source = _RECORD_SOURCES.get(record_type)
    if not source:
        return []
    if source[0] == "intelligence":
        intelligence = projection.get("intelligence")
        if not isinstance(intelligence, dict):
            return []
        rows = intelligence.get(source[1])
        return (
            [dict(row) for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []
        )
    if source[1] == "results":
        hunt = projection.get("source_hunt")
        rows = hunt.get("results") if isinstance(hunt, dict) else []
        return (
            [dict(row) for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []
        )
    graph = projection.get("source_hunt", {}).get("graph", {})
    rows = graph.get("edges", []) if isinstance(graph, dict) else []
    return [dict(row) for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def mobile_records_view(request: HttpRequest) -> JsonResponse:
    try:
        actor = _actor(request, "scan.read")
    except WebPermissionDenied as exc:
        return JsonResponse({"detail": str(exc)}, status=403)
    requested_by = actor.governance_identity.reviewer_id
    plan = current_mobile_plan(request, requested_by=requested_by)
    if plan is None:
        return JsonResponse({"detail": "No mobile assessment is selected."}, status=404)
    projection = mobile_assessment_projection(plan)
    record_type = request.GET.get("record_type", "findings").strip().casefold()
    if record_type not in _RECORD_SOURCES:
        return JsonResponse({"detail": "Unsupported mobile record type."}, status=400)
    rows = _rows_for(projection, record_type)
    query = request.GET.get("query", "").strip().casefold()
    state = request.GET.get("state", "").strip().casefold()
    ownership = request.GET.get("ownership", "").strip().casefold()
    protocol = request.GET.get("protocol", "").strip().casefold()
    if query:
        rows = [row for row in rows if query in str(row).casefold()]
    if state:
        rows = [
            row
            for row in rows
            if _row_value(row, "state") == state or _row_value(row, "evidence_state") == state
        ]
    if ownership:
        rows = [row for row in rows if _row_value(row, "ownership") == ownership]
    if protocol:
        rows = [row for row in rows if _row_value(row, "protocol") == protocol]
    page_size = _integer(request.GET.get("page_size"), 25)
    if page_size not in _PAGE_SIZES:
        page_size = 25
    total_items = len(rows)
    total_pages = max(1, ceil(total_items / page_size))
    page = max(1, min(_integer(request.GET.get("page"), 1), total_pages))
    start = (page - 1) * page_size
    return JsonResponse(
        {
            "assessment_id": projection.get("assessment_id"),
            "record_type": record_type,
            "items": rows[start : start + page_size],
            "pagination": {
                "page": page,
                "page_size": page_size,
                "total_items": total_items,
                "total_pages": total_pages,
            },
        }
    )


__all__ = ["mobile_records_view"]
