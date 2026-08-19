from __future__ import annotations

from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, JsonResponse
from django.views.decorators.cache import cache_control
from django.views.decorators.http import require_POST

from vulnhunter.web.assessment_projection import mobile_assessment_projection
from vulnhunter.web.conversation_mobile_views import _actor
from vulnhunter.web.conversational_views import _append_message
from vulnhunter.web.mobile_conversation_state import current_mobile_plan, remember_mobile_plan
from vulnhunter.web.mobile_source_hunt import (
    MobileSourceHuntHandoffError,
    run_mobile_source_hunt_handoff,
)
from vulnhunter.web.services import WebPermissionDenied


@cache_control(private=True, no_store=True)
@login_required
@require_POST
def mobile_source_hunt_handoff_view(request: HttpRequest) -> JsonResponse:
    try:
        actor = _actor(request, "scan.read")
    except WebPermissionDenied as exc:
        return JsonResponse({"detail": str(exc)}, status=403)

    requested_by = actor.governance_identity.reviewer_id
    plan = current_mobile_plan(request, requested_by=requested_by)
    if plan is None:
        return JsonResponse(
            {"detail": "No completed APK analysis is selected in this conversation."}, status=404
        )
    selected_seed_id = request.POST.get("seed_id", "").strip() or None
    selected_record_id = request.POST.get("record_id", "").strip() or None
    try:
        result = run_mobile_source_hunt_handoff(
            plan=plan,
            requested_by=requested_by,
            selected_seed_id=selected_seed_id,
            selected_record_id=selected_record_id,
        )
    except MobileSourceHuntHandoffError as exc:
        return JsonResponse({"detail": str(exc)}, status=409)

    report = result["report"]
    plan["source_hunt"] = {
        "state": "completed",
        "requested_by": requested_by,
        "report": report,
        "report_path": result["report_path"],
    }
    remember_mobile_plan(request, plan)
    projection = mobile_assessment_projection(plan)
    message = _append_message(
        request,
        role="assistant",
        kind="source_hunt",
        content=(
            "Source Hunt completed from retained APK intelligence. "
            f"Examined {len(report.get('results', []))} bounded seeds; "
            f"the persisted graph contains {len(report.get('graph', {}).get('nodes', []))} nodes "
            f"and {len(report.get('graph', {}).get('edges', []))} edges."
        ),
        metadata={"source_hunt_result": report},
    )
    return JsonResponse(
        {
            "message": message,
            "plan": plan,
            "mobile_plan": plan,
            "projection": projection,
            "assessment_projection": projection,
            "task_card": projection.get("task_card"),
            "mobile_execution": plan.get("execution"),
            "source_hunt": report,
        }
    )


__all__ = ["mobile_source_hunt_handoff_view"]
