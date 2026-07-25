"""Exact approval and status endpoints for MobSF and disposable runtime work."""

from __future__ import annotations

from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, JsonResponse
from django.urls import reverse
from django.views.decorators.cache import cache_control
from django.views.decorators.http import require_GET, require_POST

from vulnhunter.web.conversational_views import _actor, _append_message
from vulnhunter.web.mobile_conversation_state import (
    current_mobile_plan,
    remember_mobile_plan,
)
from vulnhunter.web.mobile_extension_execution import (
    enqueue_mobile_extension,
    mobile_extension_status,
)
from vulnhunter.web.services import WebPermissionDenied


@cache_control(private=True, no_store=True)
@login_required
@require_POST
def mobile_extension_approve_view(request: HttpRequest) -> JsonResponse:
    try:
        actor = _actor(request, "scan.create")
    except WebPermissionDenied as exc:
        return JsonResponse({"detail": str(exc)}, status=403)
    requested_by = actor.governance_identity.reviewer_id
    plan = current_mobile_plan(request, requested_by=requested_by)
    if plan is None:
        return JsonResponse(
            {"detail": "No mobile hunt is selected in this conversation."},
            status=404,
        )
    kind = request.POST.get("kind", "").strip().casefold()
    reason = request.POST.get("reason", "").strip()
    package_name = request.POST.get("package_name", "").strip() or None
    execution = enqueue_mobile_extension(
        request,
        plan=plan,
        kind=kind,
        package_name=package_name,
        reason=reason,
        requested_by=requested_by,
    )
    if execution.get("state") != "queued":
        return JsonResponse(
            {"detail": execution.get("reason", "Extension approval was rejected.")},
            status=409,
        )
    execution["status_url"] = reverse(
        "web-conversation-mobile-extension-status",
        kwargs={"job_id": execution["job_id"]},
    )
    raw_jobs = plan.get("extension_jobs")
    jobs = list(raw_jobs) if isinstance(raw_jobs, list) else []
    jobs.append(execution)
    plan["extension_jobs"] = jobs[-8:]
    remember_mobile_plan(request, plan)
    label = "private MobSF" if kind == "mobsf" else "disposable ADB/Frida runtime"
    message = _append_message(
        request,
        role="assistant",
        kind="mobile_plan",
        content=(
            f"Your exact {label} approval was bound to this APK and plan digest. "
            "The separate worker job is queued; the browser will show its real terminal state."
        ),
        metadata={"mobile_plan": plan, "mobile_extension": execution},
    )
    return JsonResponse(
        {
            "message": message,
            "mobile_plan": plan,
            "mobile_extension": execution,
        }
    )


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def mobile_extension_status_view(
    request: HttpRequest,
    job_id: str,
) -> JsonResponse:
    try:
        actor = _actor(request, "scan.read")
    except WebPermissionDenied as exc:
        return JsonResponse({"detail": str(exc)}, status=403)
    status = mobile_extension_status(
        request,
        job_id=job_id,
        requested_by=actor.governance_identity.reviewer_id,
    )
    if status is None:
        return JsonResponse({"detail": "Mobile extension job does not exist."}, status=404)
    return JsonResponse({"mobile_extension": status})
