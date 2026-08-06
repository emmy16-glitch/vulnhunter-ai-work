"""Authenticated browser action for authoritative mobile assessment retries."""

from __future__ import annotations

from copy import deepcopy

from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, JsonResponse
from django.urls import reverse
from django.views.decorators.cache import cache_control
from django.views.decorators.http import require_http_methods

from vulnhunter.web.assessment_projection import mobile_assessment_projection
from vulnhunter.web.conversation_attachments import ConversationAttachment
from vulnhunter.web.conversation_mobile_views import _resolve_artifact
from vulnhunter.web.conversational_views import _actor
from vulnhunter.web.mobile_conversation_state import current_mobile_plan, remember_mobile_plan
from vulnhunter.web.mobile_retry import MobileRetryError, retry_mobile_execution
from vulnhunter.web.services import WebPermissionDenied


def _error_response(
    request: HttpRequest,
    *,
    code: str,
    message: str,
    status: int,
    retryable: bool,
    assessment_id: str | None = None,
) -> JsonResponse:
    error: dict[str, object] = {
        "code": code,
        "message": message,
        "retryable": retryable,
        "action": {
            "label": "Try again" if retryable else "Return to assessment history",
            "method": "POST" if retryable else "GET",
            "url": request.get_full_path() if retryable else reverse("web-scan-run-list"),
        },
    }
    if assessment_id:
        error["assessment_id"] = assessment_id
    return JsonResponse({"error": error}, status=status)


def _retry_attachment(plan: dict[str, object]) -> ConversationAttachment | None:
    return ConversationAttachment.from_payload(plan.get("artifact"))


def _selected_plan(request: HttpRequest) -> tuple[object, dict[str, object] | None] | JsonResponse:
    try:
        actor = _actor(request, "scan.create")
    except WebPermissionDenied as exc:
        return _error_response(
            request,
            code="mobile_retry_forbidden",
            message=str(exc),
            status=403,
            retryable=False,
        )

    requested_by = actor.governance_identity.reviewer_id
    plan = current_mobile_plan(request, requested_by=requested_by)
    if plan is None:
        return _error_response(
            request,
            code="mobile_retry_assessment_not_selected",
            message="No mobile assessment is selected in this conversation.",
            status=404,
            retryable=False,
        )
    return actor, plan


def _projection_payload(plan: dict[str, object]) -> dict[str, object] | None:
    projection = mobile_assessment_projection(plan)
    if projection is None:
        return None
    return {
        "mobile_execution": plan.get("execution") or {},
        "mobile_plan": plan,
        "assessment_projection": projection,
        "task_card": projection["task_card"],
    }


@cache_control(private=True, no_store=True)
@login_required
@require_http_methods(["GET", "POST"])
def mobile_retry_view(request: HttpRequest) -> JsonResponse:
    """Read or retry the selected server-owned mobile assessment state."""

    selected = _selected_plan(request)
    if isinstance(selected, JsonResponse):
        return selected
    actor, plan = selected
    assessment_id = str(plan.get("run_id") or "").strip() or None

    if request.method == "GET":
        payload = _projection_payload(plan)
        if payload is None:
            return _error_response(
                request,
                code="mobile_retry_projection_unavailable",
                message=(
                    "The selected mobile assessment could not be projected from "
                    "authoritative state."
                ),
                status=409,
                retryable=False,
                assessment_id=assessment_id,
            )
        return JsonResponse(payload)

    requested_by = actor.governance_identity.reviewer_id
    retry_scope = request.POST.get("retry_scope", "").strip()
    idempotency_key = request.POST.get("idempotency_key", "").strip()
    attachment = _retry_attachment(plan)
    artifact = _resolve_artifact(attachment) if attachment is not None else None

    try:
        execution = retry_mobile_execution(
            request,
            plan=plan,
            requested_by=requested_by,
            retry_scope=retry_scope,
            idempotency_key=idempotency_key,
            attachment=attachment,
            artifact=artifact,
        )
    except MobileRetryError as exc:
        return _error_response(
            request,
            code=exc.code,
            message=str(exc),
            status=409,
            retryable=exc.retryable,
            assessment_id=assessment_id,
        )

    refreshed = deepcopy(plan)
    if execution.get("state") == "queued" and execution.get("job_id"):
        execution["status_url"] = reverse(
            "web-conversation-mobile-status",
            kwargs={"job_id": execution["job_id"]},
        )
    refreshed["execution"] = execution
    payload = _projection_payload(refreshed)
    if payload is None:
        return _error_response(
            request,
            code="mobile_retry_projection_refresh_unavailable",
            message=(
                "The refreshed mobile assessment could not be projected from "
                "authoritative state."
            ),
            status=409,
            retryable=True,
            assessment_id=assessment_id,
        )
    remember_mobile_plan(request, refreshed)
    return JsonResponse(payload)


__all__ = ["mobile_retry_view"]
