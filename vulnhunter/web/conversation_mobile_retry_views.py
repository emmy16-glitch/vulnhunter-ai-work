"""Authenticated browser action for authoritative mobile assessment retries."""

from __future__ import annotations

from copy import deepcopy

from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, JsonResponse
from django.urls import reverse
from django.views.decorators.cache import cache_control
from django.views.decorators.http import require_POST

from vulnhunter.web.conversation_attachments import ConversationAttachment
from vulnhunter.web.conversation_mobile_views import _resolve_artifact
from vulnhunter.web.conversational_views import _actor
from vulnhunter.web.mobile_conversation_state import current_mobile_plan, remember_mobile_plan
from vulnhunter.web.mobile_retry import MobileRetryError, retry_mobile_execution
from vulnhunter.web.services import WebPermissionDenied


def _retry_attachment(plan: dict[str, object]) -> ConversationAttachment | None:
    return ConversationAttachment.from_payload(plan.get("artifact"))


@cache_control(private=True, no_store=True)
@login_required
@require_POST
def mobile_retry_view(request: HttpRequest) -> JsonResponse:
    """Retry exactly the persisted safe scope and refresh authoritative plan state."""

    try:
        actor = _actor(request, "scan.create")
    except WebPermissionDenied as exc:
        return JsonResponse({"detail": str(exc)}, status=403)

    requested_by = actor.governance_identity.reviewer_id
    plan = current_mobile_plan(request, requested_by=requested_by)
    if plan is None:
        return JsonResponse(
            {"detail": "No mobile assessment is selected in this conversation."},
            status=404,
        )

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
        return JsonResponse({"detail": str(exc)}, status=409)

    refreshed = deepcopy(plan)
    if execution.get("state") == "queued" and execution.get("job_id"):
        execution["status_url"] = reverse(
            "web-conversation-mobile-status",
            kwargs={"job_id": execution["job_id"]},
        )
    refreshed["execution"] = execution
    remember_mobile_plan(request, refreshed)
    return JsonResponse(
        {
            "mobile_execution": execution,
            "mobile_plan": refreshed,
        }
    )


__all__ = ["mobile_retry_view"]
