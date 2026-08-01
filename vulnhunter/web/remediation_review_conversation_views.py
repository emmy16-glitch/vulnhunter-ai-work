"""Chat bridge for independent remediation review status and protected handoff."""

from __future__ import annotations

from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, JsonResponse
from django.views.decorators.cache import cache_control
from django.views.decorators.http import require_POST

from vulnhunter.web.remediation_conversation_state import (
    current_remediation_plan,
    record_remediation_event,
    remediation_chat_reply,
)
from vulnhunter.web.remediation_review_views import remediation_review_url
from vulnhunter.web.services import WebPermissionDenied, authorized_actor


def _intent(text: str) -> str:
    lowered = " ".join(text.casefold().split())
    if any(
        phrase in lowered
        for phrase in (
            "start remediation review",
            "open remediation review",
            "review remediation",
            "review the remediation",
            "independent remediation review",
            "review the fix",
            "approve remediation review",
        )
    ):
        return "open"
    if any(term in lowered for term in ("result", "decision", "outcome", "receipt")):
        return "results"
    if any(term in lowered for term in ("next step", "what next", "next action")):
        return "next_step"
    return "status"


@cache_control(private=True, no_store=True)
@login_required
@require_POST
def remediation_review_chat_view(request: HttpRequest) -> JsonResponse:
    try:
        authorized_actor(
            request.user,
            required_actions=("review.read_assigned", "finding.read"),
        )
    except WebPermissionDenied as exc:
        return JsonResponse({"detail": str(exc)}, status=403)
    thread = getattr(request, "vulnhunter_thread", None)
    workspace_id = str(getattr(thread, "thread_id", "") or "") or None
    if workspace_id is None:
        return JsonResponse(
            {"detail": "Select a durable workspace before independent remediation review."},
            status=409,
        )
    text = request.POST.get("message", "").strip()
    if not text or len(text) > 4_000:
        return JsonResponse(
            {"detail": "Enter a message between 1 and 4,000 characters."},
            status=400,
        )

    from vulnhunter.web.conversational_views import _append_message

    _append_message(request, role="user", content=text)
    intent = _intent(text)
    plan = current_remediation_plan(request)
    if plan is not None:
        record_remediation_event(request, plan)

    redirect_url = None
    if plan is None:
        copy = (
            "No governed remediation is bound to this workspace. Independent review requires "
            "an exact passed retest first."
        )
    else:
        remediation = plan.get("plan")
        remediation = remediation if isinstance(remediation, dict) else {}
        finding_id = str(plan.get("finding_id") or "")
        state = str(remediation.get("state") or "unknown")
        if intent == "open" and state == "awaiting_review" and finding_id:
            redirect_url = remediation_review_url(finding_id, workspace_id)
            copy = (
                "Opening the protected independent review workspace. The governance secret, "
                "evidence checklist and rationale remain outside ordinary chat."
            )
        elif intent == "open" and state in {"review_approved", "review_needs_rework"}:
            redirect_url = remediation_review_url(finding_id, workspace_id) if finding_id else None
            copy = (
                "Opening the signed review result already bound to this workspace. A recorded "
                "decision cannot be replaced or edited through chat."
            )
        elif intent == "open":
            copy = (
                f"The remediation is {state}. Independent review opens only after the exact "
                "governed retest passes."
            )
        else:
            copy = remediation_chat_reply(intent, plan)

    metadata: dict[str, object] = {}
    if plan is not None:
        remediation = plan.get("plan")
        remediation = remediation if isinstance(remediation, dict) else {}
        graph = plan.get("assessment_graph")
        graph = graph if isinstance(graph, dict) else {}
        latest_review = remediation.get("latest_review")
        latest_review = latest_review if isinstance(latest_review, dict) else {}
        metadata["remediation_review"] = {
            "remediation_id": plan.get("remediation_id"),
            "finding_id": plan.get("finding_id"),
            "state": remediation.get("state"),
            "chat_stage": graph.get("chat_stage"),
            "report_state": graph.get("report_state"),
            "receipt_id": latest_review.get("receipt_id"),
            "outcome": latest_review.get("outcome"),
        }
    message = _append_message(
        request,
        role="assistant",
        kind="result" if intent == "results" else "status",
        content=copy,
        metadata=metadata,
    )
    response: dict[str, object] = {"message": message, "handled": True}
    if redirect_url:
        response["redirect_url"] = redirect_url
    return JsonResponse(response)


__all__ = ["remediation_review_chat_view"]
