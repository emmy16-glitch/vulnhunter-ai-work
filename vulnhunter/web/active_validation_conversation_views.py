"""Chat bridge for workspace-bound Active Validation plans."""

from __future__ import annotations

from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, JsonResponse
from django.urls import reverse
from django.views.decorators.cache import cache_control
from django.views.decorators.http import require_POST

from vulnhunter.web.active_validation_conversation_state import (
    active_validation_chat_reply,
    current_active_validation_plan,
    record_active_validation_event,
)
from vulnhunter.web.services import WebPermissionDenied, authorized_actor


def _intent(text: str) -> str:
    lowered = " ".join(text.casefold().split())
    if any(term in lowered for term in ("result", "finding", "evidence", "what happened")):
        return "results"
    if any(term in lowered for term in ("next step", "what next", "next action")):
        return "next_step"
    if any(
        term in lowered
        for term in (
            "status",
            "progress",
            "is it running",
            "is it done",
            "how far",
        )
    ):
        return "status"
    return "setup"


def _parent_assessment_id(request: HttpRequest) -> str | None:
    state = request.session.get("vulnhunter_conversation_state", {})
    if not isinstance(state, dict):
        return None
    run_id = state.get("run_id")
    return str(run_id) if isinstance(run_id, str) and run_id else None


@cache_control(private=True, no_store=True)
@login_required
@require_POST
def active_validation_chat_view(request: HttpRequest) -> JsonResponse:
    try:
        authorized_actor(request.user, required_actions=("scan.read",))
    except WebPermissionDenied as exc:
        return JsonResponse({"detail": str(exc)}, status=403)
    if getattr(request, "vulnhunter_thread", None) is None:
        return JsonResponse(
            {"detail": "Select a durable workspace before using Active Validation."},
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
    plan = current_active_validation_plan(request)
    if plan is not None:
        record_active_validation_event(request, plan)

    redirect_url = None
    if intent == "setup":
        if plan is not None:
            redirect_url = str(plan.get("detail_url") or "") or None
            copy = (
                "Opening the protected Active Validation workspace for the exact existing plan. "
                "Password step-up and governed approval remain outside ordinary chat."
            )
        else:
            assessment_id = _parent_assessment_id(request)
            if assessment_id:
                redirect_url = reverse(
                    "web-lab-create",
                    kwargs={"assessment_id": assessment_id},
                )
                copy = (
                    "Active Validation starts from a persisted assessment finding. Opening the "
                    "protected setup keeps finding selection, password re-authentication, the "
                    "reviewed synthetic scenario and exact plan approval outside ordinary chat."
                )
            else:
                copy = (
                    "No parent assessment is selected in this workspace. Complete an authorised "
                    "assessment with a persisted finding before requesting Active Validation."
                )
    elif plan is None:
        copy = (
            "No Active Validation plan is bound to this workspace. Start from a persisted finding "
            "on the parent assessment."
        )
    else:
        copy = active_validation_chat_reply(intent, plan)

    metadata: dict[str, object] = {}
    if plan is not None:
        execution = plan.get("execution")
        execution = execution if isinstance(execution, dict) else {}
        graph = plan.get("assessment_graph")
        graph = graph if isinstance(graph, dict) else {}
        metadata["active_validation"] = {
            "lab_id": plan.get("lab_id"),
            "state": execution.get("state"),
            "current_trial": execution.get("current_trial"),
            "chat_stage": graph.get("chat_stage"),
            "task_graph_id": plan.get("task_graph_id"),
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


__all__ = ["active_validation_chat_view"]
