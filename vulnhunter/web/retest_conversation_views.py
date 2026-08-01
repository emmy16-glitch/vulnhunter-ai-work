"""Chat bridge for workspace-bound governed retests."""

from __future__ import annotations

from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, JsonResponse
from django.views.decorators.cache import cache_control
from django.views.decorators.http import require_POST

from vulnhunter.web.remediation_conversation_state import current_remediation_plan
from vulnhunter.web.retest_conversation_state import (
    current_retest_plan,
    record_retest_event,
    retest_chat_reply,
    retest_create_url,
)
from vulnhunter.web.services import WebPermissionDenied, authorized_actor


def _intent(text: str) -> str:
    lowered = " ".join(text.casefold().split())
    if any(
        phrase in lowered
        for phrase in (
            "start retest",
            "run retest",
            "open retest",
            "retest finding",
            "retest the fix",
            "verify after fix",
        )
    ):
        return "start"
    if any(term in lowered for term in ("result", "evidence", "outcome")):
        return "results"
    if any(term in lowered for term in ("next step", "what next", "next action")):
        return "next_step"
    if any(term in lowered for term in ("status", "progress", "is it done", "is it ready")):
        return "status"
    return "status"


@cache_control(private=True, no_store=True)
@login_required
@require_POST
def retest_chat_view(request: HttpRequest) -> JsonResponse:
    try:
        authorized_actor(request.user, required_actions=("finding.read",))
    except WebPermissionDenied as exc:
        return JsonResponse({"detail": str(exc)}, status=403)
    thread = getattr(request, "vulnhunter_thread", None)
    workspace_id = str(getattr(thread, "thread_id", "") or "") or None
    if workspace_id is None:
        return JsonResponse(
            {"detail": "Select a durable workspace before starting a governed retest."},
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
    retest_state = current_retest_plan(request)
    if retest_state is not None:
        record_retest_event(request, retest_state)
    remediation_state = current_remediation_plan(request)

    redirect_url = None
    if intent == "start":
        if retest_state is not None:
            redirect_url = str(retest_state.get("detail_url") or "") or None
            copy = (
                "Opening the exact governed retest already bound to this workspace. Ordinary chat "
                "cannot supply passwords, evidence JSON or deterministic test authority."
            )
        elif remediation_state is None:
            copy = (
                "No remediation plan is bound to this workspace. A governed retest can start only "
                "after an independently verified fix reaches ready-for-retest."
            )
        else:
            plan = remediation_state.get("plan")
            plan = plan if isinstance(plan, dict) else {}
            state = str(plan.get("state") or "unknown")
            finding_id = str(remediation_state.get("finding_id") or "")
            if state == "ready_for_retest" and finding_id:
                redirect_url = retest_create_url(finding_id, workspace_id)
                copy = (
                    "Opening protected retest planning. Fresh password re-authentication and exact "
                    "bounded checks remain outside ordinary chat."
                )
            else:
                copy = (
                    f"The remediation is {state}, so a governed retest cannot start. A fixed "
                    "read-only verification receipt is required first."
                )
    elif retest_state is not None:
        copy = retest_chat_reply(intent, retest_state)
    elif remediation_state is not None:
        plan = remediation_state.get("plan")
        plan = plan if isinstance(plan, dict) else {}
        state = str(plan.get("state") or "unknown")
        copy = (
            f"No governed retest is active. The remediation is {state}. Start the retest only "
            "after it reaches ready-for-retest."
        )
    else:
        copy = "No remediation or governed retest is bound to this workspace."

    metadata: dict[str, object] = {}
    if retest_state is not None:
        result = retest_state.get("result")
        result = result if isinstance(result, dict) else {}
        graph = retest_state.get("assessment_graph")
        graph = graph if isinstance(graph, dict) else {}
        metadata["retest"] = {
            "retest_id": retest_state.get("retest_id"),
            "finding_id": retest_state.get("finding_id"),
            "outcome": result.get("outcome") or "pending",
            "chat_stage": graph.get("chat_stage"),
            "report_state": retest_state.get("report_state"),
            "task_graph_id": retest_state.get("task_graph_id"),
            "receipt_id": result.get("receipt_id"),
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


__all__ = ["retest_chat_view"]
