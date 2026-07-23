"""Inline exact-plan confirmation for the conversational workspace.

The browser user remains one account. The approval ledger records a derived
confirmation principal so request creation and confirmation remain distinct
audit events without requiring a second login.
"""

from __future__ import annotations

from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, JsonResponse
from django.views.decorators.cache import cache_control
from django.views.decorators.http import require_POST

from vulnhunter.approvals import ApprovalDecision
from vulnhunter.approvals.store import ApprovalNotFoundError, ApprovalStoreError
from vulnhunter.web.assessment_workflow import AssessmentWorkflowError, AssessmentWorkflowService
from vulnhunter.web.conversational_views import (
    _actor,
    _append_message,
    _approval_store,
    _run_payload,
    _visible_run,
)
from vulnhunter.web.services import WebPermissionDenied, product_service


@cache_control(private=True, no_store=True)
@login_required
@require_POST
def approve_view(request: HttpRequest) -> JsonResponse:
    try:
        actor = _actor(request, "scan.create")
    except WebPermissionDenied as exc:
        return JsonResponse({"detail": str(exc)}, status=403)

    request_id = request.POST.get("request_id", "").strip()
    plan_digest = request.POST.get("plan_digest", "").strip()
    reason = request.POST.get("reason", "").strip() or "Approved in the assessment workspace."
    if len(reason) < 8:
        return JsonResponse(
            {"detail": "Enter an approval note of at least eight characters."},
            status=400,
        )

    identity_id = actor.governance_identity.reviewer_id
    confirmation_actor = f"{identity_id}.interactive-confirmation"
    try:
        store = _approval_store()
        pending = store.get(request_id)
        run = _visible_run(pending.run_id, actor)
        workflow = AssessmentWorkflowService.from_settings()
        workflow.validate_approval_binding(
            request=pending,
            submitted_plan_digest=plan_digest,
        )
        decided = store.decide(
            request_id=request_id,
            actor_id=confirmation_actor,
            decision=ApprovalDecision.APPROVE_ONCE,
            reason=reason,
        )
        workflow.record_approval_decision(
            request=decided,
            actor_id=confirmation_actor,
        )
    except ApprovalNotFoundError as exc:
        return JsonResponse({"detail": str(exc)}, status=404)
    except (ApprovalStoreError, AssessmentWorkflowError) as exc:
        return JsonResponse({"detail": str(exc)}, status=409)

    refreshed = product_service().get_agent_run(str(getattr(run, "run_id")))
    message = _append_message(
        request,
        role="assistant",
        kind="status",
        content=(
            "Approval recorded for this exact plan. The signed Nuclei job is continuing, "
            "and live progress will appear below."
        ),
        metadata={"run_id": str(getattr(refreshed, "run_id"))},
    )
    return JsonResponse({"message": message, "run": _run_payload(refreshed)})
