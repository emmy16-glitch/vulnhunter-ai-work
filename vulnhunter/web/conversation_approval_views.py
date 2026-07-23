"""Compatibility approval endpoint for the conversational workspace.

Approval decisions must come from a separately authenticated governed identity.
The assessment requester can monitor the run in chat, but cannot approve its own
plan through this endpoint.
"""

from __future__ import annotations

from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, JsonResponse
from django.views.decorators.cache import cache_control
from django.views.decorators.http import require_POST

from vulnhunter.approvals import ApprovalDecision
from vulnhunter.approvals.store import ApprovalNotFoundError, ApprovalStoreError
from vulnhunter.product import ProductServiceError
from vulnhunter.web.assessment_workflow import (
    AssessmentWorkflowError,
    AssessmentWorkflowService,
)
from vulnhunter.web.conversational_views import (
    _actor,
    _append_message,
    _approval_store,
    _run_payload,
)
from vulnhunter.web.services import WebPermissionDenied, product_service


@cache_control(private=True, no_store=True)
@login_required
@require_POST
def approve_view(request: HttpRequest) -> JsonResponse:
    try:
        actor = _actor(request, "campaign.approve", "settings.manage")
    except WebPermissionDenied as exc:
        return JsonResponse({"detail": str(exc)}, status=403)

    request_id = request.POST.get("request_id", "").strip()
    plan_digest = request.POST.get("plan_digest", "").strip()
    reason = (
        request.POST.get("reason", "").strip()
        or "Approved independently in the assessment workspace."
    )
    if len(reason) < 8:
        return JsonResponse(
            {"detail": "Enter an approval note of at least eight characters."},
            status=400,
        )

    identity_id = actor.governance_identity.reviewer_id
    try:
        store = _approval_store()
        pending = store.get(request_id)
        if identity_id == pending.requested_by:
            return JsonResponse(
                {"detail": "The assessment requester cannot approve its own plan."},
                status=409,
            )
        workflow = AssessmentWorkflowService.from_settings()
        workflow.validate_approval_binding(
            request=pending,
            submitted_plan_digest=plan_digest,
        )
        decided = store.decide(
            request_id=request_id,
            actor_id=identity_id,
            decision=ApprovalDecision.APPROVE_ONCE,
            reason=reason,
        )
        workflow.record_approval_decision(
            request=decided,
            actor_id=identity_id,
        )
        refreshed = product_service().get_agent_run(pending.run_id)
    except ApprovalNotFoundError as exc:
        return JsonResponse({"detail": str(exc)}, status=404)
    except (ApprovalStoreError, AssessmentWorkflowError, ProductServiceError) as exc:
        return JsonResponse({"detail": str(exc)}, status=409)

    message = _append_message(
        request,
        role="assistant",
        kind="status",
        content=(
            "Independent approval was recorded for this exact plan. The signed "
            "Nuclei job can now continue."
        ),
        metadata={"run_id": str(refreshed.run_id)},
    )
    return JsonResponse({"message": message, "run": _run_payload(refreshed)})
