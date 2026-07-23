"""Inline exact-plan confirmation for the conversational workspace.

The signed-in assessment requester may confirm only an immutable, already-
authorized passive Nuclei plan. The confirmation cannot alter target, port,
profile, templates, rate limit, concurrency or plan digest. Higher-risk profiles
remain blocked from this single-account endpoint.
"""

from __future__ import annotations

from pathlib import Path

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, JsonResponse
from django.views.decorators.cache import cache_control
from django.views.decorators.http import require_POST

from vulnhunter.approvals.store import ApprovalNotFoundError, ApprovalStoreError
from vulnhunter.product import ProductServiceError
from vulnhunter.web.assessment_workflow import (
    AssessmentWorkflowError,
    AssessmentWorkflowService,
)
from vulnhunter.web.conversational_views import (
    _actor,
    _append_message,
    _run_payload,
    _visible_run,
)
from vulnhunter.web.inline_confirmation_store import InlineConfirmationStore
from vulnhunter.web.services import WebPermissionDenied, product_service


def _confirmation_store() -> InlineConfirmationStore:
    store = InlineConfirmationStore(Path(settings.VULNHUNTER_APPROVAL_DATABASE))
    store.initialize()
    return store


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
    reason = (
        request.POST.get("reason", "").strip()
        or "Confirmed for this exact authorized passive plan."
    )
    if len(reason) < 8:
        return JsonResponse(
            {"detail": "Enter a confirmation note of at least eight characters."},
            status=400,
        )

    identity_id = actor.governance_identity.reviewer_id
    try:
        store = _confirmation_store()
        pending = store.get(request_id)
        run = _visible_run(pending.run_id, actor)
        command_plan = getattr(run, "command_plan_summary", {})
        plan_data = command_plan if isinstance(command_plan, dict) else {}
        profile = str(plan_data.get("exact_profile") or "")
        authoritative_digest = str(plan_data.get("plan_digest") or "")
        if profile != "passive":
            return JsonResponse(
                {
                    "detail": (
                        "Inline confirmation is limited to the reviewed passive profile. "
                        "Choose Passive to continue safely."
                    )
                },
                status=409,
            )
        if not authoritative_digest or authoritative_digest != plan_digest:
            return JsonResponse(
                {"detail": "The displayed command plan is stale or has been modified."},
                status=409,
            )

        workflow = AssessmentWorkflowService.from_settings()
        workflow.validate_approval_binding(
            request=pending,
            submitted_plan_digest=plan_digest,
        )
        confirmed = store.confirm_exact_passive_plan(
            request_id=request_id,
            actor_id=identity_id,
            action_manifest_sha256=authoritative_digest,
            profile=profile,
            reason=reason,
        )
        workflow.record_approval_decision(
            request=confirmed,
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
            "Exact passive plan confirmed. The signed Nuclei job is continuing "
            "from the paused point, and live progress will appear here."
        ),
        metadata={"run_id": str(refreshed.run_id)},
    )
    return JsonResponse({"message": message, "run": _run_payload(refreshed)})
