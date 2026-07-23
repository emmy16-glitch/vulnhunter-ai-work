"""Single-account conversational assessment workspace."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import Http404, HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import render
from django.urls import reverse
from django.views.decorators.cache import cache_control
from django.views.decorators.http import require_GET, require_POST

from vulnhunter.approvals import ApprovalDecision, ApprovalStatus, ApprovalStore
from vulnhunter.approvals.store import ApprovalNotFoundError, ApprovalStoreError
from vulnhunter.product import ProductServiceError
from vulnhunter.web.assessment_workflow import AssessmentWorkflowError, AssessmentWorkflowService
from vulnhunter.web.conversation_service import (
    canonical_target,
    groq_runtime_status,
    interpret_request,
)
from vulnhunter.web.services import (
    WebCapabilityUnavailable,
    WebPermissionDenied,
    activity_payload,
    authorized_actor,
    navigation_for,
    product_service,
    run_visible_to_actor,
    stop_agent_run,
)

_SESSION_MESSAGES = "vulnhunter_conversation_messages"
_SESSION_STATE = "vulnhunter_conversation_state"
_MAX_MESSAGES = 50


def _render(
    request: HttpRequest,
    template_name: str,
    context: dict[str, object],
    *,
    status: int = 200,
) -> HttpResponse:
    base = {
        "navigation": navigation_for(request.user),
        "current_route": request.resolver_match.url_name if request.resolver_match else "",
    }
    base.update(context)
    return render(request, template_name, base, status=status)


def _actor(request: HttpRequest, *actions: str):
    return authorized_actor(request.user, required_actions=tuple(actions))


def _messages(request: HttpRequest) -> list[dict[str, object]]:
    raw = request.session.get(_SESSION_MESSAGES, [])
    if not isinstance(raw, list):
        raw = []
    messages = [item for item in raw if isinstance(item, dict)][-_MAX_MESSAGES:]
    if not messages:
        messages = [
            {
                "role": "assistant",
                "kind": "welcome",
                "content": (
                    "Tell me what authorised target you want assessed. I will gather any missing "
                    "details, prepare the bounded Nuclei plan, pause for your approval, and continue "
                    "in this same workspace."
                ),
                "timestamp": datetime.now(UTC).isoformat(),
            }
        ]
        request.session[_SESSION_MESSAGES] = messages
    return messages


def _append_message(
    request: HttpRequest,
    *,
    role: str,
    content: str,
    kind: str = "text",
    metadata: dict[str, object] | None = None,
) -> dict[str, object]:
    message = {
        "role": role,
        "kind": kind,
        "content": " ".join(content.split()),
        "timestamp": datetime.now(UTC).isoformat(),
        "metadata": metadata or {},
    }
    messages = _messages(request)
    messages.append(message)
    request.session[_SESSION_MESSAGES] = messages[-_MAX_MESSAGES:]
    request.session.modified = True
    return message


def _state(request: HttpRequest) -> dict[str, object]:
    raw = request.session.get(_SESSION_STATE, {})
    return dict(raw) if isinstance(raw, dict) else {}


def _save_state(request: HttpRequest, state: dict[str, object]) -> None:
    request.session[_SESSION_STATE] = state
    request.session.modified = True


def _enum_value(value: object) -> str:
    return str(getattr(value, "value", value))


def _approval_store() -> ApprovalStore:
    store = ApprovalStore(Path(settings.VULNHUNTER_APPROVAL_DATABASE))
    store.initialize()
    return store


def _pending_for_run(run_id: str):
    actionable = {
        ApprovalStatus.PENDING,
        ApprovalStatus.INFORMATION_REQUIRED,
        ApprovalStatus.CONDITIONS_PROPOSED,
    }
    now = datetime.now(UTC)
    try:
        records = _approval_store().list()
    except ApprovalStoreError:
        return None
    candidates = [
        item
        for item in records
        if item.run_id == run_id and item.status in actionable and item.expires_at > now
    ]
    return max(candidates, key=lambda item: item.requested_at) if candidates else None


def _approval_payload(run: object) -> dict[str, object] | None:
    pending = _pending_for_run(str(getattr(run, "run_id")))
    if pending is None:
        return None
    return {
        "request_id": pending.request_id,
        "summary": pending.summary,
        "risk_summary": pending.risk_summary,
        "plan_digest": str(getattr(run, "plan_digest", "")),
        "target": str(getattr(run, "scope_summary", "")),
        "profile": str(getattr(run, "risk_classification", "passive")),
        "scanner": str(getattr(run, "requested_tool", "nuclei")),
        "expires_at": pending.expires_at.isoformat(),
    }


def _safe_finding(item: object) -> dict[str, object]:
    return {
        "title": str(getattr(item, "title", "Candidate finding")),
        "severity": str(getattr(item, "severity", "info")),
        "verification": str(getattr(item, "verification", "candidate")),
        "target": str(getattr(item, "target_reference", "")),
        "finding_id": str(getattr(item, "finding_id", "")),
    }


def _safe_artifact(item: object) -> dict[str, object]:
    return {
        "filename": str(getattr(item, "filename", "evidence artifact")),
        "type": str(getattr(item, "type", "evidence")),
        "size": int(getattr(item, "size", 0) or 0),
        "checksum": str(getattr(item, "checksum", "")),
    }


def _run_payload(run: object) -> dict[str, object]:
    run_id = str(getattr(run, "run_id"))
    try:
        timeline = activity_payload(run_id, after_sequence=0)
    except Exception:
        timeline = {"events": [], "terminal": False, "last_sequence": 0}
    events = timeline.get("events", []) if isinstance(timeline, dict) else []
    if not isinstance(events, list):
        events = []
    findings = tuple(getattr(run, "findings", ()) or ())
    artifacts = tuple(getattr(run, "artifacts", ()) or ())
    current_state = str(getattr(run, "workflow_state", None) or getattr(run, "current_state", "unknown"))
    terminal = current_state in {
        "completed",
        "failed",
        "cancelled",
        "blocked",
        "denied",
        "timed_out",
        "readiness_blocked",
        "execution_blocked",
    }
    return {
        "run_id": run_id,
        "state": current_state,
        "task_state": str(getattr(run, "current_state", current_state)),
        "approval_state": _enum_value(getattr(run, "approval_state", "not_required")),
        "execution_state": str(getattr(run, "execution_state", "not_started")),
        "target": str(getattr(run, "scope_summary", getattr(run, "objective", ""))),
        "profile": str(getattr(run, "risk_classification", "passive")),
        "scanner": str(getattr(run, "requested_tool", "nuclei")),
        "created_at": getattr(run, "created_at").isoformat(),
        "updated_at": getattr(run, "updated_at").isoformat(),
        "terminal": terminal,
        "blocking_reason": getattr(run, "execution_blocking_reason", None),
        "evaluation_result": getattr(run, "evaluation_result", None),
        "findings": [_safe_finding(item) for item in findings],
        "artifacts": [_safe_artifact(item) for item in artifacts],
        "events": events[-30:],
        "last_sequence": timeline.get("last_sequence", 0) if isinstance(timeline, dict) else 0,
        "approval": _approval_payload(run),
        "detail_url": reverse("web-scan-run-detail", kwargs={"run_id": run_id}),
        "findings_url": reverse("web-findings-overview"),
    }


def _visible_run(run_id: str, actor: object):
    try:
        run = product_service().get_agent_run(run_id)
    except ProductServiceError as exc:
        raise Http404(str(exc)) from exc
    if not run_visible_to_actor(run, actor):
        raise Http404("Assessment run does not exist.")
    return run


def _recent_runs(actor: object) -> tuple[dict[str, object], ...]:
    try:
        runs = product_service().list_agent_runs()
    except ProductServiceError:
        return ()
    visible = [run for run in runs if run_visible_to_actor(run, actor)]
    visible.sort(key=lambda item: item.updated_at, reverse=True)
    return tuple(_run_payload(run) for run in visible[:12])


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def workspace_view(request: HttpRequest) -> HttpResponse:
    try:
        actor = _actor(request, "scan.create", "scan.read")
    except WebPermissionDenied as exc:
        return _render(
            request,
            "web/denied.html",
            {"page_title": "Access Denied", "denied_message": str(exc)},
            status=403,
        )
    state = _state(request)
    active_run = None
    run_id = state.get("run_id")
    if isinstance(run_id, str) and run_id:
        try:
            active_run = _run_payload(_visible_run(run_id, actor))
        except Http404:
            state.pop("run_id", None)
            _save_state(request, state)
    initial = {
        "messages": _messages(request),
        "active_run": active_run,
        "recent_runs": _recent_runs(actor),
        "groq": groq_runtime_status(),
        "message_url": reverse("web-conversation-message"),
        "status_url_template": reverse("web-conversation-status", kwargs={"run_id": "RUN_ID"}),
        "approval_url": reverse("web-conversation-approve"),
        "reset_url": reverse("web-conversation-reset"),
    }
    return _render(
        request,
        "web/conversation.html",
        {
            "page_title": "Assessment Workspace",
            "conversation": initial,
            "groq": initial["groq"],
            "recent_runs": initial["recent_runs"],
        },
    )


@cache_control(private=True, no_store=True)
@login_required
@require_POST
def message_view(request: HttpRequest) -> JsonResponse:
    try:
        actor = _actor(request, "scan.create")
    except WebPermissionDenied as exc:
        return JsonResponse({"detail": str(exc)}, status=403)
    text = request.POST.get("message", "").strip()
    if not text or len(text) > 4_000:
        return JsonResponse({"detail": "Enter a message between 1 and 4,000 characters."}, status=400)

    _append_message(request, role="user", content=text)
    state = _state(request)
    workflow = AssessmentWorkflowService.from_settings()
    try:
        choices = workflow.list_authorizations(
            identity_id=actor.governance_identity.reviewer_id,
            username=request.user.get_username(),
        )
    except (OSError, RuntimeError, ValueError) as exc:
        message = _append_message(
            request,
            role="assistant",
            kind="error",
            content=f"The authorization service is unavailable: {exc}",
        )
        return JsonResponse({"message": message}, status=503)

    profiles = tuple(sorted({profile for item in choices for profile in item.approved_profiles}))
    interpreted = interpret_request(text, available_profiles=profiles)

    current_run_id = state.get("run_id")
    if interpreted.intent == "status" and isinstance(current_run_id, str):
        run = _visible_run(current_run_id, actor)
        payload = _run_payload(run)
        message = _append_message(
            request,
            role="assistant",
            content=f"The assessment is currently {payload['state']}. Open the progress card below for details.",
            kind="status",
            metadata={"provider": interpreted.provider},
        )
        return JsonResponse({"message": message, "run": payload})

    if interpreted.intent == "cancel" and isinstance(current_run_id, str):
        try:
            stop_agent_run(request.user, run_id=current_run_id, reason="Cancelled from chat workspace")
        except WebCapabilityUnavailable as exc:
            message = _append_message(request, role="assistant", kind="error", content=str(exc))
            return JsonResponse({"message": message}, status=409)
        run = _visible_run(current_run_id, actor)
        message = _append_message(
            request,
            role="assistant",
            content="The cancellation request was recorded. No additional scanner work will be started.",
            kind="status",
        )
        return JsonResponse({"message": message, "run": _run_payload(run)})

    if interpreted.intent not in {"scan", "clarify"}:
        message = _append_message(
            request,
            role="assistant",
            content=interpreted.assistant_copy or "Tell me which authorised target you want to assess.",
            metadata={"provider": interpreted.provider, "provider_detail": interpreted.provider_detail},
        )
        return JsonResponse({"message": message})

    if not choices:
        message = _append_message(
            request,
            role="assistant",
            kind="error",
            content=(
                "No active authorization is available for this account. Create or prepare an "
                "authorization before starting a scan."
            ),
        )
        return JsonResponse({"message": message}, status=409)

    target = interpreted.target or (state.get("target") if isinstance(state.get("target"), str) else None)
    if target is None:
        suggestions = [item.approved_targets[0] for item in choices if item.approved_targets]
        message = _append_message(
            request,
            role="assistant",
            kind="question",
            content=(
                "I need the authorised target before I can prepare the scan. Choose the suggested "
                "target below or paste a complete http or https URL."
            ),
            metadata={
                "suggestions": [
                    {"label": value, "message": f"Scan {value} using the passive profile"}
                    for value in suggestions[:4]
                ],
                "provider": interpreted.provider,
            },
        )
        return JsonResponse({"message": message})

    canonical = canonical_target(target)
    matched = None
    for item in choices:
        if any(canonical_target(value) == canonical for value in item.approved_targets):
            matched = item
            break
    if matched is None:
        message = _append_message(
            request,
            role="assistant",
            kind="error",
            content="That target is not present in an active authorization for this account.",
        )
        return JsonResponse({"message": message}, status=409)

    profile = interpreted.profile or (
        state.get("profile") if isinstance(state.get("profile"), str) else None
    )
    if profile not in matched.approved_profiles:
        profile = "passive" if "passive" in matched.approved_profiles else None
    if profile is None:
        message = _append_message(
            request,
            role="assistant",
            kind="question",
            content="Which authorised assessment profile should I use? Passive is recommended first.",
            metadata={
                "suggestions": [
                    {"label": value.title(), "message": f"Use the {value} profile for {canonical}"}
                    for value in matched.approved_profiles
                ],
                "provider": interpreted.provider,
            },
        )
        state.update({"target": canonical, "authorization_id": matched.authorization_id})
        _save_state(request, state)
        return JsonResponse({"message": message})

    protocol = canonical_target(canonical).split(":", 1)[0]
    port = interpreted.port
    if port is None:
        from urllib.parse import urlsplit

        parsed = urlsplit(canonical)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if protocol not in matched.approved_protocols or port not in matched.approved_ports:
        message = _append_message(
            request,
            role="assistant",
            kind="error",
            content="The requested protocol or port is outside the active authorization.",
        )
        return JsonResponse({"message": message}, status=409)

    try:
        result = workflow.create_assessment(
            authorization_id=matched.authorization_id,
            target=canonical,
            protocol=protocol,
            port=port,
            profile=profile,
            identity_id=actor.governance_identity.reviewer_id,
            username=request.user.get_username(),
        )
    except (AssessmentWorkflowError, OSError, RuntimeError, ValueError) as exc:
        message = _append_message(request, role="assistant", kind="error", content=str(exc))
        return JsonResponse({"message": message}, status=409)

    run = product_service().get_agent_run(result.task.task_id)
    state = {
        "run_id": result.task.task_id,
        "target": canonical,
        "profile": profile,
        "authorization_id": matched.authorization_id,
    }
    _save_state(request, state)
    message = _append_message(
        request,
        role="assistant",
        kind="plan",
        content=(
            interpreted.assistant_copy
            or "I validated the authorised scope and prepared the exact Nuclei plan. Review the inline approval card to continue."
        ),
        metadata={
            "provider": interpreted.provider,
            "provider_detail": interpreted.provider_detail,
            "run_id": result.task.task_id,
        },
    )
    return JsonResponse({"message": message, "run": _run_payload(run)}, status=201)


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
        return JsonResponse({"detail": "Enter an approval note of at least eight characters."}, status=400)
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
            actor_id=actor.governance_identity.reviewer_id,
            decision=ApprovalDecision.APPROVE_ONCE,
            reason=reason,
            allow_requester=True,
        )
        workflow.record_approval_decision(
            request=decided,
            actor_id=actor.governance_identity.reviewer_id,
        )
    except ApprovalNotFoundError as exc:
        return JsonResponse({"detail": str(exc)}, status=404)
    except (ApprovalStoreError, AssessmentWorkflowError) as exc:
        return JsonResponse({"detail": str(exc)}, status=409)

    run = product_service().get_agent_run(str(getattr(run, "run_id")))
    message = _append_message(
        request,
        role="assistant",
        kind="status",
        content=(
            "Approval recorded for this exact plan. The signed Nuclei job is continuing, and live progress will appear below."
        ),
        metadata={"run_id": str(getattr(run, "run_id"))},
    )
    return JsonResponse({"message": message, "run": _run_payload(run)})


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def status_view(request: HttpRequest, run_id: str) -> JsonResponse:
    try:
        actor = _actor(request, "scan.read")
    except WebPermissionDenied as exc:
        return JsonResponse({"detail": str(exc)}, status=403)
    return JsonResponse({"run": _run_payload(_visible_run(run_id, actor))})


@cache_control(private=True, no_store=True)
@login_required
@require_POST
def reset_view(request: HttpRequest) -> JsonResponse:
    try:
        _actor(request, "scan.create")
    except WebPermissionDenied as exc:
        return JsonResponse({"detail": str(exc)}, status=403)
    request.session.pop(_SESSION_MESSAGES, None)
    request.session.pop(_SESSION_STATE, None)
    request.session.modified = True
    return JsonResponse({"messages": _messages(request)})
