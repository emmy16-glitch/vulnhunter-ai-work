"""Role-aware assessment control centre for operators and approvers."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LoginView
from django.http import Http404, HttpRequest, HttpResponse, JsonResponse, StreamingHttpResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.views.decorators.cache import cache_control
from django.views.decorators.http import require_GET

from vulnhunter.adversary_lab.store import AdversaryLabStore, AdversaryLabStoreError
from vulnhunter.approvals import ApprovalStatus, ApprovalStore
from vulnhunter.approvals.store import ApprovalStoreError
from vulnhunter.product import ProductServiceError
from vulnhunter.web import stream_views, views
from vulnhunter.web.forms import VulnHunterAuthenticationForm
from vulnhunter.web.services import (
    WebPermissionDenied,
    activity_payload,
    authorized_actor,
    control_availability,
    navigation_for,
    product_service,
    role_policy,
    run_visible_to_actor,
)


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


def _role_allows(actor, *actions: str) -> bool:
    return role_policy().any_role_allows(actor.product_roles, *actions)


def _can(user, *actions: str) -> bool:
    try:
        actor = authorized_actor(user, required_actions=tuple(actions))
    except WebPermissionDenied:
        return False
    return _role_allows(actor, *actions)


def _pending_approvals() -> tuple[object, ...]:
    try:
        store = ApprovalStore(Path(settings.VULNHUNTER_APPROVAL_DATABASE))
        store.initialize()
        records = store.list()
    except ApprovalStoreError:
        return ()
    actionable = {
        ApprovalStatus.PENDING,
        ApprovalStatus.INFORMATION_REQUIRED,
        ApprovalStatus.CONDITIONS_PROPOSED,
    }
    now = datetime.now(UTC)
    return tuple(
        sorted(
            (
                item
                for item in records
                if item.status in actionable and item.expires_at > now
            ),
            key=lambda item: item.requested_at,
            reverse=True,
        )
    )


def _approval_context_for_run(run_id: str) -> tuple[object | None, object | None]:
    try:
        store = ApprovalStore(Path(settings.VULNHUNTER_APPROVAL_DATABASE))
        store.initialize()
        records = tuple(item for item in store.list() if item.run_id == run_id)
    except ApprovalStoreError:
        return None, None
    if not records:
        return None, None
    latest = max(records, key=lambda item: item.requested_at)
    pending = next((item for item in _pending_approvals() if item.run_id == run_id), None)
    return latest, pending


def _can_view_cross_scope(actor) -> bool:
    return _role_allows(actor, "settings.manage", "campaign.approve", "audit.read")


def _run_is_visible(run, actor) -> bool:
    return run_visible_to_actor(run, actor) or _can_view_cross_scope(actor)


class UnifiedLoginView(LoginView):
    authentication_form = VulnHunterAuthenticationForm
    template_name = "web/login.html"
    redirect_authenticated_user = True

    def get_success_url(self) -> str:
        can_approve = _can(self.request.user, "settings.manage", "campaign.approve")
        can_create = _can(self.request.user, "scan.create")
        pending = _pending_approvals()
        if can_approve and not can_create and pending:
            return reverse("web-scan-run-detail", kwargs={"run_id": pending[0].run_id})
        if can_approve and not can_create:
            return reverse("web-scan-run-list")
        return reverse("web-dashboard")


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def unified_dashboard_view(request: HttpRequest) -> HttpResponse:
    try:
        actor = authorized_actor(request.user, required_actions=("dashboard.read",))
    except WebPermissionDenied:
        return views.dashboard_view(request)
    can_approve = _role_allows(actor, "settings.manage", "campaign.approve")
    can_create = _role_allows(actor, "scan.create")
    if can_approve and not can_create:
        pending = _pending_approvals()
        if pending:
            return redirect("web-scan-run-detail", run_id=pending[0].run_id)
        return redirect("web-scan-run-list")
    return views.dashboard_view(request)


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def assessment_list_view(request: HttpRequest) -> HttpResponse:
    try:
        actor = authorized_actor(request.user, required_actions=("audit.read", "scan.read"))
    except WebPermissionDenied as exc:
        return _render(
            request,
            "web/denied.html",
            {"page_title": "Access Denied", "denied_message": str(exc)},
            status=403,
        )
    can_create = _role_allows(actor, "scan.create")
    can_decide = _role_allows(actor, "settings.manage")
    cross_scope = _can_view_cross_scope(actor)
    try:
        all_runs = product_service().list_agent_runs()
        runs = tuple(all_runs if cross_scope else (run for run in all_runs if run_visible_to_actor(run, actor)))
    except ProductServiceError as exc:
        runs = ()
        error = str(exc)
    else:
        error = None
    pending = tuple(item for item in _pending_approvals() if any(run.run_id == item.run_id for run in runs))
    return _render(
        request,
        "web/agent_runs.html",
        {
            "page_title": "Assessment Control Centre",
            "runs": runs,
            "error_message": error,
            "can_create_assessment": can_create,
            "can_decide_approval": can_decide,
            "approval_only": can_decide and not can_create,
            "pending_approvals": pending,
        },
    )


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def assessment_detail_view(request: HttpRequest, run_id: str) -> HttpResponse:
    try:
        actor = authorized_actor(request.user, required_actions=("audit.read", "scan.read"))
    except WebPermissionDenied as exc:
        return _render(
            request,
            "web/denied.html",
            {"page_title": "Access Denied", "denied_message": str(exc)},
            status=403,
        )
    try:
        run = product_service().get_agent_run(run_id)
    except ProductServiceError as exc:
        raise Http404(str(exc)) from exc
    if not _run_is_visible(run, actor):
        raise Http404("Assessment run does not exist.")

    timeline = activity_payload(run_id, after_sequence=0)
    controls = control_availability(request.user, run.current_state, run.approval_state.value)
    approval_record, pending_approval = _approval_context_for_run(run_id)
    can_decide_approval = _role_allows(actor, "settings.manage")
    try:
        lab_store = AdversaryLabStore(Path(settings.VULNHUNTER_ADVERSARY_LAB_DATABASE))
        lab_store.initialize()
        lab_runs = lab_store.list_for_assessment(run_id)
    except (OSError, AdversaryLabStoreError):
        lab_runs = ()
    latest_lab = lab_runs[0] if lab_runs else None
    can_request_lab = can_decide_approval and bool(request.user.is_staff or request.user.is_superuser)
    return _render(
        request,
        "web/agent_run_detail.html",
        {
            "page_title": f"Assessment {run.run_id}",
            "run": run,
            "timeline": timeline,
            "controls": controls,
            "actor": actor,
            "approval_record": approval_record,
            "pending_approval": pending_approval,
            "can_decide_approval": can_decide_approval,
            "lab_runs": lab_runs,
            "latest_lab": latest_lab,
            "can_request_lab": can_request_lab,
        },
    )


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def assessment_activity_view(request: HttpRequest, run_id: str) -> JsonResponse:
    try:
        actor = authorized_actor(request.user, required_actions=("audit.read", "scan.read"))
    except WebPermissionDenied:
        return JsonResponse({"detail": "forbidden"}, status=403)
    try:
        run = product_service().get_agent_run(run_id)
    except ProductServiceError as exc:
        raise Http404(str(exc)) from exc
    if not _run_is_visible(run, actor):
        raise Http404("Assessment run does not exist.")
    raw = request.GET.get("after_sequence", "0")
    try:
        after_sequence = max(0, int(raw))
    except (TypeError, ValueError):
        return JsonResponse({"detail": "after_sequence must be a non-negative integer"}, status=400)
    return JsonResponse(activity_payload(run_id, after_sequence=after_sequence))


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def assessment_activity_stream_view(request: HttpRequest, run_id: str):
    try:
        actor = authorized_actor(request.user, required_actions=("audit.read", "scan.read"))
    except WebPermissionDenied:
        return JsonResponse({"detail": "forbidden"}, status=403)
    try:
        after_sequence = stream_views._after_sequence_or_error(request)
    except ValueError as exc:
        return JsonResponse({"detail": str(exc)}, status=400)
    try:
        run = product_service().get_agent_run(run_id)
    except ProductServiceError as exc:
        raise Http404(str(exc)) from exc
    if not _run_is_visible(run, actor):
        raise Http404("Assessment run does not exist.")

    payload = activity_payload(run_id, after_sequence=after_sequence)
    elapsed_seconds = max(0, int((datetime.now(UTC) - run.created_at).total_seconds()))
    payload.update(
        {
            "run_id": run.run_id,
            "task_state": run.current_state,
            "run_state": payload.get("run_state") or run.current_state,
            "active_summary": stream_views._active_summary(run),
            "approval_state": run.approval_state.value,
            "execution_state": run.execution_state,
            "workflow_state": getattr(run, "workflow_state", None),
            "execution_enabled": getattr(run, "execution_enabled", False),
            "execution_blocking_reason": getattr(run, "execution_blocking_reason", None),
            "readiness": getattr(run, "readiness", {}),
            "evaluation_result": run.evaluation_result,
            "elapsed_seconds": elapsed_seconds,
            "updated_at": run.updated_at.isoformat(),
        }
    )
    sequence = int(payload.get("last_sequence", after_sequence))
    stream: Iterator[str] = stream_views._event_stream(sequence=sequence, payload=payload)
    response = StreamingHttpResponse(stream, content_type="text/event-stream; charset=utf-8")
    response["Cache-Control"] = "private, no-cache, no-store, must-revalidate"
    response["X-Accel-Buffering"] = "no"
    return response
