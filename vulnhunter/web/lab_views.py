"""Nested web workflow for controlled synthetic impact simulation."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import Http404, HttpRequest, HttpResponse, JsonResponse, StreamingHttpResponse
from django.shortcuts import redirect, render
from django.views.decorators.cache import cache_control
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from vulnhunter.adversary_lab.models import LabState
from vulnhunter.adversary_lab.registry import get_scenario, list_scenarios
from vulnhunter.adversary_lab.runner import LabWorkerPolicy, SyntheticScenarioRunner
from vulnhunter.adversary_lab.service import AdversaryLabService, AdversaryLabServiceError
from vulnhunter.adversary_lab.store import AdversaryLabStore, AdversaryLabStoreError
from vulnhunter.agent_activity.service import AgentActivityService
from vulnhunter.agent_activity.store import AppendOnlyActivityStore
from vulnhunter.product import ProductServiceError
from vulnhunter.web.services import (
    WebPermissionDenied,
    activity_payload,
    authorized_actor,
    navigation_for,
    product_service,
    run_visible_to_actor,
)

_STEP_UP_SESSION_KEY = "vulnhunter_lab_step_up"


def _render(
    request: HttpRequest,
    template: str,
    context: dict[str, object],
    *,
    status: int = 200,
) -> HttpResponse:
    payload = {
        "navigation": navigation_for(request.user),
        "current_route": request.resolver_match.url_name if request.resolver_match else "",
        **context,
    }
    return render(request, template, payload, status=status)


def _denied(request: HttpRequest, message: str, *, status: int = 403) -> HttpResponse:
    return _render(
        request,
        "web/denied.html",
        {"page_title": "Access Denied", "denied_message": message},
        status=status,
    )


def _store() -> AdversaryLabStore:
    store = AdversaryLabStore(Path(settings.VULNHUNTER_ADVERSARY_LAB_DATABASE))
    store.initialize()
    return store


def _activity_service() -> AgentActivityService:
    return AgentActivityService(
        AppendOnlyActivityStore(Path(settings.VULNHUNTER_AGENT_ACTIVITY_ROOT))
    )


def _service() -> AdversaryLabService:
    policy = LabWorkerPolicy(
        enabled=settings.VULNHUNTER_ADVERSARY_LAB_ENABLED,
        workspace_root=Path(settings.VULNHUNTER_ADVERSARY_LAB_WORKSPACE_ROOT).absolute(),
        evidence_root=Path(settings.VULNHUNTER_ADVERSARY_LAB_EVIDENCE_ROOT).absolute(),
        maximum_trials=settings.VULNHUNTER_ADVERSARY_LAB_MAX_TRIALS,
    )
    return AdversaryLabService(
        store=_store(),
        activity_service=_activity_service(),
        runner=SyntheticScenarioRunner(policy),
    )


def _assessment_for_actor(request: HttpRequest, assessment_id: str):
    try:
        actor = authorized_actor(request.user, required_actions=("scan.read", "audit.read"))
        run = product_service().get_agent_run(assessment_id)
    except WebPermissionDenied:
        raise
    except ProductServiceError as exc:
        raise Http404(str(exc)) from exc
    if not run_visible_to_actor(run, actor):
        raise Http404("Assessment run does not exist.")
    return actor, run


def _operator(request: HttpRequest, action: str):
    actor = authorized_actor(request.user, required_actions=(action,))
    if not (request.user.is_staff or request.user.is_superuser):
        raise WebPermissionDenied("This action requires a staff account and governed role.")
    return actor


def _password_step_up(request: HttpRequest, *, lab_id: str, password: str) -> None:
    if not password or not request.user.check_password(password):
        raise WebPermissionDenied("Password re-authentication failed.")
    expires_at = datetime.now(UTC) + timedelta(
        seconds=settings.VULNHUNTER_ADVERSARY_LAB_STEP_UP_SECONDS
    )
    request.session[_STEP_UP_SESSION_KEY] = {
        "lab_id": lab_id,
        "username": request.user.get_username(),
        "expires_at": expires_at.isoformat(),
    }
    request.session.modified = True


def _step_up_active(request: HttpRequest, lab_id: str) -> bool:
    raw = request.session.get(_STEP_UP_SESSION_KEY)
    if not isinstance(raw, dict):
        return False
    if raw.get("lab_id") != lab_id or raw.get("username") != request.user.get_username():
        return False
    try:
        expires_at = datetime.fromisoformat(str(raw["expires_at"]))
    except (KeyError, TypeError, ValueError):
        return False
    return expires_at > datetime.now(UTC)


def _after_sequence(request: HttpRequest) -> int:
    values: list[int] = []
    for raw in (request.GET.get("after_sequence"), request.headers.get("Last-Event-ID")):
        if raw in {None, ""}:
            continue
        try:
            value = int(raw)
        except (TypeError, ValueError) as exc:
            raise ValueError("activity sequence must be an integer") from exc
        if value < 0:
            raise ValueError("activity sequence must be non-negative")
        values.append(value)
    return max(values, default=0)


def _event_stream(*, sequence: int, payload: dict[str, object]) -> Iterator[str]:
    encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True, default=str)
    yield "retry: 1500\n"
    yield f"id: {sequence}\n"
    yield "event: activity\n"
    yield f"data: {encoded}\n\n"


@cache_control(private=True, no_store=True)
@login_required
@require_http_methods(["GET", "POST"])
def lab_create_view(request: HttpRequest, assessment_id: str) -> HttpResponse:
    try:
        _operator(request, "settings.manage")
        _actor, run = _assessment_for_actor(request, assessment_id)
    except WebPermissionDenied as exc:
        return _denied(request, str(exc))

    findings = tuple(run.findings)
    if request.method == "POST":
        try:
            maximum_trials = int(request.POST.get("maximum_trials", "5"))
        except ValueError:
            maximum_trials = 0
        finding_reference = request.POST.get("finding_reference", "").strip()
        scenario_id = request.POST.get("scenario_id", "").strip()
        password = request.POST.get("password", "")
        selected_finding = next(
            (
                finding
                for finding in findings
                if str(finding.get("evidence_id", "")) == finding_reference
            ),
            None,
        )
        try:
            if selected_finding is None:
                raise ValueError("Select a persisted finding from this assessment.")
            if not run.authorization_id:
                raise ValueError("The assessment has no recorded authorization binding.")
            if not 1 <= maximum_trials <= 10:
                raise ValueError("Maximum trials must be between 1 and 10.")
            get_scenario(scenario_id)
            _password_step_up(request, lab_id="pending-lab-plan", password=password)
            record = _service().create_plan(
                assessment_id=assessment_id,
                finding_reference=finding_reference,
                authorization_id=run.authorization_id,
                target_reference=str(selected_finding.get("target_reference") or run.scope_summary),
                scenario_id=scenario_id,
                maximum_trials=maximum_trials,
                requested_by=request.user.get_username(),
            )
            _password_step_up(request, lab_id=record.plan.lab_id, password=password)
        except (ValueError, WebPermissionDenied, AdversaryLabServiceError) as exc:
            messages.error(request, str(exc))
        else:
            messages.success(
                request,
                "The exact synthetic lab plan was created and is waiting "
                "for an independent approver.",
            )
            return redirect("web-lab-detail", lab_id=record.plan.lab_id)

    return _render(
        request,
        "web/lab_create.html",
        {
            "page_title": "Request Active Validation",
            "run": run,
            "findings": findings,
            "scenarios": list_scenarios(),
            "hard_trial_ceiling": 10,
        },
        status=200 if findings else 409,
    )


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def lab_detail_view(request: HttpRequest, lab_id: str) -> HttpResponse:
    try:
        authorized_actor(request.user, required_actions=("scan.read", "audit.read"))
        record = _store().get(lab_id)
        _actor, run = _assessment_for_actor(request, record.plan.assessment_id)
    except WebPermissionDenied as exc:
        return _denied(request, str(exc))
    except AdversaryLabStoreError as exc:
        raise Http404(str(exc)) from exc

    permissions: dict[str, bool] = {}
    for key, action in {
        "approve": "campaign.approve",
        "execute": "settings.manage",
        "cancel": "settings.manage",
    }.items():
        try:
            _operator(request, action)
        except WebPermissionDenied:
            permissions[key] = False
        else:
            permissions[key] = True
    if record.plan.requested_by == request.user.get_username():
        permissions["approve"] = False

    return _render(
        request,
        "web/lab_detail.html",
        {
            "page_title": f"Active Validation {record.plan.lab_id}",
            "run": run,
            "lab": record,
            "scenario": get_scenario(record.plan.scenario_id),
            "timeline": activity_payload(lab_id, after_sequence=0),
            "permissions": permissions,
            "step_up_active": _step_up_active(request, lab_id),
            "terminal_states": tuple(
                state.value
                for state in LabState
                if state
                in {
                    LabState.COMPLETED,
                    LabState.CANCELLED,
                    LabState.BLOCKED,
                    LabState.FAILED,
                }
            ),
        },
    )


@cache_control(private=True, no_store=True)
@login_required
@require_POST
def lab_approve_view(request: HttpRequest, lab_id: str) -> HttpResponse:
    try:
        _operator(request, "campaign.approve")
        record = _store().get(lab_id)
        _assessment_for_actor(request, record.plan.assessment_id)
        _password_step_up(request, lab_id=lab_id, password=request.POST.get("password", ""))
        _service().approve(lab_id, approved_by=request.user.get_username())
    except (WebPermissionDenied, AdversaryLabStoreError, AdversaryLabServiceError) as exc:
        messages.error(request, str(exc))
    else:
        messages.success(request, "The exact synthetic lab plan was independently approved.")
    return redirect("web-lab-detail", lab_id=lab_id)


@cache_control(private=True, no_store=True)
@login_required
@require_POST
def lab_queue_view(request: HttpRequest, lab_id: str) -> HttpResponse:
    try:
        _operator(request, "settings.manage")
        record = _store().get(lab_id)
        _assessment_for_actor(request, record.plan.assessment_id)
        _password_step_up(request, lab_id=lab_id, password=request.POST.get("password", ""))
        _service().queue(lab_id, queued_by=request.user.get_username())
    except (WebPermissionDenied, AdversaryLabStoreError, AdversaryLabServiceError) as exc:
        messages.error(request, str(exc))
    else:
        messages.success(request, "The approved plan was queued for the isolated lab worker.")
    return redirect("web-lab-detail", lab_id=lab_id)


@cache_control(private=True, no_store=True)
@login_required
@require_POST
def lab_stop_view(request: HttpRequest, lab_id: str) -> HttpResponse:
    try:
        _operator(request, "settings.manage")
        record = _store().get(lab_id)
        _assessment_for_actor(request, record.plan.assessment_id)
        _service().request_cancel(
            lab_id,
            actor_id=request.user.get_username(),
            reason=request.POST.get("reason", "Operator requested stop."),
        )
    except (WebPermissionDenied, AdversaryLabStoreError, AdversaryLabServiceError) as exc:
        messages.error(request, str(exc))
    else:
        messages.success(request, "The stop request was recorded at the next safe checkpoint.")
    return redirect("web-lab-detail", lab_id=lab_id)


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def lab_activity_stream_view(request: HttpRequest, lab_id: str):
    try:
        authorized_actor(request.user, required_actions=("scan.read", "audit.read"))
        record = _store().get(lab_id)
        _assessment_for_actor(request, record.plan.assessment_id)
    except WebPermissionDenied:
        return JsonResponse({"detail": "forbidden"}, status=403)
    except AdversaryLabStoreError as exc:
        raise Http404(str(exc)) from exc
    try:
        after_sequence = _after_sequence(request)
    except ValueError as exc:
        return JsonResponse({"detail": str(exc)}, status=400)

    payload = activity_payload(lab_id, after_sequence=after_sequence)
    elapsed_seconds = 0
    if record.started_at:
        elapsed_seconds = max(0, int((datetime.now(UTC) - record.started_at).total_seconds()))
    payload.update(
        {
            "lab_id": lab_id,
            "assessment_id": record.plan.assessment_id,
            "run_state": record.state.value,
            "active_summary": record.active_summary,
            "current_trial": record.current_trial,
            "maximum_trials": record.plan.maximum_trials,
            "confirmed_trials": record.confirmed_trials,
            "cleanup_verified": record.cleanup_verified,
            "result": record.result,
            "elapsed_seconds": elapsed_seconds,
            "updated_at": record.updated_at.isoformat(),
            "terminal": record.terminal,
        }
    )
    sequence = int(payload.get("last_sequence", after_sequence))
    response = StreamingHttpResponse(
        _event_stream(sequence=sequence, payload=payload),
        content_type="text/event-stream; charset=utf-8",
    )
    response["Cache-Control"] = "private, no-cache, no-store, must-revalidate"
    response["X-Accel-Buffering"] = "no"
    return response
