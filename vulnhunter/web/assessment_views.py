"""Authenticated assessment workflow surfaces.

Web launch creates a persisted, non-executing bounded task. Scanner execution,
network access, approval consumption, and provider activation remain controlled by
the existing runtime and cannot be enabled from these views.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import redirect
from django.views.decorators.cache import cache_control
from django.views.decorators.http import require_GET, require_http_methods

from vulnhunter.agent.models import AgentTask, PermissionManifest, ToolRisk
from vulnhunter.agent.store import AgentStore, AgentStoreError
from vulnhunter.agent_activity.store import ActivityStoreError
from vulnhunter.approvals import ApprovalStatus, ApprovalStore
from vulnhunter.approvals.store import ApprovalStoreError
from vulnhunter.authorization.models import AuthorizationRecord
from vulnhunter.authorization.store import AuthorizationStore
from vulnhunter.product import ProductServiceError
from vulnhunter.web.assessment_profiles import assessment_profile, assessment_profiles
from vulnhunter.web.assessment_projection import build_assessment_projection
from vulnhunter.web.forms import NewAssessmentForm
from vulnhunter.web.services import (
    WebPermissionDenied,
    activity_payload,
    activity_service,
    authorized_actor,
    control_availability,
    product_service,
)
from vulnhunter.web.views import _denied, _render


def _authorization_rows() -> tuple[tuple[AuthorizationRecord, ...], tuple[dict[str, str], ...]]:
    store = AuthorizationStore.from_path(Path(settings.VULNHUNTER_AUTHORIZATION_DATABASE))
    store.initialize()
    now = datetime.now(UTC)
    records = tuple(
        record
        for record in store.list(limit=250)
        if record.status == "active" and record.valid_from <= now < record.expires_at
    )
    rows = tuple(
        {
            "id": record.authorization_id,
            "label": f"{record.hostname}:{record.port}{record.path_boundary}",
            "target": record.target_url,
            "scope": f"{record.scheme}://{record.hostname}:{record.port}{record.path_boundary}",
            "owner": record.owner,
            "expires_at": record.expires_at.isoformat(),
            "record_sha256": record.record_sha256,
        }
        for record in records
    )
    return records, rows


def _launch_context(request: HttpRequest, *, bound_form: NewAssessmentForm | None = None):
    try:
        records, authorization_rows = _authorization_rows()
        error_message = None
    except (OSError, RuntimeError, ValueError) as exc:
        records = ()
        authorization_rows = ()
        error_message = str(exc)
    profiles = assessment_profiles()
    form = bound_form or NewAssessmentForm(
        authorization_rows=authorization_rows,
        profile_rows=profiles,
    )
    return {
        "records": records,
        "authorization_rows": authorization_rows,
        "profiles": profiles,
        "launch_form": form,
        "error_message": error_message,
    }


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
    actionable_states = {
        ApprovalStatus.PENDING,
        ApprovalStatus.INFORMATION_REQUIRED,
        ApprovalStatus.CONDITIONS_PROPOSED,
    }
    actionable = next(
        (
            item
            for item in sorted(records, key=lambda item: item.requested_at, reverse=True)
            if item.status in actionable_states
        ),
        None,
    )
    return latest, actionable


def _create_launch_task(
    *,
    record: AuthorizationRecord,
    profile: dict[str, str],
    objective: str,
    actor_id: str,
) -> AgentTask:
    run_id = f"run-web-{uuid4().hex[:20]}"
    manifest = PermissionManifest(
        manifest_id=f"manifest-{uuid4().hex[:20]}",
        role_id="orchestrator",
        skill_id="bounded-task-routing",
        allowed_actions=("task.plan",),
        allowed_tools=("repository.read",),
        allowed_risks=(ToolRisk.READ_ONLY,),
        max_steps=1,
        max_tool_calls=1,
        maximum_runtime_seconds=3_600,
        allow_network=False,
        allow_connectors=False,
        allow_secrets=False,
        allow_git_write=False,
        allow_deployment=False,
    )
    task = AgentTask(
        task_id=run_id,
        objective=objective,
        permission_manifest=manifest,
        memory={
            "launch_source": "web",
            "launch_actor_id": actor_id,
            "authorization_id": record.authorization_id,
            "authorization_record_sha256": record.record_sha256,
            "profile_id": profile["id"],
            "profile_name": profile["name"],
            "input_summary": f"{profile['name']} launch request for {record.hostname}",
            "scope_summary": (
                f"{record.scheme}://{record.hostname}:{record.port}{record.path_boundary}"
            ),
            "execution_enabled": False,
        },
    )
    store = AgentStore.open_existing(Path(settings.VULNHUNTER_AGENT_DATABASE))
    store.create_task(task)
    store.append_event(
        task.task_id,
        "run.created",
        {
            "source": "web",
            "actor_id": actor_id,
            "authorization_id": record.authorization_id,
            "authorization_record_sha256": record.record_sha256,
            "profile_id": profile["id"],
            "execution_enabled": False,
        },
    )
    store.append_event(
        task.task_id,
        "authorization.bound",
        {
            "authorization_id": record.authorization_id,
            "target": record.target_url,
            "path_boundary": record.path_boundary,
        },
    )
    return task


def _record_launch_activity(
    task: AgentTask,
    *,
    record: AuthorizationRecord,
    profile: dict[str, str],
    actor_id: str,
) -> None:
    service = activity_service()
    now = datetime.now(UTC)
    common = {
        "run_id": task.task_id,
        "timestamp": now,
        "run_state": "created",
        "authorization_reference": record.authorization_id,
        "scope_reference": record.record_sha256,
        "role_id": task.permission_manifest.role_id,
        "skill_id": task.permission_manifest.skill_id,
        "metadata": {
            "profile_id": profile["id"],
            "target": record.target_url,
            "path_boundary": record.path_boundary,
            "execution_enabled": False,
        },
    }
    service.record_transition(
        **common,
        event_type="run_created",
        summary="A governed web launch request was persisted without starting a scanner.",
        source="operator",
        audit_reference=actor_id,
    )
    service.record_transition(
        **common,
        event_type="objective_received",
        summary="The approved assessment objective and profile were recorded.",
        source="operator",
        audit_reference=actor_id,
    )
    service.record_transition(
        **common,
        event_type="authorization_check_passed",
        summary="The selected authorization record is active, current, and integrity checked.",
        source="system",
        policy_outcome="not_checked",
    )


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def assessment_list_view(request: HttpRequest) -> HttpResponse:
    try:
        authorized_actor(request.user, required_actions=("audit.read", "scan.read"))
    except WebPermissionDenied as exc:
        return _denied(request, str(exc))
    try:
        runs = product_service().list_agent_runs()
        run_error = None
    except ProductServiceError as exc:
        runs = ()
        run_error = str(exc)
    try:
        authorized_actor(request.user, required_actions=("scan.create",))
    except WebPermissionDenied:
        can_create = False
        launch = {
            "authorization_rows": (),
            "profiles": (),
            "launch_form": None,
            "error_message": None,
        }
    else:
        can_create = True
        launch = _launch_context(request)
    return _render(
        request,
        "web/agent_runs.html",
        {
            "page_title": "Assessments",
            "runs": runs,
            "error_message": run_error or launch.get("error_message"),
            "can_create": can_create,
            **launch,
        },
    )


@cache_control(private=True, no_store=True)
@login_required
@require_http_methods(["GET", "POST"])
def new_assessment_view(request: HttpRequest) -> HttpResponse:
    try:
        actor = authorized_actor(request.user, required_actions=("scan.create",))
    except WebPermissionDenied as exc:
        return _denied(request, str(exc))

    launch = _launch_context(request)
    records = launch["records"]
    authorization_rows = launch["authorization_rows"]
    profiles = launch["profiles"]
    if request.method == "POST":
        form = NewAssessmentForm(
            request.POST,
            authorization_rows=authorization_rows,
            profile_rows=profiles,
        )
        launch["launch_form"] = form
        if form.is_valid():
            selected = next(
                (
                    record
                    for record in records
                    if record.authorization_id == form.cleaned_data["authorization_id"]
                ),
                None,
            )
            if selected is None:
                form.add_error("authorization_id", "Select a current active authorization.")
            else:
                try:
                    profile = assessment_profile(form.cleaned_data["profile_id"])
                    objective = form.cleaned_data["objective"] or (
                        f"{profile['name']} for the authorized target {selected.hostname}"
                    )
                    task = _create_launch_task(
                        record=selected,
                        profile=profile,
                        objective=objective,
                        actor_id=actor.governance_identity.reviewer_id,
                    )
                except (AgentStoreError, OSError, RuntimeError, ValueError) as exc:
                    messages.error(request, f"The launch request could not be persisted: {exc}")
                else:
                    try:
                        _record_launch_activity(
                            task,
                            record=selected,
                            profile=profile,
                            actor_id=actor.governance_identity.reviewer_id,
                        )
                    except (ActivityStoreError, OSError, RuntimeError, ValueError) as exc:
                        messages.warning(
                            request,
                            "The run was created, but its live activity projection is unavailable: "
                            f"{exc}",
                        )
                    else:
                        messages.success(
                            request,
                            (
                                "Assessment launch request created. No scanner or network "
                                "operation started."
                            ),
                        )
                    return redirect("web-agent-run-detail", run_id=task.task_id)

    return _render(
        request,
        "web/new_scan.html",
        {
            "page_title": "New Governed Assessment",
            **launch,
        },
    )


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def assessment_detail_view(request: HttpRequest, run_id: str) -> HttpResponse:
    try:
        actor = authorized_actor(request.user, required_actions=("audit.read", "scan.read"))
    except WebPermissionDenied as exc:
        return _denied(request, str(exc))
    try:
        run = product_service().get_agent_run(run_id)
    except ProductServiceError as exc:
        raise Http404(str(exc)) from exc
    timeline = activity_payload(run_id, after_sequence=0)
    controls = control_availability(request.user, run.current_state, run.approval_state.value)
    approval_record, pending_approval = _approval_context_for_run(run_id)
    try:
        authorized_actor(request.user, required_actions=("settings.manage",))
    except WebPermissionDenied:
        can_decide_approval = False
    else:
        can_decide_approval = True
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
            "assessment": build_assessment_projection(run),
        },
    )
