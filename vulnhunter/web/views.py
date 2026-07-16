from __future__ import annotations

import json
from pathlib import Path

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LoginView
from django.db import DatabaseError, connection
from django.http import Http404, HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import redirect, render
from django.views.decorators.cache import cache_control
from django.views.decorators.http import require_GET, require_http_methods

from vulnhunter.agent import AgentStore, AgentStoreError
from vulnhunter.approvals import ApprovalStatus, ApprovalStore
from vulnhunter.approvals.store import ApprovalStoreError
from vulnhunter.authorization.store import AuthorizationStore
from vulnhunter.exceptions import GovernanceError
from vulnhunter.product import ProductServiceError
from vulnhunter.web.forms import StopRunForm, VulnHunterAuthenticationForm
from vulnhunter.web.services import (
    WebCapabilityUnavailable,
    WebPermissionDenied,
    activity_payload,
    authorized_actor,
    control_availability,
    get_pilot_plan_record,
    governance_store,
    intelligence_status,
    list_pilot_plan_records,
    navigation_for,
    product_service,
    stop_agent_run,
)


class VulnHunterLoginView(LoginView):
    authentication_form = VulnHunterAuthenticationForm
    template_name = "web/login.html"
    redirect_authenticated_user = True


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


def _protected(
    request: HttpRequest,
    *,
    required_actions: tuple[str, ...],
):
    return authorized_actor(request.user, required_actions=required_actions)


def _denied(request: HttpRequest, message: str, *, status: int = 403) -> HttpResponse:
    return _render(
        request,
        "web/denied.html",
        {
            "page_title": "Access Denied",
            "denied_message": message,
        },
        status=status,
    )


def _after_sequence_or_400(request: HttpRequest) -> int:
    raw_value = request.GET.get("after_sequence", "0")
    try:
        value = int(raw_value)
    except (TypeError, ValueError) as exc:
        raise ValueError("after_sequence must be a non-negative integer") from exc
    return max(0, value)


def _approval_context_for_run(run_id: str) -> tuple[object | None, object | None]:
    """Return the latest and actionable approval records for one run.

    This lookup never starts execution. It only reads the approval ledger so the
    web surface can show a real decision dialog instead of a decorative card.
    """

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


@require_GET
def health_view(request: HttpRequest) -> JsonResponse:
    del request
    return JsonResponse({"status": "ok"})


@require_GET
def deployment_readiness_view(request: HttpRequest) -> JsonResponse:
    """Return minimal hosting readiness without activating external capabilities."""

    del request
    database_ready = False
    configuration_ready = False
    agent_store_ready = False
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            database_ready = cursor.fetchone() == (1,)
    except DatabaseError:
        database_ready = False

    try:
        runtime_path = Path(settings.VULNHUNTER_SECURITY_TOOL_CONFIG).resolve(strict=True)
        runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
        configuration_ready = (
            isinstance(runtime, dict)
            and runtime.get("schema_version") == "1.0"
            and isinstance(runtime.get("execution_enabled"), bool)
        )
    except (OSError, json.JSONDecodeError, RuntimeError):
        configuration_ready = False

    try:
        agent_store_ready = (
            AgentStore.open_existing(Path(settings.VULNHUNTER_AGENT_DATABASE)).schema_version() == 1
        )
    except AgentStoreError:
        agent_store_ready = False

    ready = database_ready and configuration_ready and agent_store_ready
    return JsonResponse(
        {
            "status": "ready" if ready else "unready",
            "checks": {
                "configuration": "ok" if configuration_ready else "failed",
                "database": "ok" if database_ready else "failed",
                "agent_store": "ok" if agent_store_ready else "failed",
            },
        },
        status=200 if ready else 503,
    )


@cache_control(private=True, no_store=True)
@require_http_methods(["POST"])
def logout_view(request: HttpRequest) -> HttpResponse:
    logout(request)
    return redirect("web-login")


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def dashboard_view(request: HttpRequest) -> HttpResponse:
    try:
        _protected(request, required_actions=("dashboard.read",))
    except WebPermissionDenied as exc:
        return _denied(request, str(exc))
    summary = product_service().load_dashboard()
    return _render(
        request,
        "web/dashboard.html",
        {"page_title": "Dashboard", "dashboard": summary},
    )


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def status_view(request: HttpRequest) -> HttpResponse:
    try:
        _protected(request, required_actions=("audit.read", "dashboard.read"))
    except WebPermissionDenied as exc:
        return _denied(request, str(exc))
    status = product_service().load_status()
    return _render(
        request,
        "web/status.html",
        {"page_title": "System Status", "status_summary": status},
    )


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def authorization_list_view(request: HttpRequest) -> HttpResponse:
    try:
        _protected(request, required_actions=("authorization.read",))
    except WebPermissionDenied as exc:
        return _denied(request, str(exc))

    error_message = None
    try:
        store = AuthorizationStore.from_path(Path(settings.VULNHUNTER_AUTHORIZATION_DATABASE))
        store.initialize()
        authorizations = store.list(limit=250)
    except (OSError, RuntimeError, ValueError) as exc:
        authorizations = ()
        error_message = str(exc)
    return _render(
        request,
        "web/authorizations_overview.html",
        {
            "page_title": "Authorizations",
            "authorizations": authorizations,
            "error_message": error_message,
        },
    )


def _identity_assignments(identity_id: str) -> tuple[tuple[object, object], ...]:
    records: list[tuple[object, object]] = []
    store = governance_store()
    store.initialize()
    for campaign in store.list_campaigns():
        for assignment in store.list_assignments(campaign.campaign_id):
            records.append((campaign, assignment))
    return tuple(records)


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def review_queue_view(request: HttpRequest) -> HttpResponse:
    try:
        actor = _protected(request, required_actions=("review.read", "review.read_assigned"))
    except WebPermissionDenied as exc:
        return _denied(request, str(exc))

    error_message = None
    try:
        assignments = tuple(
            (campaign, assignment)
            for campaign, assignment in _identity_assignments(actor.governance_identity.reviewer_id)
            if actor.governance_identity.reviewer_id in assignment.primary_reviewers
        )
    except (GovernanceError, OSError, RuntimeError) as exc:
        assignments = ()
        error_message = str(exc)
    return _render(
        request,
        "web/review_queue.html",
        {
            "page_title": "Review Queue",
            "assignments": assignments,
            "error_message": error_message,
        },
    )


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def adjudication_queue_view(request: HttpRequest) -> HttpResponse:
    try:
        actor = _protected(
            request,
            required_actions=("adjudication.read", "adjudication.read_assigned"),
        )
    except WebPermissionDenied as exc:
        return _denied(request, str(exc))

    error_message = None
    try:
        assignments = tuple(
            (campaign, assignment)
            for campaign, assignment in _identity_assignments(actor.governance_identity.reviewer_id)
            if assignment.adjudicator_id == actor.governance_identity.reviewer_id
        )
    except (GovernanceError, OSError, RuntimeError) as exc:
        assignments = ()
        error_message = str(exc)
    return _render(
        request,
        "web/adjudications_overview.html",
        {
            "page_title": "Adjudications",
            "assignments": assignments,
            "error_message": error_message,
        },
    )


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def release_list_view(request: HttpRequest) -> HttpResponse:
    try:
        _protected(request, required_actions=("release.read",))
    except WebPermissionDenied as exc:
        return _denied(request, str(exc))
    try:
        campaigns = product_service().list_campaigns()
        error_message = None
    except ProductServiceError as exc:
        campaigns = ()
        error_message = str(exc)
    return _render(
        request,
        "web/releases_overview.html",
        {
            "page_title": "Releases",
            "campaigns": campaigns,
            "error_message": error_message,
        },
    )


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def dataset_list_view(request: HttpRequest) -> HttpResponse:
    try:
        _protected(request, required_actions=("dataset.read",))
    except WebPermissionDenied as exc:
        return _denied(request, str(exc))
    try:
        campaigns = product_service().list_campaigns()
        error_message = None
    except ProductServiceError as exc:
        campaigns = ()
        error_message = str(exc)
    return _render(
        request,
        "web/datasets_overview.html",
        {
            "page_title": "Datasets",
            "campaigns": campaigns,
            "error_message": error_message,
        },
    )


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def model_list_view(request: HttpRequest) -> HttpResponse:
    try:
        _protected(request, required_actions=("model.read", "audit.read"))
    except WebPermissionDenied as exc:
        return _denied(request, str(exc))
    return _render(
        request,
        "web/models_overview.html",
        {
            "page_title": "Models",
            "intelligence_status": intelligence_status(),
        },
    )


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def campaign_list_view(request: HttpRequest) -> HttpResponse:
    try:
        _protected(request, required_actions=("campaign.read",))
    except WebPermissionDenied as exc:
        return _denied(request, str(exc))
    try:
        campaigns = product_service().list_campaigns()
    except ProductServiceError as exc:
        campaigns = ()
        error = str(exc)
    else:
        error = None
    return _render(
        request,
        "web/campaigns.html",
        {"page_title": "Campaigns", "campaigns": campaigns, "error_message": error},
    )


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def campaign_detail_view(request: HttpRequest, campaign_id: str) -> HttpResponse:
    try:
        _protected(request, required_actions=("campaign.read",))
    except WebPermissionDenied as exc:
        return _denied(request, str(exc))
    try:
        campaign = product_service().get_campaign(campaign_id)
    except ProductServiceError as exc:
        raise Http404(str(exc)) from exc
    return _render(
        request,
        "web/campaign_detail.html",
        {"page_title": f"Campaign {campaign.campaign_id}", "campaign": campaign},
    )


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def readiness_view(request: HttpRequest, campaign_id: str) -> HttpResponse:
    try:
        _protected(request, required_actions=("campaign.read",))
    except WebPermissionDenied as exc:
        return _denied(request, str(exc))
    try:
        campaign = product_service().get_campaign(campaign_id)
    except ProductServiceError as exc:
        raise Http404(str(exc)) from exc
    return _render(
        request,
        "web/readiness.html",
        {
            "page_title": f"Readiness {campaign.campaign_id}",
            "campaign": campaign,
            "readiness": campaign.readiness,
        },
    )


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def role_list_view(request: HttpRequest) -> HttpResponse:
    try:
        _protected(request, required_actions=("audit.read",))
    except WebPermissionDenied as exc:
        return _denied(request, str(exc))
    roles = product_service().list_roles()
    return _render(request, "web/roles.html", {"page_title": "Roles", "roles": roles})


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def role_detail_view(request: HttpRequest, role_id: str) -> HttpResponse:
    try:
        _protected(request, required_actions=("audit.read",))
    except WebPermissionDenied as exc:
        return _denied(request, str(exc))
    try:
        role = product_service().get_role(role_id)
    except ProductServiceError as exc:
        raise Http404(str(exc)) from exc
    return _render(
        request,
        "web/role_detail.html",
        {"page_title": role.display_name, "role": role},
    )


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def skill_list_view(request: HttpRequest) -> HttpResponse:
    try:
        _protected(request, required_actions=("audit.read",))
    except WebPermissionDenied as exc:
        return _denied(request, str(exc))
    skills = product_service().list_skills()
    return _render(request, "web/skills.html", {"page_title": "Skills", "skills": skills})


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def skill_detail_view(request: HttpRequest, skill_id: str) -> HttpResponse:
    try:
        _protected(request, required_actions=("audit.read",))
    except WebPermissionDenied as exc:
        return _denied(request, str(exc))
    try:
        skill = product_service().get_skill(skill_id)
    except ProductServiceError as exc:
        raise Http404(str(exc)) from exc
    return _render(
        request,
        "web/skill_detail.html",
        {"page_title": skill.display_name, "skill": skill},
    )


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def agent_run_list_view(request: HttpRequest) -> HttpResponse:
    try:
        _protected(request, required_actions=("audit.read", "scan.read"))
    except WebPermissionDenied as exc:
        return _denied(request, str(exc))
    try:
        runs = product_service().list_agent_runs()
    except ProductServiceError as exc:
        runs = ()
        error = str(exc)
    else:
        error = None
    return _render(
        request,
        "web/agent_runs.html",
        {"page_title": "Agent Runs", "runs": runs, "error_message": error},
    )


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def agent_run_detail_view(request: HttpRequest, run_id: str) -> HttpResponse:
    try:
        actor = _protected(request, required_actions=("audit.read", "scan.read"))
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
            "page_title": f"Agent Run {run.run_id}",
            "run": run,
            "timeline": timeline,
            "controls": controls,
            "actor": actor,
            "approval_record": approval_record,
            "pending_approval": pending_approval,
            "can_decide_approval": can_decide_approval,
        },
    )


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def agent_activity_view(request: HttpRequest, run_id: str) -> JsonResponse:
    try:
        _protected(request, required_actions=("audit.read", "scan.read"))
    except WebPermissionDenied:
        return JsonResponse({"detail": "forbidden"}, status=403)
    try:
        product_service().get_agent_run(run_id)
    except ProductServiceError as exc:
        raise Http404(str(exc)) from exc
    try:
        after_sequence = _after_sequence_or_400(request)
    except ValueError as exc:
        return JsonResponse({"detail": str(exc)}, status=400)
    return JsonResponse(activity_payload(run_id, after_sequence=after_sequence))


@cache_control(private=True, no_store=True)
@login_required
@require_http_methods(["GET", "POST"])
def stop_run_view(request: HttpRequest, run_id: str) -> HttpResponse:
    try:
        _protected(request, required_actions=("audit.read", "scan.read"))
    except WebPermissionDenied as exc:
        return _denied(request, str(exc))
    try:
        run = product_service().get_agent_run(run_id)
    except ProductServiceError as exc:
        raise Http404(str(exc)) from exc

    controls = control_availability(request.user, run.current_state, run.approval_state.value)
    stop_control = controls["stop"]
    if request.method == "POST":
        if not bool(stop_control["available"]):
            return _render(
                request,
                "web/stop_run_confirm.html",
                {
                    "page_title": f"Stop {run.run_id}",
                    "run": run,
                    "form": StopRunForm(request.POST),
                    "stop_control": stop_control,
                },
                status=403,
            )
        form = StopRunForm(request.POST)
        if form.is_valid():
            try:
                stop_agent_run(request.user, run_id=run_id, reason=form.cleaned_data["reason"])
            except (WebPermissionDenied, WebCapabilityUnavailable) as exc:
                messages.error(request, str(exc))
            else:
                messages.success(
                    request,
                    "The cancellation request was recorded and the run moved to cancelled. "
                    "In-flight bounded tool work may still finish or time out.",
                )
                return redirect("web-agent-run-detail", run_id=run_id)
    else:
        form = StopRunForm()
    return _render(
        request,
        "web/stop_run_confirm.html",
        {
            "page_title": f"Stop {run.run_id}",
            "run": run,
            "form": form,
            "stop_control": stop_control,
        },
        status=200 if bool(stop_control["available"]) else 403,
    )


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def pilot_plan_list_view(request: HttpRequest) -> HttpResponse:
    try:
        _protected(request, required_actions=("campaign.read", "report.read"))
    except WebPermissionDenied as exc:
        return _denied(request, str(exc))
    records = list_pilot_plan_records()
    return _render(
        request,
        "web/pilot_plans.html",
        {"page_title": "Pilot Plans", "records": records},
    )


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def pilot_plan_detail_view(request: HttpRequest, plan_id: str) -> HttpResponse:
    try:
        _protected(request, required_actions=("campaign.read", "report.read"))
    except WebPermissionDenied as exc:
        return _denied(request, str(exc))
    try:
        record = get_pilot_plan_record(plan_id)
    except FileNotFoundError as exc:
        raise Http404(str(exc)) from exc
    return _render(
        request,
        "web/pilot_plan_detail.html",
        {"page_title": f"Pilot Plan {record.plan_id}", "record": record},
    )


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def pilot_plan_validation_view(request: HttpRequest, plan_id: str) -> HttpResponse:
    try:
        _protected(request, required_actions=("campaign.read", "report.read"))
    except WebPermissionDenied as exc:
        return _denied(request, str(exc))
    try:
        record = get_pilot_plan_record(plan_id)
    except FileNotFoundError as exc:
        raise Http404(str(exc)) from exc
    return _render(
        request,
        "web/pilot_plan_validation.html",
        {"page_title": f"Validation {record.plan_id}", "record": record},
    )


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def findings_overview_view(request: HttpRequest) -> HttpResponse:
    """Truthful entry point for the unified finding lifecycle."""

    try:
        _protected(request, required_actions=("audit.read", "scan.read"))
    except WebPermissionDenied as exc:
        return _denied(request, str(exc))
    capabilities = (
        ("Deterministic deduplication", "ready"),
        ("Evidence provenance and hashes", "ready"),
        ("Analyst verification workflow", "ready"),
        ("Remediation and retest lifecycle", "ready"),
        ("Live external scanner findings", "activation required"),
    )
    return _render(
        request,
        "web/findings_overview.html",
        {"page_title": "Findings", "capabilities": capabilities},
    )


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def oracle_overview_view(request: HttpRequest) -> HttpResponse:
    """Show Oracle readiness without implying a live verifier is activated."""

    try:
        _protected(request, required_actions=("audit.read", "scan.read"))
    except WebPermissionDenied as exc:
        return _denied(request, str(exc))
    checks = (
        ("Proof-capsule validation", "ready"),
        ("Authenticated response contract", "ready"),
        ("Durable replay protection", "ready"),
        ("Transactional session history", "ready"),
        ("Live independent verifier", "disabled until manually activated"),
    )
    return _render(
        request,
        "web/oracle_overview.html",
        {"page_title": "Machine Oracle", "oracle_checks": checks},
    )


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def reports_overview_view(request: HttpRequest) -> HttpResponse:
    try:
        _protected(request, required_actions=("campaign.read", "report.read"))
    except WebPermissionDenied as exc:
        return _denied(request, str(exc))
    formats = (
        ("HTML", "available"),
        ("JSON", "available"),
        ("SARIF", "available"),
        ("Evidence ZIP", "available"),
        ("Attack-path SVG", "available"),
        ("PDF", "renderer activation required"),
    )
    return _render(
        request,
        "web/reports_overview.html",
        {"page_title": "Reports", "report_formats": formats},
    )


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def governance_overview_view(request: HttpRequest) -> HttpResponse:
    try:
        _protected(request, required_actions=("campaign.read", "audit.read"))
    except WebPermissionDenied as exc:
        return _denied(request, str(exc))
    return _render(request, "web/governance_overview.html", {"page_title": "Governance"})


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def settings_overview_view(request: HttpRequest) -> HttpResponse:
    try:
        _protected(request, required_actions=("audit.read", "dashboard.read"))
    except WebPermissionDenied as exc:
        return _denied(request, str(exc))
    return _render(
        request,
        "web/settings_overview.html",
        {"page_title": "Settings", "intelligence_status": intelligence_status()},
    )
