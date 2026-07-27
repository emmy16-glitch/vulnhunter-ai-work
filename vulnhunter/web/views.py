from __future__ import annotations

import json
import sqlite3
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
from vulnhunter.authorization.models import AuthorizationEvent, AuthorizationRecord
from vulnhunter.authorization.store import AuthorizationStore
from vulnhunter.exceptions import (
    AuthorizationError,
    AuthorizationNotFoundError,
    AuthorizationPolicyError,
    GovernanceError,
)
from vulnhunter.product import ProductNotFoundError, ProductServiceError
from vulnhunter.web.forms import (
    AuthorizationRevokeForm,
    StopRunForm,
    VulnHunterAuthenticationForm,
)
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
    operational_unavailable,
    product_service,
    role_policy,
    run_controllable_by_actor,
    run_readable_to_actor,
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
        {"page_title": "Assessment Workspace", "dashboard": summary},
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


def _authorization_record_data(
    authorization_id: str,
) -> tuple[AuthorizationStore, AuthorizationRecord, tuple[AuthorizationEvent, ...]]:
    store = AuthorizationStore.from_path(Path(settings.VULNHUNTER_AUTHORIZATION_DATABASE))
    store.initialize()
    authorization = store.get(authorization_id)
    events = store.list_events(authorization_id, limit=250)
    return store, authorization, events


def _render_authorization_detail(
    request: HttpRequest,
    *,
    authorization: AuthorizationRecord,
    events: tuple[AuthorizationEvent, ...],
    can_revoke: bool,
    revoke_form: AuthorizationRevokeForm | None = None,
    status: int = 200,
) -> HttpResponse:
    return _render(
        request,
        "web/authorization_detail.html",
        {
            "page_title": "Authorization Detail",
            "authorization": authorization,
            "events": events,
            "can_revoke": can_revoke,
            "revoke_form": (
                revoke_form if revoke_form is not None else AuthorizationRevokeForm()
            ),
        },
        status=status,
    )


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def authorization_list_view(request: HttpRequest) -> HttpResponse:
    try:
        _protected(request, required_actions=("authorization.read",))
    except WebPermissionDenied as exc:
        return _denied(request, str(exc))

    try:
        store = AuthorizationStore.from_path(Path(settings.VULNHUNTER_AUTHORIZATION_DATABASE))
        store.initialize()
        authorizations = store.list(limit=250)
    except (AuthorizationError, OSError, RuntimeError, ValueError, sqlite3.Error):
        return operational_unavailable(
            request,
            "Authorization records are temporarily unavailable.",
        )
    return _render(
        request,
        "web/authorizations_overview.html",
        {
            "page_title": "Authorizations",
            "authorizations": authorizations,
        },
    )


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def authorization_detail_view(
    request: HttpRequest,
    authorization_id: str,
) -> HttpResponse:
    try:
        actor = _protected(request, required_actions=("authorization.read",))
    except WebPermissionDenied as exc:
        return _denied(request, str(exc))

    try:
        _, authorization, events = _authorization_record_data(authorization_id)
    except AuthorizationNotFoundError as exc:
        raise Http404("Authorization record not found.") from exc
    except (AuthorizationError, OSError, RuntimeError, ValueError, sqlite3.Error):
        return operational_unavailable(
            request,
            "Authorization records are temporarily unavailable.",
        )

    can_revoke = role_policy().any_role_allows(actor.product_roles, "settings.manage")
    return _render_authorization_detail(
        request,
        authorization=authorization,
        events=events,
        can_revoke=can_revoke,
    )


@cache_control(private=True, no_store=True)
@login_required
@require_http_methods(["POST"])
def authorization_revoke_view(
    request: HttpRequest,
    authorization_id: str,
) -> HttpResponse:
    try:
        _protected(request, required_actions=("settings.manage",))
    except WebPermissionDenied as exc:
        return _denied(request, str(exc))

    form = AuthorizationRevokeForm(request.POST)
    try:
        store, authorization, events = _authorization_record_data(authorization_id)
    except AuthorizationNotFoundError as exc:
        raise Http404("Authorization record not found.") from exc
    except (AuthorizationError, OSError, RuntimeError, ValueError, sqlite3.Error):
        return operational_unavailable(
            request,
            "Authorization records are temporarily unavailable.",
        )

    if not form.is_valid():
        return _render_authorization_detail(
            request,
            authorization=authorization,
            events=events,
            can_revoke=True,
            revoke_form=form,
            status=400,
        )

    try:
        store.revoke(authorization_id, reason=form.cleaned_data["reason"])
    except AuthorizationNotFoundError as exc:
        raise Http404("Authorization record not found.") from exc
    except AuthorizationPolicyError as exc:
        form.add_error(None, str(exc))
        try:
            _, authorization, events = _authorization_record_data(authorization_id)
        except (AuthorizationError, OSError, RuntimeError, ValueError, sqlite3.Error):
            return operational_unavailable(
                request,
                "Authorization records are temporarily unavailable.",
            )
        return _render_authorization_detail(
            request,
            authorization=authorization,
            events=events,
            can_revoke=authorization.status == "active",
            revoke_form=form,
            status=409,
        )
    except (AuthorizationError, OSError, RuntimeError, ValueError, sqlite3.Error):
        return operational_unavailable(
            request,
            "Authorization records are temporarily unavailable.",
        )

    messages.success(request, "Authorization revoked. Future validation will fail closed.")
    return redirect("web-authorization-detail", authorization_id=authorization_id)


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
        actor = _protected(request, required_actions=("review.read_assigned",))
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
            required_actions=("adjudication.read_assigned",),
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
def campaign_list_view(request: HttpRequest) -> HttpResponse:
    try:
        actor = _protected(
            request,
            required_actions=("campaign.read", "campaign.read_summary"),
        )
    except WebPermissionDenied as exc:
        return _denied(request, str(exc))
    summary_only = role_policy().any_role_allows(
        actor.product_roles, "campaign.read_summary"
    ) and not role_policy().any_role_allows(actor.product_roles, "campaign.read")
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
        {
            "page_title": "Campaigns",
            "campaigns": campaigns,
            "error_message": error,
            "summary_only": summary_only,
        },
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
    except ProductNotFoundError as exc:
        raise Http404(str(exc)) from exc
    except ProductServiceError:
        return operational_unavailable(request)
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
    except ProductNotFoundError as exc:
        raise Http404(str(exc)) from exc
    except ProductServiceError:
        return operational_unavailable(request)
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
    try:
        roles = product_service().list_roles()
    except ProductServiceError as exc:
        roles = ()
        error_message = str(exc)
    else:
        error_message = None
    return _render(
        request,
        "web/roles.html",
        {"page_title": "Roles", "roles": roles, "error_message": error_message},
    )


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
    except ProductNotFoundError as exc:
        raise Http404(str(exc)) from exc
    except ProductServiceError:
        return operational_unavailable(request)
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
    try:
        skills = product_service().list_skills()
    except ProductServiceError as exc:
        skills = ()
        error_message = str(exc)
    else:
        error_message = None
    return _render(
        request,
        "web/skills.html",
        {"page_title": "Skills", "skills": skills, "error_message": error_message},
    )


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
    except ProductNotFoundError as exc:
        raise Http404(str(exc)) from exc
    except ProductServiceError:
        return operational_unavailable(request)
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
        actor = _protected(request, required_actions=("audit.read", "scan.read"))
    except WebPermissionDenied as exc:
        return _denied(request, str(exc))
    try:
        runs = tuple(
            run for run in product_service().list_agent_runs() if run_readable_to_actor(run, actor)
        )
    except ProductServiceError as exc:
        runs = ()
        error = str(exc)
    else:
        error = None
    return _render(
        request,
        "web/agent_runs.html",
        {"page_title": "Assessment History", "runs": runs, "error_message": error},
    )


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def agent_activity_view(request: HttpRequest, run_id: str) -> JsonResponse:
    try:
        actor = _protected(request, required_actions=("audit.read", "scan.read"))
    except WebPermissionDenied:
        return JsonResponse({"detail": "forbidden"}, status=403)
    try:
        run = product_service().get_agent_run(run_id)
    except ProductNotFoundError as exc:
        raise Http404(str(exc)) from exc
    except ProductServiceError:
        return JsonResponse({"detail": "assessment service unavailable"}, status=503)
    if not run_readable_to_actor(run, actor):
        raise Http404("Assessment run does not exist.")
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
        actor = _protected(request, required_actions=("audit.read", "scan.read"))
    except WebPermissionDenied as exc:
        return _denied(request, str(exc))
    try:
        run = product_service().get_agent_run(run_id)
    except ProductNotFoundError as exc:
        raise Http404(str(exc)) from exc
    except ProductServiceError:
        return operational_unavailable(request)
    if not run_controllable_by_actor(run, actor):
        raise Http404("Assessment run does not exist.")

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
        actor = _protected(request, required_actions=("audit.read", "dashboard.read"))
    except WebPermissionDenied as exc:
        return _denied(request, str(exc))

    status = product_service().load_status()
    state_copy = {
        "available": "Validated and available.",
        "empty": "Configured and healthy; no records exist yet.",
        "missing": "Required local state has not been created.",
        "invalid": "Configuration or integrity validation failed.",
        "unavailable": "A required dependency is not available.",
    }
    capability_rows = tuple(
        {
            "name": name,
            "state": capability.state.value,
            "detail": state_copy.get(capability.state.value, "State reported by the backend."),
        }
        for name, capability in (
            ("Authorization store", status.authorization_store),
            ("Governance store", status.governance_store),
            ("Role and skill registry", status.role_registry),
            ("Bounded agent runtime", status.agent_runtime),
            ("Dataset readiness", status.readiness),
            ("Audit evidence", status.audit_evidence),
        )
    )

    mobile_policy = Path(settings.VULNHUNTER_MOBILE_STATIC_WORKER_POLICY)
    activation_rows = (
        {
            "name": "Passive Nuclei enqueue",
            "enabled": bool(settings.VULNHUNTER_NUCLEI_PILOT_ENQUEUE_ENABLED),
            "detail": (
                "Approved plans may be written to the signed worker spool."
                if settings.VULNHUNTER_NUCLEI_PILOT_ENQUEUE_ENABLED
                else (
                    "Gated until the reviewed worker policy, signing key "
                    "and local target are ready."
                )
            ),
            "link": "web-security-tool-registry",
        },
        {
            "name": "Controlled active validation",
            "enabled": bool(settings.VULNHUNTER_ADVERSARY_LAB_ENABLED),
            "detail": (
                "Synthetic isolated validation workspaces are available."
                if settings.VULNHUNTER_ADVERSARY_LAB_ENABLED
                else "Gated in this environment; existing evidence remains readable."
            ),
            "link": "web-scan-run-list",
        },
        {
            "name": "Repository graph refresh",
            "enabled": bool(settings.VULNHUNTER_GRAPHIFY_EXECUTION_ENABLED),
            "detail": (
                "Explicit repository graph generation is enabled."
                if settings.VULNHUNTER_GRAPHIFY_EXECUTION_ENABLED
                else (
                    "Validated graph loading is available; explicit rebuild "
                    "execution remains gated."
                )
            ),
            "link": "web-model-list",
        },
        {
            "name": "Sanitized advisory analysis",
            "enabled": bool(settings.VULNHUNTER_GROQ_ENABLED),
            "detail": (
                "Bounded advisory health checks are enabled; the provider "
                "remains non-authoritative."
                if settings.VULNHUNTER_GROQ_ENABLED
                else (
                    "Optional remote advisory routing is gated; deterministic workflows continue."
                )
            ),
            "link": "web-model-list",
        },
        {
            "name": "Mobile static worker policy",
            "enabled": mobile_policy.is_file(),
            "detail": (
                "A local networkless static-analysis policy is present."
                if mobile_policy.is_file()
                else "Upload is available, but no reviewed static worker policy is present."
            ),
            "link": "web-mobile-analysis",
        },
    )
    enabled_count = sum(1 for row in activation_rows if row["enabled"])
    healthy_count = sum(1 for row in capability_rows if row["state"] in {"available", "empty"})
    security_rows = (
        {
            "name": "Django debug",
            "safe": not settings.DEBUG,
            "value": "Off" if not settings.DEBUG else "On",
        },
        {
            "name": "HTTPS enforcement",
            "safe": bool(settings.SECURE_SSL_REDIRECT),
            "value": "Required" if settings.SECURE_SSL_REDIRECT else "Local-only",
        },
        {
            "name": "Session cookie",
            "safe": bool(settings.SESSION_COOKIE_HTTPONLY),
            "value": "HttpOnly",
        },
        {
            "name": "CSRF cookie",
            "safe": bool(settings.CSRF_COOKIE_HTTPONLY),
            "value": "HttpOnly",
        },
        {
            "name": "Frame embedding",
            "safe": settings.X_FRAME_OPTIONS == "DENY",
            "value": settings.X_FRAME_OPTIONS,
        },
        {
            "name": "Content Security Policy",
            "safe": bool(settings.VULNHUNTER_CSP),
            "value": "Same-origin",
        },
    )
    identity = actor.governance_identity
    related_controls = (
        {
            "label": "Integrations & Tools",
            "detail": "Inspect registered tools and activation readiness.",
            "url_name": "web-security-tool-registry",
            "icon": "link",
            "actions": ("audit.read", "scan.read"),
        },
        {
            "label": "Governance policies",
            "detail": "Review policy, role and release boundaries.",
            "url_name": "web-governance-overview",
            "icon": "policy",
            "actions": ("campaign.read", "audit.read"),
        },
        {
            "label": "Role registry",
            "detail": "Inspect role definitions and allowed actions.",
            "url_name": "web-role-list",
            "icon": "team",
            "actions": ("audit.read",),
        },
        {
            "label": "Skill registry",
            "detail": "Inspect governed skill definitions and boundaries.",
            "url_name": "web-skill-list",
            "icon": "policy",
            "actions": ("audit.read",),
        },
        {
            "label": "System status",
            "detail": "Review current backend readiness and store health.",
            "url_name": "web-status",
            "icon": "activity",
            "actions": ("audit.read", "dashboard.read"),
        },
    )
    policy = role_policy()
    management_links = tuple(
        item
        for item in related_controls
        if policy.any_role_allows(actor.product_roles, *item["actions"])
    )
    return _render(
        request,
        "web/settings_overview.html",
        {
            "page_title": "Settings",
            "intelligence_status": intelligence_status(),
            "capability_rows": capability_rows,
            "activation_rows": activation_rows,
            "enabled_count": enabled_count,
            "healthy_count": healthy_count,
            "security_rows": security_rows,
            "identity": identity,
            "product_roles": actor.product_roles,
            "management_links": management_links,
            "database_engine": settings.DATABASES["default"]["ENGINE"].rsplit(".", 1)[-1],
            "environment_label": "Local debug" if settings.DEBUG else "Hardened runtime",
        },
    )
