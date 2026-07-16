"""Authenticated web surfaces for approvals, tools, and advanced profiles."""

from __future__ import annotations

from pathlib import Path

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.cache import cache_control
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from vulnhunter.advanced import AssessmentProfile
from vulnhunter.approvals import ApprovalDecision, ApprovalStore
from vulnhunter.approvals.store import (
    ApprovalNotFoundError,
    ApprovalStoreError,
)
from vulnhunter.authorization.store import AuthorizationStore
from vulnhunter.mobile import (
    MobileAnalysisProfile,
    MobileArtifactError,
    MobileArtifactIngestor,
)
from vulnhunter.security_tools.catalog import default_catalog
from vulnhunter.web.forms import MobileApkUploadForm
from vulnhunter.web.services import (
    WebPermissionDenied,
    authorized_actor,
    navigation_for,
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


def _approval_store() -> ApprovalStore:
    store = ApprovalStore(Path(settings.VULNHUNTER_APPROVAL_DATABASE))
    store.initialize()
    return store


def _approval_redirect(request: HttpRequest, request_id: str) -> HttpResponse:
    next_url = request.POST.get("next", "").strip()
    if next_url and url_has_allowed_host_and_scheme(
        next_url,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure(),
    ):
        return redirect(next_url)
    return redirect("web-approval-detail", request_id=request_id)


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def approval_list_view(request: HttpRequest) -> HttpResponse:
    try:
        authorized_actor(request.user, required_actions=("audit.read", "settings.manage"))
    except WebPermissionDenied as exc:
        return _render(
            request,
            "web/denied.html",
            {"page_title": "Access Denied", "denied_message": str(exc)},
            status=403,
        )
    approvals = _approval_store().list()
    return _render(
        request,
        "web/approvals.html",
        {"page_title": "Approval Centre", "approvals": approvals},
    )


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def approval_detail_view(request: HttpRequest, request_id: str) -> HttpResponse:
    try:
        authorized_actor(request.user, required_actions=("audit.read", "settings.manage"))
    except WebPermissionDenied as exc:
        return _render(
            request,
            "web/denied.html",
            {"page_title": "Access Denied", "denied_message": str(exc)},
            status=403,
        )
    store = _approval_store()
    try:
        approval = store.get(request_id)
        events = store.events(request_id)
    except ApprovalNotFoundError as exc:
        raise Http404(str(exc)) from exc
    return _render(
        request,
        "web/approval_detail.html",
        {
            "page_title": f"Approval {approval.request_id}",
            "approval": approval,
            "events": events,
            "decisions": tuple(ApprovalDecision),
        },
    )


@cache_control(private=True, no_store=True)
@login_required
@require_POST
def approval_decision_view(request: HttpRequest, request_id: str) -> HttpResponse:
    try:
        actor = authorized_actor(request.user, required_actions=("settings.manage",))
    except WebPermissionDenied as exc:
        messages.error(request, str(exc))
        return _approval_redirect(request, request_id)

    raw_decision = request.POST.get("decision", "").strip()
    reason = request.POST.get("reason", "").strip()
    conditions = tuple(
        line.strip() for line in request.POST.get("conditions", "").splitlines() if line.strip()
    )
    if len(reason) < 8:
        messages.error(request, "A decision reason of at least eight characters is required.")
        return _approval_redirect(request, request_id)
    try:
        decision = ApprovalDecision(raw_decision)
    except ValueError:
        messages.error(request, "Unknown approval decision.")
        return _approval_redirect(request, request_id)

    try:
        _approval_store().decide(
            request_id=request_id,
            actor_id=actor.governance_identity.reviewer_id,
            decision=decision,
            reason=reason,
            conditions=conditions,
        )
    except ApprovalStoreError as exc:
        messages.error(request, str(exc))
    else:
        messages.success(request, f"Decision recorded: {decision.value}.")
    return _approval_redirect(request, request_id)


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def security_tool_registry_view(request: HttpRequest) -> HttpResponse:
    try:
        authorized_actor(request.user, required_actions=("audit.read", "scan.read"))
    except WebPermissionDenied as exc:
        return _render(
            request,
            "web/denied.html",
            {"page_title": "Access Denied", "denied_message": str(exc)},
            status=403,
        )
    catalog = default_catalog()
    availability = {item.tool_id: item for item in catalog.detect_all()}
    rows = tuple(
        {
            "definition": definition,
            "availability": availability[definition.tool_id],
        }
        for definition in catalog.list()
    )
    return _render(
        request,
        "web/security_tools.html",
        {"page_title": "Security Tool Registry", "tool_rows": rows},
    )


def _assessment_profiles() -> tuple[dict[str, str], ...]:
    return (
        {
            "id": AssessmentProfile.DEEP_DISCOVERY.value,
            "name": "Deep Discovery",
            "description": "Authorised attack-surface and service mapping.",
            "gate": "Campaign scope and network-discovery approval.",
        },
        {
            "id": AssessmentProfile.ACTIVE_ASSESSMENT.value,
            "name": "Active Assessment",
            "description": "Bounded web, TLS and vulnerability assessment.",
            "gate": "Separate active-testing approval.",
        },
        {
            "id": AssessmentProfile.EXPLOITABILITY_VALIDATION.value,
            "name": "Exploitability Validation",
            "description": "Minimum-impact validation of selected candidates.",
            "gate": "Exact-action approval and one-time consumption.",
        },
        {
            "id": AssessmentProfile.PRIVILEGED_ENVIRONMENT.value,
            "name": "Privileged Environment",
            "description": "Short-lived brokered inspection without stored credentials.",
            "gate": "Owner reauthentication and privilege grant.",
        },
        {
            "id": AssessmentProfile.ATTACK_PATH_SIMULATION.value,
            "name": "Attack-Path Simulation",
            "description": "Correlate authorised multi-stage attack paths.",
            "gate": "Stage-by-stage approval.",
        },
        {
            "id": AssessmentProfile.REMEDIATION_RETEST.value,
            "name": "Remediation Retest",
            "description": "Repeat only checks required to verify a fix.",
            "gate": "Retest scope approval.",
        },
    )


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def new_scan_view(request: HttpRequest) -> HttpResponse:
    try:
        authorized_actor(request.user, required_actions=("scan.create",))
    except WebPermissionDenied as exc:
        return _render(
            request,
            "web/denied.html",
            {"page_title": "Access Denied", "denied_message": str(exc)},
            status=403,
        )

    error_message = None
    try:
        authorization_store = AuthorizationStore.from_path(
            Path(settings.VULNHUNTER_AUTHORIZATION_DATABASE)
        )
        authorization_store.initialize()
        authorizations = authorization_store.list(limit=100)
    except (OSError, RuntimeError, ValueError) as exc:
        authorizations = ()
        error_message = str(exc)
    return _render(
        request,
        "web/new_scan.html",
        {
            "page_title": "New Bounded Scan",
            "authorizations": authorizations,
            "profiles": _assessment_profiles(),
            "error_message": error_message,
        },
    )


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def advanced_profiles_view(request: HttpRequest) -> HttpResponse:
    try:
        authorized_actor(request.user, required_actions=("audit.read", "scan.read"))
    except WebPermissionDenied as exc:
        return _render(
            request,
            "web/denied.html",
            {"page_title": "Access Denied", "denied_message": str(exc)},
            status=403,
        )
    profiles = _assessment_profiles()
    return _render(
        request,
        "web/advanced_profiles.html",
        {"page_title": "Advanced Assessment Mode", "profiles": profiles},
    )


@cache_control(private=True, no_store=True)
@login_required
@require_http_methods(["GET", "POST"])
def mobile_analysis_view(request: HttpRequest) -> HttpResponse:
    try:
        authorized_actor(request.user, required_actions=("scan.create", "settings.manage"))
    except WebPermissionDenied as exc:
        return _render(
            request,
            "web/denied.html",
            {"page_title": "Access Denied", "denied_message": str(exc)},
            status=403,
        )

    ingestor = MobileArtifactIngestor(
        Path(settings.VULNHUNTER_MOBILE_ARTIFACT_ROOT),
        maximum_apk_bytes=settings.VULNHUNTER_MOBILE_MAX_APK_BYTES,
    )
    form = MobileApkUploadForm(request.POST or None, request.FILES or None)
    uploaded_record = None
    if request.method == "POST" and form.is_valid():
        uploaded = form.cleaned_data["apk_file"]
        try:
            uploaded_record = ingestor.ingest_chunks(uploaded.name, uploaded.chunks())
        except MobileArtifactError as exc:
            form.add_error("apk_file", str(exc))
        else:
            messages.success(
                request,
                "APK stored safely. No analysis tool or emulator was started.",
            )
            form = MobileApkUploadForm()

    profiles = (
        {
            "id": MobileAnalysisProfile.STATIC.value,
            "name": "Static APK Analysis",
            "description": "Signature, package, manifest, smali, bytecode, and packer analysis.",
            "gate": "Local read-only tools; execution remains disabled until enabled by policy.",
        },
        {
            "id": MobileAnalysisProfile.STATIC_AND_NATIVE.value,
            "name": "Static and Native Analysis",
            "description": "Adds native .so library triage when the APK contains native code.",
            "gate": "Ghidra connector actions require exact approval.",
        },
        {
            "id": MobileAnalysisProfile.DYNAMIC.value,
            "name": "Dynamic Emulator Analysis",
            "description": "MobSF, ADB, and Frida validation in a disposable emulator.",
            "gate": "Isolated runtime and explicit dynamic-analysis approval are mandatory.",
        },
        {
            "id": MobileAnalysisProfile.FULL.value,
            "name": "Full Mobile Assessment",
            "description": "Static, native, and separately approved dynamic analysis stages.",
            "gate": "Stage-by-stage approval; APK is never executed on the host.",
        },
        {
            "id": MobileAnalysisProfile.RETEST.value,
            "name": "Mobile Remediation Retest",
            "description": "Repeat only the bounded checks needed to validate a fix.",
            "gate": "Exact artifact and retest scope must be recorded.",
        },
    )
    return _render(
        request,
        "web/mobile_analysis.html",
        {
            "page_title": "Mobile APK Analysis",
            "form": form,
            "uploaded_record": uploaded_record,
            "artifacts": ingestor.list_records(),
            "profiles": profiles,
        },
    )
