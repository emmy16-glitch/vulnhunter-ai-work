"""Authenticated web surfaces for approvals, tools, and advanced profiles."""

from __future__ import annotations

import json
from pathlib import Path

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import Http404, HttpRequest, HttpResponse, JsonResponse
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
from vulnhunter.mobile import (
    MobileAnalysisProfile,
    MobileArtifactError,
    MobileArtifactIngestor,
)
from vulnhunter.security_tools.catalog import default_catalog
from vulnhunter.web.assessment_workflow import (
    AssessmentWorkflowError,
    AssessmentWorkflowService,
)
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


def _load_json_object(path: Path) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _tool_gate_label(definition) -> str:
    parts = [
        "connector"
        if definition.connector_only
        else "approval"
        if definition.approval_required
        else "policy"
    ]
    if definition.requires_isolation:
        parts.append("isolation")
    return " + ".join(parts)


def _nuclei_operational_projection(availability) -> tuple[str, str, str]:
    runtime = _load_json_object(Path(settings.VULNHUNTER_SECURITY_TOOL_CONFIG))
    nuclei = runtime.get("nuclei") if isinstance(runtime.get("nuclei"), dict) else {}
    worker = (
        runtime.get("scanner_worker")
        if isinstance(runtime.get("scanner_worker"), dict)
        else {}
    )
    readiness = _load_json_object(Path(settings.VULNHUNTER_NUCLEI_READINESS_REPORT))
    policy = _load_json_object(Path(settings.VULNHUNTER_NUCLEI_WORKER_POLICY))
    key_path = Path(settings.VULNHUNTER_NUCLEI_WORKER_SIGNING_KEY_FILE)
    gates = {
        "local_binary": availability.usable,
        "readiness": readiness.get("ready") is True,
        "runtime": runtime.get("execution_enabled") is True,
        "nuclei": nuclei.get("enabled") is True and nuclei.get("real_runner_enabled") is True,
        "worker": (
            worker.get("execution_enabled") is True
            and worker.get("transport_enabled") is True
        ),
        "worker_policy": policy.get("enabled") is True,
        "signing_key": key_path.is_file(),
        "enqueue": bool(settings.VULNHUNTER_NUCLEI_PILOT_ENQUEUE_ENABLED),
    }
    if all(gates.values()):
        return (
            "operational",
            "Passive private-lab worker ready",
            "Exact authorization, independent approval and a signed worker job are still required.",
        )
    missing = ", ".join(name.replace("_", " ") for name, enabled in gates.items() if not enabled)
    return (
        "gated",
        "Private-lab worker gated",
        f"Missing or unverified gates: {missing}.",
    )


def _tool_projection(definition, availability) -> dict[str, object]:
    if definition.tool_id == "nuclei":
        operational_state, operational_label, operational_detail = _nuclei_operational_projection(
            availability
        )
        adapter_label = "Connected worker adapter"
    elif definition.connector_only:
        operational_state = "connector_required"
        operational_label = "Connector required"
        operational_detail = "This catalog entry has no direct web-host execution path."
        adapter_label = "Connector contract"
    elif availability.usable:
        operational_state = "registered_only"
        operational_label = "Installed; not activated here"
        operational_detail = (
            "The local executable passed its version probe, but this registry does not grant "
            "execution authority or create a runnable web workflow."
        )
        adapter_label = "Catalog adapter"
    else:
        operational_state = "unavailable"
        operational_label = "Unavailable locally"
        operational_detail = (
            "Install and verify the exact tool before any governed adapter can use it."
        )
        adapter_label = "Catalog registration"
    return {
        "definition": definition,
        "availability": availability,
        "adapter_label": adapter_label,
        "gate_label": _tool_gate_label(definition),
        "operational_state": operational_state,
        "operational_label": operational_label,
        "operational_detail": operational_detail,
    }


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
        store = _approval_store()
        pending = store.get(request_id)
        workflow = AssessmentWorkflowService.from_settings()
        workflow.validate_approval_binding(
            request=pending,
            submitted_plan_digest=request.POST.get("plan_digest", "").strip(),
        )
        decided = store.decide(
            request_id=request_id,
            actor_id=actor.governance_identity.reviewer_id,
            decision=decision,
            reason=reason,
            conditions=conditions,
        )
        workflow.record_approval_decision(
            request=decided,
            actor_id=actor.governance_identity.reviewer_id,
        )
    except (ApprovalStoreError, AssessmentWorkflowError) as exc:
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
        _tool_projection(definition, availability[definition.tool_id])
        for definition in catalog.list()
    )
    summary = {
        "registered": len(rows),
        "locally_ready": sum(1 for row in rows if row["availability"].usable),
        "operational": sum(1 for row in rows if row["operational_state"] == "operational"),
    }
    return _render(
        request,
        "web/security_tools.html",
        {"page_title": "Security Tool Registry", "tool_rows": rows, "summary": summary},
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
@require_http_methods(["GET", "POST"])
def new_scan_view(request: HttpRequest) -> HttpResponse:
    try:
        actor = authorized_actor(request.user, required_actions=("scan.create",))
    except WebPermissionDenied as exc:
        return _render(
            request,
            "web/denied.html",
            {"page_title": "Access Denied", "denied_message": str(exc)},
            status=403,
        )

    workflow = AssessmentWorkflowService.from_settings()
    error_message = None
    try:
        authorizations = workflow.list_authorizations(
            identity_id=actor.governance_identity.reviewer_id,
            username=request.user.get_username(),
        )
    except (OSError, RuntimeError, ValueError) as exc:
        authorizations = ()
        error_message = str(exc)
    if request.method == "POST":
        try:
            port = int(request.POST.get("port", ""))
            result = workflow.create_assessment(
                authorization_id=request.POST.get("authorization_id", "").strip(),
                target=request.POST.get("target", "").strip(),
                protocol=request.POST.get("protocol", "").strip(),
                port=port,
                profile=request.POST.get("profile", "").strip(),
                identity_id=actor.governance_identity.reviewer_id,
                username=request.user.get_username(),
            )
        except (AssessmentWorkflowError, OSError, RuntimeError, ValueError) as exc:
            error_message = str(exc)
        else:
            messages.success(
                request,
                (
                    "The governed assessment was created. Exact independent approval is required; "
                    "an approved passive plan can enter the signed private-lab worker queue."
                ),
            )
            return redirect("web-agent-run-detail", run_id=result.task.task_id)
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
def active_authorizations_view(request: HttpRequest) -> JsonResponse:
    """Return only the current actor's active, activation-bound records."""

    try:
        actor = authorized_actor(request.user, required_actions=("scan.create",))
        choices = AssessmentWorkflowService.from_settings().list_authorizations(
            identity_id=actor.governance_identity.reviewer_id,
            username=request.user.get_username(),
        )
    except WebPermissionDenied:
        return JsonResponse({"detail": "forbidden"}, status=403)
    except (OSError, RuntimeError, ValueError):
        return JsonResponse({"detail": "authorization service unavailable"}, status=503)
    response = JsonResponse(
        {
            "authorizations": [
                {
                    "authorization_id": item.authorization_id,
                    "display_label": item.display_label,
                    "expires_at": item.expires_at.isoformat(),
                    "approved_targets": item.approved_targets,
                    "approved_protocols": item.approved_protocols,
                    "approved_ports": item.approved_ports,
                    "approved_profiles": item.approved_profiles,
                }
                for item in choices
            ]
        }
    )
    response["Cache-Control"] = "private, no-store, max-age=0"
    return response


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
            "gate": "Local read-only tools require a separately verified static-worker policy.",
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
