"""Protected chat-first workflow for human-governed remediation planning."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ObjectDoesNotExist
from django.http import Http404, HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import redirect, render
from django.views.decorators.cache import cache_control
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from vulnhunter.assessment_graph import AssessmentGraphError
from vulnhunter.findings import (
    FindingConflict,
    FindingLifecycleError,
    FindingService,
    FindingStatus,
    FindingStoreError,
    RemediationState,
    VerificationState,
)
from vulnhunter.security import redact_text
from vulnhunter.web.remediation_assessment_graph import (
    bind_remediation_assessment_graph,
    fail_remediation_graph,
    project_remediation_finding,
)
from vulnhunter.web.remediation_conversation_state import (
    current_remediation_plan,
    record_remediation_event,
    remediation_chat_reply,
    remediation_create_url,
    remediation_detail_url,
    remediation_finding_store,
    remediation_workspace_url,
    remember_remediation_workspace,
)
from vulnhunter.web.services import WebPermissionDenied, authorized_actor

_FINDING_ID = re.compile(r"\bfinding-[a-z0-9][a-z0-9._-]{0,116}\b")
_IDENTIFIER_SANITIZER = re.compile(r"[^a-z0-9._-]+")


def _render(
    request: HttpRequest,
    template: str,
    context: dict[str, object],
    *,
    status: int = 200,
) -> HttpResponse:
    return render(
        request,
        template,
        {"current_route": "web-findings-overview", **context},
        status=status,
    )


def _denied(request: HttpRequest, message: str, *, status: int = 403) -> HttpResponse:
    return _render(
        request,
        "web/denied.html",
        {"page_title": "Access Denied", "denied_message": message},
        status=status,
    )


def _remediator(request: HttpRequest):
    actor = authorized_actor(
        request.user,
        required_actions=("finding.read", "settings.manage"),
    )
    if not (request.user.is_staff or request.user.is_superuser):
        raise WebPermissionDenied(
            "Remediation planning currently requires a staff account and governed role."
        )
    return actor


def _owner_id(request: HttpRequest, actor: object) -> str:
    governance = getattr(actor, "governance_identity", None)
    value = str(
        getattr(governance, "reviewer_id", "")
        or request.user.get_username()
        or "remediation-owner"
    ).casefold()
    normalized = _IDENTIFIER_SANITIZER.sub("-", value).strip("-._")
    return (normalized or "remediation-owner")[:120]


def _workspace_id(request: HttpRequest) -> str | None:
    thread = getattr(request, "vulnhunter_thread", None)
    thread_id = getattr(thread, "thread_id", None)
    return str(thread_id) if thread_id is not None else None


def _split_values(value: str, *, maximum: int = 40) -> tuple[str, ...]:
    pieces = re.split(r"[\n,]+", value)
    cleaned = tuple(
        redact_text(" ".join(piece.split()))[:1_000]
        for piece in pieces
        if piece.strip()
    )
    if len(cleaned) > maximum:
        raise ValueError(f"no more than {maximum} bounded entries are allowed")
    return cleaned


def _intent(text: str) -> str:
    lowered = " ".join(text.casefold().split())
    if any(
        phrase in lowered
        for phrase in (
            "start remediation",
            "open remediation",
            "create remediation",
            "plan remediation",
            "remediate finding",
            "fix finding",
        )
    ):
        return "setup"
    if any(term in lowered for term in ("result", "plan", "targets", "red test")):
        return "results"
    if any(term in lowered for term in ("next step", "what next", "next action")):
        return "next_step"
    if any(term in lowered for term in ("status", "progress", "is it ready", "is it done")):
        return "status"
    return "setup"


def _finding_id_from_text(text: str) -> str | None:
    match = _FINDING_ID.search(text.casefold())
    return match.group(0) if match else None


@cache_control(private=True, no_store=True)
@login_required
@require_POST
def remediation_chat_view(request: HttpRequest) -> JsonResponse:
    try:
        authorized_actor(request.user, required_actions=("finding.read",))
    except WebPermissionDenied as exc:
        return JsonResponse({"detail": str(exc)}, status=403)
    workspace_id = _workspace_id(request)
    if workspace_id is None:
        return JsonResponse(
            {"detail": "Select a durable workspace before planning remediation."},
            status=409,
        )
    text = request.POST.get("message", "").strip()
    if not text or len(text) > 4_000:
        return JsonResponse(
            {"detail": "Enter a message between 1 and 4,000 characters."},
            status=400,
        )

    from vulnhunter.web.conversational_views import _append_message

    _append_message(request, role="user", content=text)
    intent = _intent(text)
    plan = current_remediation_plan(request)
    if plan is not None:
        record_remediation_event(request, plan)

    redirect_url = None
    if intent == "setup":
        if plan is not None:
            redirect_url = str(plan.get("detail_url") or "") or None
            copy = (
                "Opening the exact remediation plan already bound to this workspace. "
                "Implementation, fix verification and merge remain separate human-controlled steps."
            )
        else:
            finding_id = _finding_id_from_text(text)
            if finding_id is None:
                copy = (
                    "Remediation requires the exact ID of an independently verified finding, for "
                    "example: ‘Plan remediation for finding-01’. Ordinary chat cannot invent or "
                    "verify a finding."
                )
            else:
                redirect_url = remediation_create_url(finding_id, workspace_id)
                copy = (
                    f"Opening protected remediation planning for {finding_id}. Fresh password "
                    "re-authentication and exact bounded plan fields remain outside ordinary chat."
                )
    elif plan is None:
        copy = (
            "No remediation plan is bound to this workspace. Start with the exact ID of an "
            "independently verified finding."
        )
    else:
        copy = remediation_chat_reply(intent, plan)

    metadata: dict[str, object] = {}
    if plan is not None:
        remediation = plan.get("plan")
        remediation = remediation if isinstance(remediation, dict) else {}
        graph = plan.get("assessment_graph")
        graph = graph if isinstance(graph, dict) else {}
        metadata["remediation"] = {
            "remediation_id": plan.get("remediation_id"),
            "finding_id": plan.get("finding_id"),
            "state": remediation.get("state"),
            "chat_stage": graph.get("chat_stage"),
            "task_graph_id": plan.get("task_graph_id"),
        }
    message = _append_message(
        request,
        role="assistant",
        kind="result" if intent == "results" else "status",
        content=copy,
        metadata=metadata,
    )
    response: dict[str, object] = {"message": message, "handled": True}
    if redirect_url:
        response["redirect_url"] = redirect_url
    return JsonResponse(response)


@cache_control(private=True, no_store=True)
@login_required
@require_http_methods(["GET", "POST"])
def remediation_create_view(request: HttpRequest, finding_id: str) -> HttpResponse:
    try:
        actor = _remediator(request)
        workspace_id = _workspace_id(request)
        if workspace_id is None:
            raise WebPermissionDenied(
                "Remediation must start from a durable chat workspace.",
            )
        finding = remediation_finding_store().get(finding_id)
    except WebPermissionDenied as exc:
        return _denied(request, str(exc), status=409 if "workspace" in str(exc) else 403)
    except FindingStoreError as exc:
        raise Http404(str(exc)) from exc

    eligible = (
        finding.verification == VerificationState.VERIFIED
        and finding.status in {FindingStatus.OPEN, FindingStatus.TRIAGED}
    )
    error = None
    submitted = {
        "summary": "",
        "target_references": finding.affected_component or finding.affected_asset,
        "regression_test": "",
        "verification_recipe": "",
        "compatibility_risks": "",
    }

    if request.method == "POST":
        submitted = {
            "summary": request.POST.get("summary", "").strip(),
            "target_references": request.POST.get("target_references", "").strip(),
            "regression_test": request.POST.get("regression_test", "").strip(),
            "verification_recipe": request.POST.get("verification_recipe", "").strip(),
            "compatibility_risks": request.POST.get("compatibility_risks", "").strip(),
        }
        try:
            if not eligible:
                raise FindingLifecycleError(
                    "Only independently verified open or triaged findings may enter remediation."
                )
            password = request.POST.get("password", "")
            if not password or not request.user.check_password(password):
                raise WebPermissionDenied("Password re-authentication failed.")
            expected_revision = int(request.POST.get("expected_revision", "-1"))
            target_references = _split_values(submitted["target_references"])
            if not target_references:
                raise ValueError("Enter at least one exact remediation target.")
            compatibility_risks = _split_values(submitted["compatibility_risks"])
            now = datetime.now(UTC)
            updated = FindingService(remediation_finding_store()).start_remediation(
                finding_id,
                owner_id=_owner_id(request, actor),
                summary=redact_text(submitted["summary"]),
                target_references=target_references,
                regression_test=redact_text(submitted["regression_test"]),
                verification_recipe=redact_text(submitted["verification_recipe"]),
                compatibility_risks=compatibility_risks,
                references=tuple(item.evidence_id for item in finding.evidence),
                expires_at=now + timedelta(days=7),
                expected_revision=expected_revision,
                now=now,
            )
            remediation = updated.remediation
            assert remediation is not None and remediation.remediation_id is not None
            try:
                graph = bind_remediation_assessment_graph(
                    updated,
                    workspace_id=workspace_id,
                )
                remember_remediation_workspace(
                    owner=request.user,
                    workspace_id=workspace_id,
                    finding=updated,
                    graph=graph,
                )
            except (
                AssessmentGraphError,
                ObjectDoesNotExist,
                OSError,
                RuntimeError,
                ValueError,
            ) as exc:
                cancelled = FindingService(remediation_finding_store()).cancel_remediation(
                    finding_id,
                    reason="Authoritative remediation graph binding failed.",
                    expected_revision=updated.revision,
                )
                fail_remediation_graph(
                    remediation.remediation_id,
                    reason="Authoritative remediation graph binding failed.",
                )
                finding = cancelled
                raise FindingLifecycleError(
                    "The remediation plan could not be bound to its chat workspace."
                ) from exc
        except (
            AssessmentGraphError,
            FindingConflict,
            FindingLifecycleError,
            FindingStoreError,
            WebPermissionDenied,
            OSError,
            RuntimeError,
            ValueError,
        ) as exc:
            error = str(exc)
        else:
            messages.success(
                request,
                "The exact remediation plan is ready for separate developer implementation.",
            )
            return redirect(remediation_detail_url(finding_id, workspace_id))

    return _render(
        request,
        "web/remediation_create.html",
        {
            "page_title": f"Plan remediation for {finding_id}",
            "finding": finding,
            "eligible": eligible,
            "submitted": submitted,
            "error": error,
            "workspace_return_url": remediation_workspace_url(workspace_id),
        },
        status=200 if eligible else 409,
    )


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def remediation_detail_view(request: HttpRequest, finding_id: str) -> HttpResponse:
    try:
        authorized_actor(request.user, required_actions=("finding.read",))
        finding = remediation_finding_store().get(finding_id)
    except WebPermissionDenied as exc:
        return _denied(request, str(exc))
    except FindingStoreError as exc:
        raise Http404(str(exc)) from exc
    remediation = finding.remediation
    if remediation is None or remediation.remediation_id is None:
        raise Http404("Finding has no governed remediation plan.")
    graph = project_remediation_finding(finding)
    workspace_id = _workspace_id(request)
    return _render(
        request,
        "web/remediation_detail.html",
        {
            "page_title": f"Remediation {remediation.remediation_id}",
            "finding": finding,
            "remediation": remediation,
            "assessment_graph": graph,
            "workspace_return_url": remediation_workspace_url(workspace_id),
            "can_cancel": (
                remediation.state == RemediationState.READY_FOR_IMPLEMENTATION
                and (request.user.is_staff or request.user.is_superuser)
            ),
        },
    )


@cache_control(private=True, no_store=True)
@login_required
@require_POST
def remediation_cancel_view(request: HttpRequest, finding_id: str) -> HttpResponse:
    workspace_id = _workspace_id(request)
    try:
        _remediator(request)
        password = request.POST.get("password", "")
        if not password or not request.user.check_password(password):
            raise WebPermissionDenied("Password re-authentication failed.")
        expected_revision = int(request.POST.get("expected_revision", "-1"))
        finding = FindingService(remediation_finding_store()).cancel_remediation(
            finding_id,
            reason=redact_text(
                request.POST.get(
                    "reason",
                    "Human owner cancelled the remediation plan before implementation.",
                )
            ),
            expected_revision=expected_revision,
        )
        graph = project_remediation_finding(finding)
        if workspace_id is not None and graph is not None:
            remember_remediation_workspace(
                owner=request.user,
                workspace_id=workspace_id,
                finding=finding,
                graph=graph,
            )
    except (
        FindingConflict,
        FindingLifecycleError,
        FindingStoreError,
        ObjectDoesNotExist,
        WebPermissionDenied,
        OSError,
        RuntimeError,
        ValueError,
    ) as exc:
        messages.error(request, str(exc))
    else:
        messages.success(
            request,
            "The remediation plan was cancelled; the finding remains triaged.",
        )
    return redirect(remediation_detail_url(finding_id, workspace_id))


__all__ = [
    "remediation_cancel_view",
    "remediation_chat_view",
    "remediation_create_view",
    "remediation_detail_view",
]
