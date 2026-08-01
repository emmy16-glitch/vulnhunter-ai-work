"""Protected browser workflow for governed before/after retesting."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ObjectDoesNotExist
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.views.decorators.cache import cache_control
from django.views.decorators.http import require_http_methods, require_POST

from vulnhunter.assessment_graph import AssessmentGraphError
from vulnhunter.findings import (
    EvidenceReference,
    FindingConflict,
    FindingLifecycleError,
    FindingStatus,
    FindingStoreError,
    GovernedRetestError,
    RemediationState,
)
from vulnhunter.security import redact_text
from vulnhunter.source_hunt import VerifierReceipt
from vulnhunter.web.remediation_assessment_graph import project_remediation_finding
from vulnhunter.web.remediation_conversation_state import (
    remediation_detail_url,
    remediation_finding_store,
)
from vulnhunter.web.retest_assessment_graph import (
    bind_retest_assessment_graph,
    project_retest_finding,
)
from vulnhunter.web.retest_conversation_state import (
    remember_retest_workspace,
    retest_create_url,
    retest_detail_url,
    retest_workspace_url,
)
from vulnhunter.web.retest_service import governed_retest_service, retest_receipt_store
from vulnhunter.web.services import WebPermissionDenied, authorized_actor

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


def _operator(request: HttpRequest):
    actor = authorized_actor(
        request.user,
        required_actions=("finding.read", "settings.manage"),
    )
    if not (request.user.is_staff or request.user.is_superuser):
        raise WebPermissionDenied(
            "Governed retesting currently requires a staff account and governed role."
        )
    return actor


def _owner_id(request: HttpRequest, actor: object) -> str:
    governance = getattr(actor, "governance_identity", None)
    value = str(
        getattr(governance, "reviewer_id", "") or request.user.get_username() or "retest-operator"
    ).casefold()
    normalized = _IDENTIFIER_SANITIZER.sub("-", value).strip("-._")
    return (normalized or "retest-operator")[:120]


def _workspace_id(request: HttpRequest) -> str | None:
    thread = getattr(request, "vulnhunter_thread", None)
    thread_id = getattr(thread, "thread_id", None)
    return str(thread_id) if thread_id is not None else None


def _split_values(value: str, *, maximum: int = 100) -> tuple[str, ...]:
    pieces = re.split(r"[\n,]+", value)
    cleaned = tuple(
        redact_text(" ".join(piece.split()))[:1_000] for piece in pieces if piece.strip()
    )
    if not cleaned:
        raise ValueError("Enter at least one exact bounded retest check.")
    if len(cleaned) > maximum:
        raise ValueError(f"No more than {maximum} bounded checks are allowed.")
    if len(set(cleaned)) != len(cleaned):
        raise ValueError("Retest checks must not contain duplicates.")
    return cleaned


def _json_model_list(value: str, model_type, *, label: str):
    try:
        payload = json.loads(value or "[]")
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be a JSON array.") from exc
    if not isinstance(payload, list):
        raise ValueError(f"{label} must be a JSON array.")
    try:
        return tuple(model_type.model_validate(item) for item in payload)
    except ValueError as exc:
        raise ValueError(f"{label} contains invalid typed evidence: {exc}") from exc


def _optional_boolean(value: str) -> bool | None:
    normalized = value.strip().casefold()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return None


def _latest_plan(finding):
    if not finding.retest_plans:
        raise Http404("Finding has no governed retest plan.")
    return finding.retest_plans[-1]


def _latest_result(finding, retest_id: str):
    return next(
        (item for item in reversed(finding.retest_results) if item.retest_id == retest_id),
        None,
    )


@cache_control(private=True, no_store=True)
@login_required
@require_http_methods(["GET", "POST"])
def retest_create_view(request: HttpRequest, finding_id: str) -> HttpResponse:
    try:
        actor = _operator(request)
        workspace_id = _workspace_id(request)
        if workspace_id is None:
            raise WebPermissionDenied(
                "Governed retesting must start from a durable chat workspace."
            )
        finding = remediation_finding_store().get(finding_id)
    except WebPermissionDenied as exc:
        return _denied(request, str(exc), status=409 if "workspace" in str(exc) else 403)
    except FindingStoreError as exc:
        raise Http404(str(exc)) from exc

    remediation = finding.remediation
    latest_verification = (
        remediation.verification_history[-1]
        if remediation is not None and remediation.verification_history
        else None
    )
    eligible = (
        finding.status == FindingStatus.READY_FOR_RETEST
        and remediation is not None
        and remediation.remediation_id is not None
        and remediation.state == RemediationState.READY_FOR_RETEST
        and latest_verification is not None
        and latest_verification.verdict == "fixed"
    )
    submitted = {
        "check_references": (remediation.verification_recipe if remediation is not None else "")
    }
    error = None

    if request.method == "POST":
        submitted = {"check_references": request.POST.get("check_references", "").strip()}
        try:
            if not eligible:
                raise FindingLifecycleError("This finding is not ready for a governed retest.")
            password = request.POST.get("password", "")
            if not password or not request.user.check_password(password):
                raise WebPermissionDenied("Password re-authentication failed.")
            expected_revision = int(request.POST.get("expected_revision", "-1"))
            checks = _split_values(submitted["check_references"])
            started = governed_retest_service().start(
                finding_id=finding_id,
                expected_revision=expected_revision,
                owner_id=_owner_id(request, actor),
                check_references=checks,
                expires_at=datetime.now(UTC) + timedelta(days=2),
            )
            plan = started.retest_plans[-1]
            try:
                retest_graph = bind_retest_assessment_graph(
                    started,
                    workspace_id=workspace_id,
                )
                remediation_graph = project_remediation_finding(started)
                remember_retest_workspace(
                    owner=request.user,
                    workspace_id=workspace_id,
                    finding=started,
                    retest_graph=retest_graph,
                    remediation_graph=remediation_graph,
                )
            except (
                AssessmentGraphError,
                ObjectDoesNotExist,
                OSError,
                RuntimeError,
                ValueError,
            ) as exc:
                cancelled, _bundle = governed_retest_service().cancel(
                    finding_id=finding_id,
                    retest_id=plan.retest_id,
                    expected_revision=started.revision,
                    reason="Authoritative retest graph or workspace binding failed.",
                )
                project_retest_finding(cancelled)
                project_remediation_finding(cancelled)
                finding = cancelled
                raise FindingLifecycleError(
                    "The retest could not be bound to its authoritative chat workspace."
                ) from exc
        except (
            AssessmentGraphError,
            FindingConflict,
            FindingLifecycleError,
            FindingStoreError,
            GovernedRetestError,
            WebPermissionDenied,
            OSError,
            RuntimeError,
            ValueError,
        ) as exc:
            error = str(exc)
        else:
            messages.success(
                request,
                "The governed retest is ready for typed before/after evidence collection.",
            )
            return redirect(retest_detail_url(finding_id, workspace_id))

    return _render(
        request,
        "web/retest_create.html",
        {
            "page_title": f"Plan retest for {finding_id}",
            "finding": finding,
            "remediation": remediation,
            "latest_verification": latest_verification,
            "eligible": eligible,
            "submitted": submitted,
            "error": error,
            "workspace_return_url": retest_workspace_url(workspace_id),
            "remediation_url": remediation_detail_url(finding_id, workspace_id),
        },
        status=200 if eligible else 409,
    )


@cache_control(private=True, no_store=True)
@login_required
@require_http_methods(["GET", "POST"])
def retest_detail_view(request: HttpRequest, finding_id: str) -> HttpResponse:
    try:
        _operator(request)
        workspace_id = _workspace_id(request)
        if workspace_id is None:
            raise WebPermissionDenied(
                "Governed retest evidence must return to a durable chat workspace."
            )
        finding = remediation_finding_store().get(finding_id)
    except WebPermissionDenied as exc:
        return _denied(request, str(exc), status=409 if "workspace" in str(exc) else 403)
    except FindingStoreError as exc:
        raise Http404(str(exc)) from exc

    plan = _latest_plan(finding)
    result = _latest_result(finding, plan.retest_id)
    active = finding.status == FindingStatus.RETESTING and result is None
    original_by_id = {item.evidence_id: item for item in finding.evidence}
    before_evidence = tuple(
        original_by_id[evidence_id]
        for evidence_id in plan.before_evidence_ids
        if evidence_id in original_by_id
    )
    submitted = {
        "before_evidence_json": json.dumps(
            [item.model_dump(mode="json") for item in before_evidence],
            indent=2,
        ),
        "after_evidence_json": "[]",
        "check_receipts_json": "[]",
        "original_issue_blocked": "unknown",
        "regression_free": "unknown",
        "blocked_reason": "",
    }
    error = None

    if request.method == "POST":
        submitted = {
            "before_evidence_json": request.POST.get("before_evidence_json", "[]").strip(),
            "after_evidence_json": request.POST.get("after_evidence_json", "[]").strip(),
            "check_receipts_json": request.POST.get("check_receipts_json", "[]").strip(),
            "original_issue_blocked": request.POST.get("original_issue_blocked", "unknown").strip(),
            "regression_free": request.POST.get("regression_free", "unknown").strip(),
            "blocked_reason": request.POST.get("blocked_reason", "").strip(),
        }
        try:
            if not active:
                raise FindingLifecycleError(
                    "This governed retest is not accepting another evidence receipt."
                )
            password = request.POST.get("password", "")
            if not password or not request.user.check_password(password):
                raise WebPermissionDenied("Password re-authentication failed.")
            expected_revision = int(request.POST.get("expected_revision", "-1"))
            typed_before = _json_model_list(
                submitted["before_evidence_json"],
                EvidenceReference,
                label="Before-fix evidence",
            )
            typed_after = _json_model_list(
                submitted["after_evidence_json"],
                EvidenceReference,
                label="After-fix evidence",
            )
            check_receipts = _json_model_list(
                submitted["check_receipts_json"],
                VerifierReceipt,
                label="Deterministic retest receipts",
            )
            updated, bundle = governed_retest_service().record(
                finding_id=finding_id,
                retest_id=plan.retest_id,
                expected_revision=expected_revision,
                before_evidence=typed_before,
                after_evidence=typed_after,
                check_receipts=check_receipts,
                original_issue_blocked=_optional_boolean(submitted["original_issue_blocked"]),
                regression_free=_optional_boolean(submitted["regression_free"]),
                blocked_reason=redact_text(submitted["blocked_reason"])
                if submitted["blocked_reason"]
                else None,
            )
        except (
            FindingConflict,
            FindingLifecycleError,
            FindingStoreError,
            GovernedRetestError,
            WebPermissionDenied,
            OSError,
            RuntimeError,
            ValueError,
        ) as exc:
            error = str(exc)
        else:
            try:
                retest_graph = project_retest_finding(updated)
                remediation_graph = project_remediation_finding(updated)
                if retest_graph is None:
                    raise AssessmentGraphError(
                        "The retest graph is unavailable after receipt persistence."
                    )
                remember_retest_workspace(
                    owner=request.user,
                    workspace_id=workspace_id,
                    finding=updated,
                    retest_graph=retest_graph,
                    remediation_graph=remediation_graph,
                )
            except (
                AssessmentGraphError,
                ObjectDoesNotExist,
                OSError,
                RuntimeError,
                ValueError,
            ):
                messages.warning(
                    request,
                    "The immutable retest receipt was recorded, but chat projection must be "
                    "retried from this page.",
                )
            if bundle.outcome.value == "passed":
                messages.success(
                    request,
                    "The governed retest passed. Independent remediation review is now ready.",
                )
            else:
                messages.warning(
                    request,
                    f"The governed retest returned {bundle.outcome.value}; review and reporting "
                    "remain blocked.",
                )
            return redirect(retest_detail_url(finding_id, workspace_id))

    bundle = None
    if result is not None:
        try:
            bundle = retest_receipt_store().load(result.receipt_id)
        except GovernedRetestError:
            bundle = None
    retest_graph = project_retest_finding(finding)
    remediation_graph = project_remediation_finding(finding)
    return _render(
        request,
        "web/retest_detail.html",
        {
            "page_title": f"Governed retest {plan.retest_id}",
            "finding": finding,
            "plan": plan,
            "result": result,
            "bundle": bundle,
            "active": active,
            "submitted": submitted,
            "error": error,
            "assessment_graph": retest_graph,
            "remediation_graph": remediation_graph,
            "workspace_return_url": retest_workspace_url(workspace_id),
            "remediation_url": remediation_detail_url(finding_id, workspace_id),
            "restart_url": retest_create_url(finding_id, workspace_id),
        },
    )


@cache_control(private=True, no_store=True)
@login_required
@require_POST
def retest_cancel_view(request: HttpRequest, finding_id: str) -> HttpResponse:
    workspace_id = _workspace_id(request)
    try:
        _operator(request)
        if workspace_id is None:
            raise WebPermissionDenied(
                "Governed retest cancellation requires a durable chat workspace."
            )
        password = request.POST.get("password", "")
        if not password or not request.user.check_password(password):
            raise WebPermissionDenied("Password re-authentication failed.")
        finding = remediation_finding_store().get(finding_id)
        plan = _latest_plan(finding)
        expected_revision = int(request.POST.get("expected_revision", "-1"))
        updated, _bundle = governed_retest_service().cancel(
            finding_id=finding_id,
            retest_id=plan.retest_id,
            expected_revision=expected_revision,
            reason=redact_text(
                request.POST.get(
                    "reason",
                    "The human operator cancelled before retest evidence collection.",
                )
            ),
        )
        retest_graph = project_retest_finding(updated)
        remediation_graph = project_remediation_finding(updated)
        if retest_graph is not None:
            remember_retest_workspace(
                owner=request.user,
                workspace_id=workspace_id,
                finding=updated,
                retest_graph=retest_graph,
                remediation_graph=remediation_graph,
            )
    except (
        FindingConflict,
        FindingLifecycleError,
        FindingStoreError,
        GovernedRetestError,
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
            "The governed retest was cancelled; the fixed finding remains ready for retest.",
        )
    return redirect(retest_detail_url(finding_id, workspace_id))


__all__ = [
    "retest_cancel_view",
    "retest_create_view",
    "retest_detail_view",
]
