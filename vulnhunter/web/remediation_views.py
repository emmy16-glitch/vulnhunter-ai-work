"""Protected chat-first workflow for human-governed remediation planning."""

from __future__ import annotations

import json
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
    RemediationFixVerificationError,
    RemediationReviewError,
    RemediationState,
    VerificationState,
)
from vulnhunter.reports import FinalRemediationReportError
from vulnhunter.security import redact_text
from vulnhunter.source_hunt import RepositorySnapshot, SourceReference, VerifierReceipt
from vulnhunter.web.final_report_service import final_report_store
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
    remediation_verify_url,
    remediation_workspace_url,
    remember_remediation_workspace,
)
from vulnhunter.web.remediation_final_report_views import remediation_final_report_url
from vulnhunter.web.remediation_fix_verification import (
    remediation_fix_verification_service,
    remediation_fix_verification_store,
)
from vulnhunter.web.remediation_review_service import remediation_review_receipt_store
from vulnhunter.web.remediation_review_views import remediation_review_url
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
        getattr(governance, "reviewer_id", "") or request.user.get_username() or "remediation-owner"
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
        redact_text(" ".join(piece.split()))[:1_000] for piece in pieces if piece.strip()
    )
    if len(cleaned) > maximum:
        raise ValueError(f"no more than {maximum} bounded entries are allowed")
    return cleaned


def _json_model(value: str, model_type, *, label: str):
    if not value.strip():
        raise ValueError(f"{label} is required")
    try:
        return model_type.model_validate_json(value)
    except ValueError as exc:
        raise ValueError(f"{label} is not valid typed JSON: {exc}") from exc


def _json_model_list(value: str, model_type, *, label: str):
    try:
        payload = json.loads(value or "[]")
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be a JSON array") from exc
    if not isinstance(payload, list):
        raise ValueError(f"{label} must be a JSON array")
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


def _intent(text: str) -> str:
    lowered = " ".join(text.casefold().split())
    if any(
        phrase in lowered
        for phrase in (
            "record implementation",
            "submit implementation",
            "implementation handoff",
            "verify remediation fix",
            "verify the remediation fix",
            "submit fixed revision",
            "record fixed revision",
        )
    ):
        return "handoff"
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
    if intent == "handoff":
        if plan is None:
            copy = (
                "No remediation plan is bound to this workspace. Start with the exact ID of an "
                "independently verified finding."
            )
        else:
            remediation = plan.get("plan")
            remediation = remediation if isinstance(remediation, dict) else {}
            state = str(remediation.get("state") or "unknown")
            if state in {"ready_for_implementation", "needs_rework"}:
                redirect_url = str(plan.get("verify_url") or "") or None
                copy = (
                    "Opening the protected implementation handoff. Fresh password "
                    "re-authentication, typed snapshot metadata and deterministic receipts stay "
                    "outside ordinary chat and are never executed as commands."
                )
            else:
                redirect_url = str(plan.get("detail_url") or "") or None
                copy = (
                    f"This remediation is {state} and is not accepting another implementation "
                    "receipt. Opening the authoritative plan instead."
                )
    elif intent == "setup":
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
        latest = remediation.get("latest_verification")
        latest = latest if isinstance(latest, dict) else {}
        metadata["remediation"] = {
            "remediation_id": plan.get("remediation_id"),
            "finding_id": plan.get("finding_id"),
            "state": remediation.get("state"),
            "chat_stage": graph.get("chat_stage"),
            "task_graph_id": plan.get("task_graph_id"),
            "verification_receipt_id": latest.get("receipt_id"),
            "verification_verdict": latest.get("verdict"),
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

    eligible = finding.verification == VerificationState.VERIFIED and finding.status in {
        FindingStatus.OPEN,
        FindingStatus.TRIAGED,
    }
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
@require_http_methods(["GET", "POST"])
def remediation_verify_view(request: HttpRequest, finding_id: str) -> HttpResponse:
    try:
        _remediator(request)
        workspace_id = _workspace_id(request)
        if workspace_id is None:
            raise WebPermissionDenied("Fix verification must return to a durable chat workspace.")
        finding = remediation_finding_store().get(finding_id)
    except WebPermissionDenied as exc:
        return _denied(request, str(exc), status=409 if "workspace" in str(exc) else 403)
    except FindingStoreError as exc:
        raise Http404(str(exc)) from exc

    remediation = finding.remediation
    eligible = (
        finding.status == FindingStatus.IN_REMEDIATION
        and remediation is not None
        and remediation.remediation_id is not None
        and remediation.state
        in {RemediationState.READY_FOR_IMPLEMENTATION, RemediationState.NEEDS_REWORK}
    )
    error = None
    submitted = {
        "builder_id": "",
        "allowed_paths": (
            "\n".join(remediation.target_references) if remediation is not None else ""
        ),
        "changed_files": "",
        "original_snapshot_json": "",
        "fixed_snapshot_json": "",
        "security_test_json": "",
        "regression_tests_json": "[]",
        "fixed_evidence_refs_json": "[]",
        "original_attack_blocked": "unknown",
    }

    if request.method == "POST":
        submitted = {
            "builder_id": request.POST.get("builder_id", "").strip(),
            "allowed_paths": request.POST.get("allowed_paths", "").strip(),
            "changed_files": request.POST.get("changed_files", "").strip(),
            "original_snapshot_json": request.POST.get("original_snapshot_json", "").strip(),
            "fixed_snapshot_json": request.POST.get("fixed_snapshot_json", "").strip(),
            "security_test_json": request.POST.get("security_test_json", "").strip(),
            "regression_tests_json": request.POST.get("regression_tests_json", "[]").strip(),
            "fixed_evidence_refs_json": request.POST.get("fixed_evidence_refs_json", "[]").strip(),
            "original_attack_blocked": request.POST.get(
                "original_attack_blocked", "unknown"
            ).strip(),
        }
        try:
            if not eligible:
                raise FindingLifecycleError(
                    "This remediation plan is not accepting another implementation receipt."
                )
            password = request.POST.get("password", "")
            if not password or not request.user.check_password(password):
                raise WebPermissionDenied("Password re-authentication failed.")
            expected_revision = int(request.POST.get("expected_revision", "-1"))
            allowed_paths = _split_values(submitted["allowed_paths"], maximum=100)
            changed_files = _split_values(submitted["changed_files"], maximum=2_000)
            original_snapshot = _json_model(
                submitted["original_snapshot_json"],
                RepositorySnapshot,
                label="Original repository snapshot",
            )
            fixed_snapshot = _json_model(
                submitted["fixed_snapshot_json"],
                RepositorySnapshot,
                label="Fixed repository snapshot",
            )
            security_test = (
                _json_model(
                    submitted["security_test_json"],
                    VerifierReceipt,
                    label="Security test receipt",
                )
                if submitted["security_test_json"]
                else None
            )
            regression_tests = _json_model_list(
                submitted["regression_tests_json"],
                VerifierReceipt,
                label="Regression test receipts",
            )
            fixed_evidence_refs = _json_model_list(
                submitted["fixed_evidence_refs_json"],
                SourceReference,
                label="Fixed evidence references",
            )
            updated, bundle = remediation_fix_verification_service().record(
                finding_id=finding_id,
                expected_revision=expected_revision,
                builder_id=submitted["builder_id"],
                allowed_paths=allowed_paths,
                changed_files=changed_files,
                original_snapshot=original_snapshot,
                fixed_snapshot=fixed_snapshot,
                security_test=security_test,
                regression_tests=regression_tests,
                fixed_evidence_refs=fixed_evidence_refs,
                original_attack_blocked=_optional_boolean(submitted["original_attack_blocked"]),
            )
        except (
            FindingConflict,
            FindingLifecycleError,
            FindingStoreError,
            RemediationFixVerificationError,
            WebPermissionDenied,
            OSError,
            RuntimeError,
            ValueError,
        ) as exc:
            error = str(exc)
        else:
            try:
                graph = project_remediation_finding(updated)
                if graph is None:
                    raise AssessmentGraphError(
                        "the remediation graph is unavailable after verification"
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
            ):
                messages.warning(
                    request,
                    "The immutable fix-verification receipt was recorded, but chat projection "
                    "must be retried from the remediation detail page.",
                )
            verdict = bundle.report.verdict.value
            if verdict == "fixed":
                messages.success(
                    request,
                    "Read-only fix verification passed. The finding is ready "
                    "for a separate retest.",
                )
            else:
                messages.warning(
                    request,
                    f"Read-only fix verification returned {verdict}; bounded rework is required.",
                )
            return redirect(remediation_detail_url(finding_id, workspace_id))

    return _render(
        request,
        "web/remediation_verify.html",
        {
            "page_title": f"Verify implementation for {finding_id}",
            "finding": finding,
            "remediation": remediation,
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
    latest_verification = (
        remediation.verification_history[-1] if remediation.verification_history else None
    )
    verification_bundle = None
    if latest_verification is not None:
        try:
            verification_bundle = remediation_fix_verification_store().load(
                latest_verification.receipt_id
            )
        except RemediationFixVerificationError:
            verification_bundle = None
    latest_review = remediation.review_history[-1] if remediation.review_history else None
    review_bundle = None
    if latest_review is not None:
        try:
            review_bundle = remediation_review_receipt_store().load(latest_review.receipt_id)
        except RemediationReviewError:
            review_bundle = None
    latest_report = remediation.report_history[-1] if remediation.report_history else None
    report_bundle = None
    if latest_report is not None:
        try:
            report_bundle = final_report_store().load(latest_report.report_id)
        except FinalRemediationReportError:
            report_bundle = None
    active_states = {
        RemediationState.READY_FOR_IMPLEMENTATION,
        RemediationState.NEEDS_REWORK,
        RemediationState.REVIEW_NEEDS_REWORK,
    }
    return _render(
        request,
        "web/remediation_detail.html",
        {
            "page_title": f"Remediation {remediation.remediation_id}",
            "finding": finding,
            "remediation": remediation,
            "assessment_graph": graph,
            "latest_verification": latest_verification,
            "verification_bundle": verification_bundle,
            "latest_review": latest_review,
            "review_bundle": review_bundle,
            "latest_report": latest_report,
            "report_bundle": report_bundle,
            "verification_url": remediation_verify_url(finding_id, workspace_id),
            "review_url": remediation_review_url(finding_id, workspace_id),
            "report_url": remediation_final_report_url(finding_id, workspace_id),
            "workspace_return_url": remediation_workspace_url(workspace_id),
            "can_verify": (
                remediation.state in active_states
                and (request.user.is_staff or request.user.is_superuser)
            ),
            "can_review": remediation.state == RemediationState.AWAITING_REVIEW,
            "can_generate_report": remediation.state == RemediationState.REVIEW_APPROVED,
            "can_cancel": (
                remediation.state in active_states
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
    "remediation_verify_view",
]
