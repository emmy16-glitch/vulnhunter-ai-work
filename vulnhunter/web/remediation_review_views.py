"""Protected workspace for governance-authenticated remediation review."""

from __future__ import annotations

import re

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ObjectDoesNotExist
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.views.decorators.cache import cache_control
from django.views.decorators.http import require_http_methods

from vulnhunter.assessment_graph import AssessmentGraphError
from vulnhunter.findings import (
    FindingConflict,
    FindingLifecycleError,
    FindingStatus,
    FindingStoreError,
    RemediationReviewChecklist,
    RemediationReviewError,
    RemediationState,
)
from vulnhunter.security import redact_text
from vulnhunter.web.remediation_assessment_graph import project_remediation_finding
from vulnhunter.web.remediation_conversation_state import (
    remember_remediation_workspace,
    remediation_detail_url,
    remediation_finding_store,
    remediation_workspace_url,
)
from vulnhunter.web.remediation_review_service import (
    remediation_review_receipt_store,
    remediation_review_service,
)
from vulnhunter.web.services import WebPermissionDenied, authorized_actor


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


def _reviewer(request: HttpRequest):
    actor = authorized_actor(
        request.user,
        required_actions=("review.read_assigned", "finding.read"),
    )
    if "reviewer" not in actor.governance_identity.roles:
        raise WebPermissionDenied(
            "Independent remediation review requires an active governed reviewer identity."
        )
    return actor


def _workspace_id(request: HttpRequest) -> str | None:
    thread = getattr(request, "vulnhunter_thread", None)
    thread_id = getattr(thread, "thread_id", None)
    return str(thread_id) if thread_id is not None else None


def remediation_review_url(finding_id: str, workspace_id: str | None) -> str:
    base = reverse("web-remediation-review", kwargs={"finding_id": finding_id})
    if workspace_id:
        return f"{base}?thread={workspace_id}"
    return base


def _optional_boolean(value: str) -> bool | None:
    normalized = value.strip().casefold()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return None


def _limitations(value: str) -> tuple[str, ...]:
    pieces = re.split(r"[\n,]+", value)
    cleaned = tuple(
        redact_text(" ".join(piece.split()))[:1_000]
        for piece in pieces
        if piece.strip()
    )
    if len(cleaned) > 100:
        raise ValueError("No more than 100 bounded limitations are allowed.")
    if len(set(cleaned)) != len(cleaned):
        raise ValueError("Review limitations must not contain duplicates.")
    return cleaned


@cache_control(private=True, no_store=True)
@login_required
@require_http_methods(["GET", "POST"])
def remediation_review_view(request: HttpRequest, finding_id: str) -> HttpResponse:
    try:
        actor = _reviewer(request)
        workspace_id = _workspace_id(request)
        if workspace_id is None:
            raise WebPermissionDenied(
                "Independent remediation review must return to a durable chat workspace."
            )
        finding = remediation_finding_store().get(finding_id)
    except WebPermissionDenied as exc:
        return _denied(request, str(exc), status=409 if "workspace" in str(exc) else 403)
    except FindingStoreError as exc:
        raise Http404(str(exc)) from exc

    remediation = finding.remediation
    latest_retest = (
        remediation.retest_history[-1]
        if remediation is not None and remediation.retest_history
        else None
    )
    eligible = (
        finding.status == FindingStatus.AWAITING_REMEDIATION_REVIEW
        and remediation is not None
        and remediation.remediation_id is not None
        and remediation.state == RemediationState.AWAITING_REVIEW
        and latest_retest is not None
        and latest_retest.outcome.value == "passed"
    )
    submitted = {
        "evidence_lineage_complete": "unknown",
        "fixed_revision_matches": "unknown",
        "approved_scope_respected": "unknown",
        "security_claim_supported": "unknown",
        "regressions_acceptable": "unknown",
        "rationale": "",
        "limitations": "",
        "blocked_reason": "",
    }
    error = None

    if request.method == "POST":
        submitted = {
            "evidence_lineage_complete": request.POST.get(
                "evidence_lineage_complete", "unknown"
            ),
            "fixed_revision_matches": request.POST.get(
                "fixed_revision_matches", "unknown"
            ),
            "approved_scope_respected": request.POST.get(
                "approved_scope_respected", "unknown"
            ),
            "security_claim_supported": request.POST.get(
                "security_claim_supported", "unknown"
            ),
            "regressions_acceptable": request.POST.get(
                "regressions_acceptable", "unknown"
            ),
            "rationale": request.POST.get("rationale", "").strip(),
            "limitations": request.POST.get("limitations", "").strip(),
            "blocked_reason": request.POST.get("blocked_reason", "").strip(),
        }
        try:
            if not eligible:
                raise FindingLifecycleError(
                    "This remediation is not awaiting an independent review decision."
                )
            expected_revision = int(request.POST.get("expected_revision", "-1"))
            checklist = RemediationReviewChecklist(
                evidence_lineage_complete=_optional_boolean(
                    submitted["evidence_lineage_complete"]
                ),
                fixed_revision_matches=_optional_boolean(
                    submitted["fixed_revision_matches"]
                ),
                approved_scope_respected=_optional_boolean(
                    submitted["approved_scope_respected"]
                ),
                security_claim_supported=_optional_boolean(
                    submitted["security_claim_supported"]
                ),
                regressions_acceptable=_optional_boolean(
                    submitted["regressions_acceptable"]
                ),
            )
            updated, bundle = remediation_review_service().record(
                finding_id=finding_id,
                expected_revision=expected_revision,
                reviewer_id=actor.governance_identity.reviewer_id,
                reviewer_secret=request.POST.get("governance_secret", ""),
                checklist=checklist,
                rationale=redact_text(submitted["rationale"]),
                limitations=_limitations(submitted["limitations"]),
                blocked_reason=(
                    redact_text(submitted["blocked_reason"])
                    if submitted["blocked_reason"]
                    else None
                ),
            )
        except (
            FindingConflict,
            FindingLifecycleError,
            FindingStoreError,
            RemediationReviewError,
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
                        "The remediation graph is unavailable after review persistence."
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
                    "The signed review receipt was recorded, but chat projection must be retried "
                    "from the remediation page.",
                )
            if bundle.outcome.value == "approved":
                messages.success(
                    request,
                    "Independent review approved the remediation. Report generation is now ready, "
                    "but merge, closure, release and publication remain separate.",
                )
            else:
                messages.warning(
                    request,
                    f"Independent review returned {bundle.outcome.value}; report generation remains "
                    "blocked and bounded remediation rework is required.",
                )
            return redirect(remediation_review_url(finding_id, workspace_id))

    latest_review = (
        remediation.review_history[-1]
        if remediation is not None and remediation.review_history
        else None
    )
    bundle = None
    if latest_review is not None:
        try:
            bundle = remediation_review_receipt_store().load(latest_review.receipt_id)
        except RemediationReviewError:
            bundle = None
    graph = project_remediation_finding(finding)
    return _render(
        request,
        "web/remediation_review.html",
        {
            "page_title": f"Independent remediation review for {finding_id}",
            "finding": finding,
            "remediation": remediation,
            "latest_retest": latest_retest,
            "latest_review": latest_review,
            "review_bundle": bundle,
            "assessment_graph": graph,
            "eligible": eligible,
            "submitted": submitted,
            "error": error,
            "actor_id": actor.governance_identity.reviewer_id,
            "workspace_return_url": remediation_workspace_url(workspace_id),
            "remediation_url": remediation_detail_url(finding_id, workspace_id),
        },
        status=200 if eligible or latest_review is not None else 409,
    )


__all__ = ["remediation_review_url", "remediation_review_view"]
