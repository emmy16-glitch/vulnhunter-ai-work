"""Protected workspace and downloads for governed final remediation reports."""

from __future__ import annotations

import re

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ObjectDoesNotExist
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.views.decorators.cache import cache_control
from django.views.decorators.http import require_GET, require_http_methods

from vulnhunter.assessment_graph import AssessmentGraphError
from vulnhunter.findings import (
    FindingConflict,
    FindingLifecycleError,
    FindingStatus,
    FindingStoreError,
    RemediationState,
)
from vulnhunter.reports import FinalRemediationReportError, FinalReportFormat
from vulnhunter.security import redact_text
from vulnhunter.web.final_report_service import (
    final_report_pdf_readiness,
    final_report_service,
    final_report_store,
)
from vulnhunter.web.remediation_assessment_graph import project_remediation_finding
from vulnhunter.web.remediation_conversation_state import (
    remediation_detail_url,
    remediation_finding_store,
    remediation_workspace_url,
    remember_remediation_workspace,
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


def _report_writer(request: HttpRequest):
    actor = authorized_actor(
        request.user,
        required_actions=("report.export", "finding.read"),
    )
    if "campaign_admin" not in actor.governance_identity.roles:
        raise WebPermissionDenied(
            "Final report generation requires an active governed administrator identity."
        )
    return actor


def _report_reader(request: HttpRequest):
    return authorized_actor(
        request.user,
        required_actions=("report.read", "finding.read"),
    )


def _workspace_id(request: HttpRequest) -> str | None:
    thread = getattr(request, "vulnhunter_thread", None)
    thread_id = getattr(thread, "thread_id", None)
    return str(thread_id) if thread_id is not None else None


def remediation_final_report_url(finding_id: str, workspace_id: str | None) -> str:
    base = reverse("web-remediation-final-report", kwargs={"finding_id": finding_id})
    if workspace_id:
        return f"{base}?thread={workspace_id}"
    return base


def remediation_publication_url(finding_id: str, workspace_id: str | None) -> str:
    base = reverse("web-remediation-publication", kwargs={"finding_id": finding_id})
    if workspace_id:
        return f"{base}?thread={workspace_id}"
    return base


def remediation_final_report_download_url(
    finding_id: str,
    artifact_format: str,
    workspace_id: str | None,
) -> str:
    base = reverse(
        "web-remediation-final-report-download",
        kwargs={"finding_id": finding_id, "artifact_format": artifact_format},
    )
    if workspace_id:
        return f"{base}?thread={workspace_id}"
    return base


def _limitations(value: str) -> tuple[str, ...]:
    pieces = re.split(r"[\n,]+", value)
    cleaned = tuple(
        redact_text(" ".join(piece.split()))[:1_000] for piece in pieces if piece.strip()
    )
    if len(cleaned) > 100:
        raise ValueError("No more than 100 bounded report limitations are allowed.")
    if len(set(cleaned)) != len(cleaned):
        raise ValueError("Report limitations must not contain duplicates.")
    return cleaned


@cache_control(private=True, no_store=True)
@login_required
@require_http_methods(["GET", "POST"])
def remediation_final_report_view(request: HttpRequest, finding_id: str) -> HttpResponse:
    try:
        actor = _report_writer(request)
        workspace_id = _workspace_id(request)
        if workspace_id is None:
            raise WebPermissionDenied(
                "Final report generation must return to a durable chat workspace."
            )
        finding = remediation_finding_store().get(finding_id)
    except WebPermissionDenied as exc:
        return _denied(request, str(exc), status=409 if "workspace" in str(exc) else 403)
    except FindingStoreError as exc:
        raise Http404(str(exc)) from exc

    remediation = finding.remediation
    latest_review = (
        remediation.review_history[-1]
        if remediation is not None and remediation.review_history
        else None
    )
    latest_report = (
        remediation.report_history[-1]
        if remediation is not None and remediation.report_history
        else None
    )
    eligible = (
        finding.status == FindingStatus.READY_FOR_REPORT
        and remediation is not None
        and remediation.remediation_id is not None
        and remediation.state == RemediationState.REVIEW_APPROVED
        and latest_review is not None
        and latest_review.outcome.value == "approved"
    )
    submitted = {"limitations": "", "include_pdf": False}
    error = None

    if request.method == "POST":
        submitted = {
            "limitations": request.POST.get("limitations", "").strip(),
            "include_pdf": request.POST.get("include_pdf", "").strip().casefold()
            in {"1", "true", "yes", "on"},
        }
        try:
            if not eligible:
                raise FindingLifecycleError(
                    "This remediation is not ready for governed final report generation."
                )
            expected_revision = int(request.POST.get("expected_revision", "-1"))
            updated, bundle = final_report_service().generate(
                finding_id=finding_id,
                expected_revision=expected_revision,
                generator_id=actor.governance_identity.reviewer_id,
                generator_secret=request.POST.get("governance_secret", ""),
                limitations=_limitations(str(submitted["limitations"])),
                include_pdf=bool(submitted["include_pdf"]),
            )
        except (
            FinalRemediationReportError,
            FindingConflict,
            FindingLifecycleError,
            FindingStoreError,
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
                        "The remediation graph is unavailable after report persistence."
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
                    "The signed final report was recorded, but chat projection must be retried "
                    "from the remediation page.",
                )
            messages.success(
                request,
                "The signed final report and unreleased export manifest were generated. "
                "Finding closure, release and publication remain separate human-authorised steps.",
            )
            return redirect(remediation_final_report_url(finding_id, workspace_id))

    bundle = None
    if latest_report is not None:
        try:
            bundle = final_report_store().load(latest_report.report_id)
        except FinalRemediationReportError:
            bundle = None
    graph = project_remediation_finding(finding)
    artifact_downloads: list[dict[str, object]] = []
    if bundle is not None:
        artifact_downloads = [
            {
                "artifact": item,
                "url": remediation_final_report_download_url(
                    finding_id,
                    item.format.value,
                    workspace_id,
                ),
            }
            for item in bundle.manifest.artifacts
        ]
    readiness = final_report_pdf_readiness()
    return _render(
        request,
        "web/remediation_final_report.html",
        {
            "page_title": f"Final remediation report for {finding_id}",
            "finding": finding,
            "remediation": remediation,
            "latest_review": latest_review,
            "latest_report": latest_report,
            "report_bundle": bundle,
            "assessment_graph": graph,
            "eligible": eligible,
            "submitted": submitted,
            "error": error,
            "actor_id": actor.governance_identity.reviewer_id,
            "pdf_readiness": readiness,
            "artifact_downloads": artifact_downloads,
            "workspace_return_url": remediation_workspace_url(workspace_id),
            "remediation_url": remediation_detail_url(finding_id, workspace_id),
            "publication_url": remediation_publication_url(finding_id, workspace_id),
        },
        status=200 if eligible or latest_report is not None else 409,
    )


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def remediation_final_report_download_view(
    request: HttpRequest,
    finding_id: str,
    artifact_format: str,
) -> HttpResponse:
    try:
        _report_reader(request)
        finding = remediation_finding_store().get(finding_id)
    except WebPermissionDenied as exc:
        return HttpResponse(str(exc), status=403, content_type="text/plain; charset=utf-8")
    except FindingStoreError as exc:
        raise Http404(str(exc)) from exc
    remediation = finding.remediation
    latest_report = (
        remediation.report_history[-1]
        if remediation is not None and remediation.report_history
        else None
    )
    if latest_report is None:
        raise Http404("The final remediation report does not exist.")
    try:
        normalized = FinalReportFormat(artifact_format)
        store = final_report_store()
        bundle = store.load(latest_report.report_id)
        path = store.artifact_path(latest_report.report_id, normalized)
        artifact = next(item for item in bundle.manifest.artifacts if item.format == normalized)
        data = path.read_bytes()
    except (FinalRemediationReportError, OSError, StopIteration, ValueError) as exc:
        raise Http404("The requested final report artifact is unavailable.") from exc
    response = HttpResponse(data, content_type=artifact.content_type)
    response["Content-Disposition"] = f'attachment; filename="{artifact.filename}"'
    response["X-VulnHunter-Artifact-SHA256"] = artifact.sha256
    response["X-VulnHunter-Manifest-SHA256"] = bundle.manifest.fingerprint()
    response["X-VulnHunter-Release-State"] = bundle.manifest.release_state
    return response


__all__ = [
    "remediation_final_report_download_url",
    "remediation_final_report_download_view",
    "remediation_final_report_url",
    "remediation_final_report_view",
    "remediation_publication_url",
]
