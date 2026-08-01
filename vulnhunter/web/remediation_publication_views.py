"""Protected request, approval, publication, correction, and revocation workflow."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ObjectDoesNotExist
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.views.decorators.cache import cache_control
from django.views.decorators.http import require_http_methods

from vulnhunter.assessment_graph import AssessmentGraphError
from vulnhunter.findings import FindingStoreError
from vulnhunter.publication import PublicationServiceError, PublicationStoreError
from vulnhunter.reports import FinalRemediationReportError
from vulnhunter.security import redact_text
from vulnhunter.web.final_report_service import final_report_store
from vulnhunter.web.publication_service import (
    PublicationRuntimeConfig,
    publication_runtime_config,
    publication_service,
    publication_store,
)
from vulnhunter.web.remediation_assessment_graph import project_remediation_finding
from vulnhunter.web.remediation_conversation_state import (
    remediation_detail_url,
    remediation_final_report_url,
    remediation_finding_store,
    remediation_workspace_url,
    remember_remediation_workspace,
)
from vulnhunter.web.services import WebPermissionDenied, authorized_actor


def _render(
    request: HttpRequest,
    context: dict[str, object],
    *,
    status: int = 200,
) -> HttpResponse:
    return render(
        request,
        "web/remediation_publication.html",
        {"current_route": "web-findings-overview", **context},
        status=status,
    )


def _denied(request: HttpRequest, message: str, *, status: int = 403) -> HttpResponse:
    return render(
        request,
        "web/denied.html",
        {
            "page_title": "Access Denied",
            "current_route": "web-findings-overview",
            "denied_message": message,
        },
        status=status,
    )


def _publication_reader(request: HttpRequest):
    return authorized_actor(
        request.user,
        required_actions=("report.read", "finding.read"),
    )


def _publication_actor(request: HttpRequest):
    actor = authorized_actor(
        request.user,
        required_actions=("report.export", "finding.read"),
    )
    if "campaign_admin" not in actor.governance_identity.roles:
        raise WebPermissionDenied(
            "Release actions require an active governed administrator identity."
        )
    return actor


def _workspace_id(request: HttpRequest) -> str | None:
    thread = getattr(request, "vulnhunter_thread", None)
    thread_id = getattr(thread, "thread_id", None)
    return str(thread_id) if thread_id is not None else None


def remediation_publication_url(finding_id: str, workspace_id: str | None) -> str:
    base = reverse("web-remediation-publication", kwargs={"finding_id": finding_id})
    return f"{base}?thread={workspace_id}" if workspace_id else base


def _confirmed(value: str) -> bool:
    return value.strip().casefold() in {"1", "true", "yes", "on"}


def _expiry_hours(value: str) -> int:
    try:
        hours = int(value)
    except ValueError as exc:
        raise PublicationServiceError("release expiry must be a whole number of hours") from exc
    if not 1 <= hours <= 168:
        raise PublicationServiceError("release expiry must be between one hour and seven days")
    return hours


def _workflow_rows(store, finding_id: str, now: datetime) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for release_request in store.list_requests_for_finding(finding_id):
        approval = store.latest_approval_for_request(release_request.request_id)
        publication = store.publication_for_request(release_request.request_id)
        if publication is not None:
            state = store.status(publication.publication_id)
        elif now >= release_request.expires_at.astimezone(UTC):
            state = "expired"
        elif approval is not None and now >= approval.expires_at.astimezone(UTC):
            state = "expired"
        elif approval is not None:
            state = "approved"
        else:
            state = "requested"
        rows.append(
            {
                "request": release_request,
                "approval": approval,
                "publication": publication,
                "state": state,
            }
        )
    rows.reverse()
    return rows


def _configured_destinations(runtime: PublicationRuntimeConfig) -> list[dict[str, object]]:
    return [
        {
            "destination_id": item.destination_id,
            "label": item.label,
            "allowed_formats": [value.value for value in item.allowed_formats],
        }
        for item in runtime.destinations
    ]


def _current_publication(store, finding_id: str):
    current = [
        item
        for item in store.list_publications_for_finding(finding_id)
        if store.status(item.publication_id) == "published"
    ]
    if len(current) > 1:
        raise PublicationStoreError(
            "multiple current publications make correction authority ambiguous"
        )
    return current[0] if current else None


def _publication_rows(
    store,
    *,
    finding_id: str,
    actor_id: str,
    actor_can_act: bool,
) -> tuple[list[dict[str, object]], tuple[object, ...]]:
    publications = store.list_publications_for_finding(finding_id)
    rows: list[dict[str, object]] = []
    for item in reversed(publications):
        state = store.status(item.publication_id)
        release_actors = {item.requester_id, item.approver_id, item.publisher_id}
        rows.append(
            {
                "publication": item,
                "state": state,
                "fingerprint": item.fingerprint(),
                "correction": store.correction_for_publication(item.publication_id),
                "revocation": store.revocation_for_publication(item.publication_id),
                "actor_can_revoke": (
                    actor_can_act and state == "published" and actor_id not in release_actors
                ),
                "actor_participated": actor_id in release_actors,
            }
        )
    return rows, publications


def _project_workspace(
    request: HttpRequest,
    *,
    finding,
    workspace_id: str | None,
) -> None:
    if workspace_id is None:
        return
    graph = project_remediation_finding(finding)
    if graph is None:
        raise AssessmentGraphError(
            "The remediation graph is unavailable after publication persistence."
        )
    remember_remediation_workspace(
        owner=request.user,
        workspace_id=workspace_id,
        finding=finding,
        graph=graph,
    )


@cache_control(private=True, no_store=True)
@login_required
@require_http_methods(["GET", "POST"])
def remediation_publication_view(request: HttpRequest, finding_id: str) -> HttpResponse:
    try:
        reader = _publication_reader(request)
        finding = remediation_finding_store().get(finding_id)
        runtime = publication_runtime_config()
        store = publication_store()
    except WebPermissionDenied as exc:
        return _denied(request, str(exc))
    except FindingStoreError as exc:
        raise Http404(str(exc)) from exc
    except (PublicationServiceError, PublicationStoreError, OSError, RuntimeError, ValueError):
        return _denied(
            request,
            "The governed publication service is not safely configured for this deployment.",
            status=503,
        )

    workspace_id = _workspace_id(request)
    remediation = finding.remediation
    latest_report = (
        remediation.report_history[-1]
        if remediation is not None and remediation.report_history
        else None
    )
    report_bundle = None
    if latest_report is not None:
        try:
            report_bundle = final_report_store().load(latest_report.report_id)
        except FinalRemediationReportError:
            report_bundle = None

    error = None
    if request.method == "POST":
        try:
            actor = _publication_actor(request)
            service = publication_service()
            action = request.POST.get("action", "").strip().casefold()
            actor_id = actor.governance_identity.reviewer_id
            actor_secret = request.POST.get("governance_secret", "")

            if action == "request":
                if latest_report is None or report_bundle is None:
                    raise PublicationServiceError(
                        "A verified signed final report is required before release "
                        "can be requested."
                    )
                publication_history = store.list_publications_for_finding(finding_id)
                if any(
                    item.source_report_id == latest_report.report_id
                    for item in publication_history
                ):
                    raise PublicationServiceError(
                        "This exact report already has publication history. Generate a new "
                        "signed report before requesting another release."
                    )
                current_publication = _current_publication(store, finding_id)
                correction_id = request.POST.get(
                    "correction_of_publication_id", ""
                ).strip() or None
                if current_publication is not None:
                    if correction_id != current_publication.publication_id:
                        raise PublicationServiceError(
                            "A new report must explicitly correct the current publication."
                        )
                    if not _confirmed(request.POST.get("confirm_correction", "")):
                        raise PublicationServiceError(
                            "Confirm that the correction preserves the superseded publication."
                        )
                elif correction_id is not None:
                    raise PublicationServiceError(
                        "A correction target is not currently published for this finding."
                    )
                release_request = service.request_release(
                    report_id=latest_report.report_id,
                    destination_id=request.POST.get("destination_id", ""),
                    formats=request.POST.getlist("formats"),
                    requester_id=actor_id,
                    requester_secret=actor_secret,
                    reason=redact_text(request.POST.get("reason", "")),
                    expires_at=datetime.now(UTC)
                    + timedelta(hours=_expiry_hours(request.POST.get("expires_in_hours", "24"))),
                    correction_of_publication_id=correction_id,
                )
                success = (
                    f"Release request {release_request.request_id} was signed. A different "
                    "configured authority must approve it before publication."
                )
            elif action == "approve":
                request_id = request.POST.get("request_id", "").strip()
                release_request = store.load_request(request_id)
                if release_request.source_finding_id != finding_id:
                    raise PublicationServiceError("release request does not belong to this finding")
                approval = service.approve_release(
                    request_id=request_id,
                    approver_id=actor_id,
                    approver_secret=actor_secret,
                )
                success = (
                    f"Release approval {approval.approval_id} was signed. A third distinct "
                    "configured authority must publish the exact approved artifacts."
                )
            elif action == "publish":
                request_id = request.POST.get("request_id", "").strip()
                approval_id = request.POST.get("approval_id", "").strip()
                release_request = store.load_request(request_id)
                approval = store.load_approval(approval_id)
                if release_request.source_finding_id != finding_id:
                    raise PublicationServiceError("release request does not belong to this finding")
                if approval.request_id != release_request.request_id:
                    raise PublicationServiceError(
                        "release approval does not belong to the selected request"
                    )
                publication = service.publish(
                    request_id=request_id,
                    approval_id=approval_id,
                    publisher_id=actor_id,
                    publisher_secret=actor_secret,
                )
                success = (
                    f"Publication {publication.publication_id} completed with a signed manifest. "
                    "Finding closure, merge and deployment remain separate."
                )
            elif action == "revoke":
                publication_id = request.POST.get("publication_id", "").strip()
                publication = store.load_publication(publication_id)
                if publication.source_finding_id != finding_id:
                    raise PublicationServiceError(
                        "publication does not belong to this finding"
                    )
                if not _confirmed(request.POST.get("confirm_revocation", "")):
                    raise PublicationServiceError(
                        "Confirm the non-destructive publication revocation."
                    )
                revocation = service.revoke(
                    publication_id=publication_id,
                    authority_id=actor_id,
                    authority_secret=actor_secret,
                    reason=redact_text(request.POST.get("reason", "")),
                )
                success = (
                    f"Revocation {revocation.revocation_id} was signed for publication "
                    f"{publication_id}. Existing artifacts remain preserved with a notice."
                )
            else:
                raise PublicationServiceError("unsupported publication workflow action")
        except WebPermissionDenied as exc:
            return _denied(request, str(exc))
        except (
            FinalRemediationReportError,
            PublicationServiceError,
            PublicationStoreError,
            OSError,
            RuntimeError,
            ValueError,
        ) as exc:
            error = str(exc)
        else:
            try:
                _project_workspace(
                    request,
                    finding=finding,
                    workspace_id=workspace_id,
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
                    "The signed publication record was persisted, but the originating chat "
                    "workspace must refresh its projection.",
                )
            messages.success(request, success)
            return redirect(remediation_publication_url(finding_id, workspace_id))

    actor_id = reader.governance_identity.reviewer_id
    actor_can_act = (
        "campaign_admin" in reader.governance_identity.roles
        and actor_id in runtime.release_authority_ids
    )
    try:
        workflow_rows = _workflow_rows(store, finding_id, datetime.now(UTC))
        publication_rows, publications = _publication_rows(
            store,
            finding_id=finding_id,
            actor_id=actor_id,
            actor_can_act=actor_can_act,
        )
        current_publication = _current_publication(store, finding_id)
    except PublicationStoreError:
        return _denied(
            request,
            "Publication-state integrity verification failed. No release action is available.",
            status=409,
        )

    current_row = next(
        (
            row
            for row in workflow_rows
            if row["state"] in {"requested", "approved"}
            and latest_report is not None
            and row["request"].source_report_id == latest_report.report_id
        ),
        None,
    )
    correction_target = None
    if (
        current_publication is not None
        and latest_report is not None
        and current_publication.source_report_id != latest_report.report_id
    ):
        correction_target = current_publication

    available_formats = (
        [item.format.value for item in report_bundle.manifest.artifacts]
        if report_bundle is not None
        else []
    )
    report_already_published = any(
        item.source_report_id == latest_report.report_id
        for item in publications
        if latest_report is not None
    )
    request_eligible = (
        latest_report is not None
        and report_bundle is not None
        and current_row is None
        and not report_already_published
    )

    return _render(
        request,
        {
            "page_title": f"Governed publication for {finding_id}",
            "finding": finding,
            "remediation": remediation,
            "latest_report": latest_report,
            "report_bundle": report_bundle,
            "workflow_rows": workflow_rows,
            "publication_rows": publication_rows,
            "current_row": current_row,
            "request_eligible": request_eligible,
            "correction_target": correction_target,
            "destinations": _configured_destinations(runtime),
            "available_formats": available_formats,
            "actor_id": actor_id,
            "actor_can_act": actor_can_act,
            "error": error,
            "workspace_return_url": remediation_workspace_url(workspace_id),
            "remediation_url": remediation_detail_url(finding_id, workspace_id),
            "report_url": remediation_final_report_url(finding_id, workspace_id),
        },
        status=200 if latest_report is not None else 409,
    )


__all__ = ["remediation_publication_url", "remediation_publication_view"]
