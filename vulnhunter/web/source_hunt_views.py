"""Authenticated web surface for queued, exact Groq source-code hunts."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render
from django.views.decorators.cache import cache_control
from django.views.decorators.http import require_http_methods

from vulnhunter.source_hunt import (
    RemoteSourceProcessingApproval,
    RepositorySnapshotBuilder,
    RepositoryVisibility,
    SourceHuntError,
    SourceHuntPolicy,
    SourceHuntStore,
)
from vulnhunter.source_hunt.jobs import SourceHuntJob, SourceHuntJobStore
from vulnhunter.web.services import WebPermissionDenied, authorized_actor
from vulnhunter.web.source_hunt_assessment_graph import (
    bind_source_hunt_assessment_graph,
    project_source_hunt_state,
)
from vulnhunter.web.source_hunt_conversation_state import (
    current_source_hunt_plan,
    record_source_hunt_event,
    remember_source_hunt_plan,
    source_hunt_setup_url,
    source_hunt_workspace_url,
)


def _approved_roots() -> tuple[Path, ...]:
    raw = os.environ.get("VULNHUNTER_SOURCE_HUNT_ROOTS", str(settings.BASE_DIR))
    return tuple(Path(item).expanduser() for item in raw.split(os.pathsep) if item.strip())


def _job_store() -> SourceHuntJobStore:
    root = Path(
        os.environ.get(
            "VULNHUNTER_SOURCE_HUNT_JOB_ROOT",
            str(settings.BASE_DIR / ".local" / "source-hunt-jobs"),
        )
    )
    return SourceHuntJobStore(root)


def _report_store() -> SourceHuntStore:
    root = Path(
        os.environ.get(
            "VULNHUNTER_SOURCE_HUNT_REPORT_ROOT",
            str(settings.BASE_DIR / ".local" / "source-hunt-reports"),
        )
    )
    return SourceHuntStore(root)


def _policy() -> SourceHuntPolicy:
    return SourceHuntPolicy(
        approved_roots=_approved_roots(),
        model=settings.VULNHUNTER_GROQ_MODEL,
        maximum_prompt_bytes=min(settings.VULNHUNTER_GROQ_MAX_INPUT_BYTES, 100_000),
        maximum_output_tokens=min(settings.VULNHUNTER_GROQ_MAX_OUTPUT_TOKENS, 4_000),
        timeout_seconds=min(settings.VULNHUNTER_GROQ_TIMEOUT_SECONDS, 180),
    )


def _denied(request: HttpRequest, message: str) -> HttpResponse:
    return render(
        request,
        "web/denied.html",
        {
            "page_title": "Access Denied",
            "current_route": "web-source-hunt",
            "denied_message": message,
        },
        status=403,
    )


@cache_control(private=True, no_store=True)
@login_required
@require_http_methods(["GET", "POST"])
def source_hunt_view(request: HttpRequest) -> HttpResponse:
    try:
        authorized_actor(request.user, required_actions=("scan.create",))
    except WebPermissionDenied as exc:
        return _denied(request, str(exc))

    report = None
    queued_job = None
    error = None
    submitted = {
        "repository_root": "",
        "revision": "",
        "visibility": "private",
        "permitted_paths": ".",
    }
    current_plan = (
        current_source_hunt_plan(request)
        if getattr(request, "vulnhunter_thread", None) is not None
        else None
    )

    report_id = request.GET.get("report", "").strip()
    if report_id:
        try:
            report = _report_store().load(report_id)
        except (OSError, ValueError) as exc:
            error = str(exc)

    if request.method == "POST":
        submitted = {
            "repository_root": request.POST.get("repository_root", "").strip(),
            "revision": request.POST.get("revision", "").strip(),
            "visibility": request.POST.get("visibility", "private").strip(),
            "permitted_paths": request.POST.get("permitted_paths", ".").strip(),
        }
        try:
            if not settings.VULNHUNTER_GROQ_ENABLED:
                raise SourceHuntError("Groq source analysis is disabled by configuration.")
            if request.POST.get("approve_remote_processing") != "yes":
                raise SourceHuntError(
                    "Confirm that the exact bounded source excerpts may be transmitted to Groq."
                )
            if request.POST.get("confirm_no_customer_data") != "yes":
                raise SourceHuntError(
                    "Confirm that customer data is absent from the approved source paths."
                )
            if request.POST.get("confirm_retention_reviewed") != "yes":
                raise SourceHuntError(
                    "Confirm that Groq retention and data controls were reviewed."
                )
            password = request.POST.get("password", "")
            if not password or not request.user.check_password(password):
                raise SourceHuntError("Password re-authentication failed.")
            visibility = RepositoryVisibility(submitted["visibility"])
            permitted_paths = tuple(
                item.strip() for item in submitted["permitted_paths"].split(",") if item.strip()
            ) or (".",)
            repository = Path(submitted["repository_root"])
            policy = _policy()
            snapshot = RepositorySnapshotBuilder(policy).build(
                repository,
                revision=submitted["revision"] or None,
            )
            now = datetime.now(UTC)
            approval = RemoteSourceProcessingApproval.create(
                repository_id=snapshot.repository_id,
                revision=snapshot.revision,
                snapshot_sha256=snapshot.snapshot_sha256,
                visibility=visibility,
                permitted_paths=permitted_paths,
                customer_data_confirmed_absent=True,
                provider_retention_reviewed=True,
                approved_by=request.user.get_username(),
                approved_at=now,
                expires_at=now + timedelta(hours=1),
            )
            queued_job = SourceHuntJob.create(
                repository_root=repository,
                snapshot=snapshot,
                approval=approval,
                model=policy.model,
                now=now,
            )
            graph = bind_source_hunt_assessment_graph(request, job=queued_job)
            try:
                _job_store().enqueue(queued_job)
            except (OSError, ValueError) as exc:
                project_source_hunt_state(
                    queued_job.job_id,
                    state="failed",
                    reason="The Source Hunt queue rejected the immutable job.",
                )
                raise exc
            if getattr(request, "vulnhunter_thread", None) is not None:
                current_plan = remember_source_hunt_plan(
                    request,
                    job=queued_job,
                    graph=graph,
                )
                record_source_hunt_event(request, current_plan)
        except (SourceHuntError, RuntimeError, ValueError, OSError) as exc:
            error = str(exc)

    jobs = _job_store().list(limit=20)
    reports = _report_store().list(limit=12)
    current_thread = getattr(request, "vulnhunter_thread", None)
    thread_id = str(current_thread.thread_id) if current_thread is not None else ""
    return render(
        request,
        "web/source_hunt.html",
        {
            "page_title": "Source Hunt",
            "current_route": "web-source-hunt",
            "report": report,
            "queued_job": queued_job,
            "jobs": jobs,
            "reports": reports,
            "error": error,
            "submitted": submitted,
            "groq_enabled": settings.VULNHUNTER_GROQ_ENABLED,
            "approved_roots": tuple(str(item) for item in _approved_roots()),
            "current_source_hunt": current_plan,
            "thread_id": thread_id,
            "source_hunt_url": source_hunt_setup_url(request),
            "workspace_return_url": source_hunt_workspace_url(request),
        },
    )
