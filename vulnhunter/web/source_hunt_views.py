"""Authenticated web surface for exact Groq source-code hunts."""

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

from vulnhunter.providers import GroqProvider, GroqProviderError
from vulnhunter.source_hunt import (
    GroqSourceHunt,
    RemoteSourceProcessingApproval,
    RepositorySnapshotBuilder,
    RepositoryVisibility,
    SourceHuntError,
    SourceHuntPolicy,
    SourceHuntStore,
)
from vulnhunter.web.services import WebPermissionDenied, authorized_actor


def _approved_roots() -> tuple[Path, ...]:
    raw = os.environ.get("VULNHUNTER_SOURCE_HUNT_ROOTS", str(settings.BASE_DIR))
    return tuple(Path(item).expanduser() for item in raw.split(os.pathsep) if item.strip())


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
    error = None
    submitted = {
        "repository_root": "",
        "revision": "",
        "visibility": "private",
        "permitted_paths": ".",
    }
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
            password = request.POST.get("password", "")
            if not password or not request.user.check_password(password):
                raise SourceHuntError("Password re-authentication failed.")
            visibility = RepositoryVisibility(submitted["visibility"])
            permitted_paths = tuple(
                item.strip()
                for item in submitted["permitted_paths"].split(",")
                if item.strip()
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
                approved_by=request.user.get_username(),
                approved_at=now,
                expires_at=now + timedelta(minutes=30),
            )
            provider = GroqProvider.from_key_file(
                Path(settings.VULNHUNTER_GROQ_API_KEY_FILE),
                approved_models=(
                    settings.VULNHUNTER_GROQ_MODEL,
                    settings.VULNHUNTER_GROQ_FALLBACK_MODEL,
                ),
                api_base=settings.VULNHUNTER_GROQ_API_BASE,
            )
            report = GroqSourceHunt(connector=provider, policy=policy).run(
                repository,
                approval=approval,
                revision=snapshot.revision,
            )
            _report_store().save(report)
        except (GroqProviderError, SourceHuntError, ValueError, OSError) as exc:
            error = str(exc)

    reports = _report_store().list(limit=12)
    return render(
        request,
        "web/source_hunt.html",
        {
            "page_title": "Source Hunt",
            "current_route": "web-source-hunt",
            "report": report,
            "reports": reports,
            "error": error,
            "submitted": submitted,
            "groq_enabled": settings.VULNHUNTER_GROQ_ENABLED,
            "approved_roots": tuple(str(item) for item in _approved_roots()),
        },
    )
