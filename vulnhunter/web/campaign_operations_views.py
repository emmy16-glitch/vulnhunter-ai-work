from __future__ import annotations

import sqlite3
from pathlib import Path

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import render
from django.views.decorators.cache import cache_control
from django.views.decorators.http import require_GET

from vulnhunter.authorization import AuthorizationStore
from vulnhunter.exceptions import AuthorizationError, GovernanceError, GovernanceNotFoundError
from vulnhunter.governance.campaign_operations import assess_campaign_operations
from vulnhunter.governance.store import GovernanceStore
from vulnhunter.observations.storage import ScanRepository
from vulnhunter.web.services import (
    WebPermissionDenied,
    authorized_actor,
    operational_unavailable,
)


def _denied(request: HttpRequest, message: str) -> HttpResponse:
    return render(
        request,
        "web/denied.html",
        {
            "page_title": "Access Denied",
            "current_route": "web-campaign-detail",
            "denied_message": message,
        },
        status=403,
    )


def _repositories_for_campaign(
    governance_store: GovernanceStore,
    campaign_id: str,
) -> dict[str, ScanRepository]:
    repositories: dict[str, ScanRepository] = {}
    for scan in governance_store.list_scans(campaign_id):
        if scan.scan_database in repositories:
            continue
        database = Path(scan.scan_database).expanduser()
        if not database.is_file() or database.is_symlink():
            continue
        repositories[scan.scan_database] = ScanRepository.from_path(database)
    return repositories


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def campaign_operations_view(request: HttpRequest, campaign_id: str) -> HttpResponse:
    """Render read-only campaign activation and release readiness for operators."""

    try:
        authorized_actor(request.user, required_actions=("campaign.read",))
    except WebPermissionDenied as exc:
        return _denied(request, str(exc))

    governance_path = Path(settings.VULNHUNTER_GOVERNANCE_DATABASE).expanduser()
    authorization_path = Path(settings.VULNHUNTER_AUTHORIZATION_DATABASE).expanduser()
    package_root = Path(
        getattr(
            settings,
            "VULNHUNTER_CAMPAIGN_RELEASE_PACKAGE_ROOT",
            governance_path.parent / "campaign-release-packages",
        )
    )
    if not governance_path.is_file() or not authorization_path.is_file():
        return operational_unavailable(
            request,
            "Campaign operations are unavailable because a required governed store is missing.",
        )

    try:
        governance_store = GovernanceStore.from_path(governance_path)
        authorization_store = AuthorizationStore.from_path(authorization_path)
        repositories = _repositories_for_campaign(governance_store, campaign_id)
        snapshot = assess_campaign_operations(
            governance_store,
            authorization_store,
            repositories,
            package_root,
            campaign_id=campaign_id,
        )
    except GovernanceNotFoundError as exc:
        raise Http404("Campaign record not found.") from exc
    except (
        AuthorizationError,
        GovernanceError,
        OSError,
        RuntimeError,
        ValueError,
        sqlite3.Error,
    ):
        return operational_unavailable(
            request,
            "Campaign operations could not be assessed safely.",
        )

    return render(
        request,
        "web/campaign_operations.html",
        {
            "page_title": f"Campaign Operations · {snapshot.campaign_id}",
            "current_route": "web-campaign-detail",
            "operations": snapshot,
        },
    )
