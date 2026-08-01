from __future__ import annotations

import sqlite3
from pathlib import Path

from django import template
from django.conf import settings

from vulnhunter.authorization import AuthorizationStore
from vulnhunter.exceptions import AuthorizationError, GovernanceError
from vulnhunter.governance.campaign_operations import assess_campaign_operations
from vulnhunter.governance.store import GovernanceStore
from vulnhunter.observations.storage import ScanRepository
from vulnhunter.web.services import WebPermissionDenied, authorized_actor

register = template.Library()


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


@register.inclusion_tag("web/_campaign_operations.html", takes_context=True)
def campaign_operations_panel(context, campaign_id: str) -> dict[str, object]:
    """Load one read-only operator assessment inside the protected campaign page."""

    request = context.get("request")
    if request is None:
        return {"operations": None, "operations_error": "Campaign operations are unavailable."}
    try:
        authorized_actor(request.user, required_actions=("campaign.read",))
    except WebPermissionDenied:
        return {"operations": None, "operations_error": "Campaign operations are unavailable."}

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
        return {
            "operations": None,
            "operations_error": "A required governed store is missing.",
        }

    try:
        governance_store = GovernanceStore.from_path(governance_path)
        authorization_store = AuthorizationStore.from_path(authorization_path)
        operations = assess_campaign_operations(
            governance_store,
            authorization_store,
            _repositories_for_campaign(governance_store, campaign_id),
            package_root,
            campaign_id=campaign_id,
        )
    except (
        AuthorizationError,
        GovernanceError,
        OSError,
        RuntimeError,
        ValueError,
        sqlite3.Error,
    ):
        return {
            "operations": None,
            "operations_error": "Campaign operations could not be assessed safely.",
        }
    return {"operations": operations, "operations_error": None}
