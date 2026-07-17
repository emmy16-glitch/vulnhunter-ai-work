from __future__ import annotations

from typing import Any

from django import template

from vulnhunter.web.models import WebUserMapping
from vulnhunter.web.services import role_policy

register = template.Library()


@register.simple_tag
def canonical_navigation(user: Any) -> tuple[dict[str, object], ...]:
    """Return one role-aware sidebar destination per product capability."""

    entries = (
        {
            "section_id": "overview",
            "section_label": "Overview",
            "label": "Dashboard",
            "url_name": "web-dashboard",
            "icon": "grid",
            "actions": ("dashboard.read",),
            "active_routes": ("web-dashboard",),
        },
        {
            "section_id": "operations",
            "section_label": "Operations",
            "label": "Authorizations",
            "url_name": "web-authorization-list",
            "icon": "authorization",
            "actions": ("authorization.read",),
            "active_routes": ("web-authorization-list",),
        },
        {
            "section_id": "operations",
            "section_label": "Operations",
            "label": "Assessments",
            "url_name": "web-scan-run-list",
            "icon": "assessment",
            "actions": ("scan.read", "scan.read_summary", "scan.create", "audit.read"),
            "active_routes": (
                "web-scan-run-list",
                "web-scan-run-detail",
                "web-agent-run-list",
                "web-agent-run-detail",
                "web-agent-run-activity",
                "web-agent-run-activity-stream",
                "web-agent-run-stop",
                "web-new-scan",
                "web-advanced-profiles",
            ),
        },
        {
            "section_id": "operations",
            "section_label": "Operations",
            "label": "Findings",
            "url_name": "web-findings-overview",
            "icon": "finding",
            "actions": ("finding.read", "scan.read", "audit.read"),
            "active_routes": ("web-findings-overview",),
        },
        {
            "section_id": "operations",
            "section_label": "Operations",
            "label": "Machine Oracle",
            "url_name": "web-oracle-overview",
            "icon": "oracle",
            "actions": ("model.read", "scan.read", "audit.read"),
            "active_routes": ("web-oracle-overview",),
        },
        {
            "section_id": "review",
            "section_label": "Review",
            "label": "Approval Centre",
            "url_name": "web-approval-list",
            "icon": "shield",
            "actions": ("audit.read", "settings.manage"),
            "active_routes": ("web-approval-list", "web-approval-detail", "web-approval-decision"),
        },
        {
            "section_id": "review",
            "section_label": "Review",
            "label": "Review Queue",
            "url_name": "web-review-queue",
            "icon": "review",
            "actions": ("review.read", "review.read_assigned"),
            "active_routes": ("web-review-queue",),
        },
        {
            "section_id": "review",
            "section_label": "Review",
            "label": "Adjudications",
            "url_name": "web-adjudication-queue",
            "icon": "scale",
            "actions": ("adjudication.read", "adjudication.read_assigned"),
            "active_routes": ("web-adjudication-queue",),
        },
        {
            "section_id": "governance",
            "section_label": "Governance",
            "label": "Campaigns",
            "url_name": "web-campaign-list",
            "icon": "layers",
            "actions": ("campaign.read", "campaign.read_summary"),
            "active_routes": (
                "web-campaign-list",
                "web-campaign-detail",
                "web-readiness-detail",
                "web-pilot-plan-list",
                "web-pilot-plan-detail",
                "web-pilot-plan-validation",
            ),
        },
        {
            "section_id": "governance",
            "section_label": "Governance",
            "label": "Releases",
            "url_name": "web-release-list",
            "icon": "release",
            "actions": ("release.read",),
            "active_routes": ("web-release-list",),
        },
        {
            "section_id": "governance",
            "section_label": "Governance",
            "label": "Reports",
            "url_name": "web-reports-overview",
            "icon": "report",
            "actions": ("report.read", "report.read_own", "report.read_public"),
            "active_routes": ("web-reports-overview",),
        },
        {
            "section_id": "governance",
            "section_label": "Governance",
            "label": "Policies",
            "url_name": "web-governance-overview",
            "icon": "policy",
            "actions": ("campaign.read", "audit.read"),
            "active_routes": (
                "web-governance-overview",
                "web-role-list",
                "web-role-detail",
                "web-skill-list",
                "web-skill-detail",
            ),
        },
        {
            "section_id": "intelligence",
            "section_label": "Intelligence",
            "label": "Datasets",
            "url_name": "web-dataset-list",
            "icon": "database",
            "actions": ("dataset.read",),
            "active_routes": ("web-dataset-list",),
        },
        {
            "section_id": "intelligence",
            "section_label": "Intelligence",
            "label": "Models",
            "url_name": "web-model-list",
            "icon": "model",
            "actions": ("model.read", "audit.read"),
            "active_routes": ("web-model-list",),
        },
        {
            "section_id": "intelligence",
            "section_label": "Intelligence",
            "label": "Mobile APK Analysis",
            "url_name": "web-mobile-analysis",
            "icon": "mobile",
            "actions": ("scan.create", "settings.manage"),
            "active_routes": ("web-mobile-analysis",),
        },
        {
            "section_id": "system",
            "section_label": "System",
            "label": "Integrations & Tools",
            "url_name": "web-security-tool-registry",
            "icon": "link",
            "actions": ("audit.read", "scan.read"),
            "active_routes": ("web-security-tool-registry",),
        },
        {
            "section_id": "system",
            "section_label": "System",
            "label": "Audit Log",
            "url_name": "web-audit-overview",
            "icon": "audit",
            "actions": ("audit.read",),
            "active_routes": ("web-audit-overview",),
        },
        {
            "section_id": "system",
            "section_label": "System",
            "label": "Settings",
            "url_name": "web-settings-overview",
            "icon": "settings",
            "actions": ("settings.manage", "audit.read", "dashboard.read"),
            "active_routes": ("web-settings-overview", "web-status"),
        },
    )

    if not getattr(user, "is_authenticated", False):
        return ()
    try:
        mapping = user.vulnhunter_mapping
    except WebUserMapping.DoesNotExist:
        return ()

    roles = tuple(str(item) for item in mapping.product_roles if isinstance(item, str))
    policy = role_policy()
    visible: list[dict[str, object]] = []
    previous_section: str | None = None
    for entry in entries:
        if not policy.any_role_allows(roles, *entry["actions"]):
            continue
        item = dict(entry)
        item["section_start"] = entry["section_id"] != previous_section
        previous_section = str(entry["section_id"])
        visible.append(item)
    return tuple(visible)
