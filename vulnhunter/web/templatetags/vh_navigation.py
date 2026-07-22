from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from django import template
from django.conf import settings

from vulnhunter.web.models import WebUserMapping
from vulnhunter.web.services import role_policy

register = template.Library()


@register.simple_tag
def professional_title(page_title: object) -> str:
    """Return concise product terminology for legacy route titles."""

    value = str(page_title)
    exact = {
        "Agent Runs": "Assessments",
        "Machine Oracle": "Verification",
        "Models": "Analysis Services",
        "Intelligence components": "Analysis Services",
        "New Bounded Scan": "New Assessment",
    }
    if value.startswith("Agent Run "):
        return "Assessment " + value.removeprefix("Agent Run ")
    return exact.get(value, value)


@register.simple_tag
def security_runtime() -> dict[str, object]:
    """Return fail-closed, non-secret activation state for UI status copy."""

    try:
        runtime = json.loads(
            Path(settings.VULNHUNTER_SECURITY_TOOL_CONFIG).read_text(encoding="utf-8")
        )
        worker = json.loads(
            Path(settings.VULNHUNTER_NUCLEI_WORKER_POLICY).read_text(encoding="utf-8")
        )
    except (OSError, TypeError, json.JSONDecodeError):
        return {
            "configured": False,
            "state": "Unavailable",
            "detail": "The governed security-tool configuration could not be validated.",
            "engine_version": "Unknown",
            "templates_version": "Unknown",
            "connectors_enabled": False,
            "validation_enabled": False,
            "worker_enabled": False,
        }

    nuclei = runtime.get("nuclei") if isinstance(runtime.get("nuclei"), dict) else {}
    scanner_worker = (
        runtime.get("scanner_worker") if isinstance(runtime.get("scanner_worker"), dict) else {}
    )
    flags = (
        runtime.get("execution_enabled") is True,
        runtime.get("active_assessment_enabled") is True,
        runtime.get("validation_enabled") is True,
        runtime.get("connectors_enabled") is True,
        nuclei.get("enabled") is True,
        nuclei.get("real_runner_enabled") is True,
        scanner_worker.get("execution_enabled") is True,
        scanner_worker.get("transport_enabled") is True,
        bool(settings.VULNHUNTER_NUCLEI_PILOT_ENQUEUE_ENABLED),
        worker.get("enabled") is True,
    )
    configured = all(flags)
    engine = str(nuclei.get("engine_version", "Unknown"))
    templates = str(nuclei.get("templates_version", "Unknown"))
    return {
        "configured": configured,
        "state": "Enabled by policy" if configured else "Gated",
        "detail": (
            f"Approved passive assessments may enter the signed worker queue with Nuclei "
            f"{engine} and templates {templates}. The worker verifies the signing key, "
            "pinned binary, reviewed templates, private target and exact approval before execution."
            if configured
            else "One or more governed runtime, queue or worker-policy gates are disabled."
        ),
        "engine_version": engine,
        "templates_version": templates,
        "connectors_enabled": runtime.get("connectors_enabled") is True,
        "validation_enabled": runtime.get("validation_enabled") is True,
        "worker_enabled": scanner_worker.get("execution_enabled") is True
        and scanner_worker.get("transport_enabled") is True,
    }


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
                "web-oracle-overview",
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
            "section_label": "Analysis",
            "label": "Datasets",
            "url_name": "web-dataset-list",
            "icon": "database",
            "actions": ("dataset.read",),
            "active_routes": ("web-dataset-list",),
        },
        {
            "section_id": "intelligence",
            "section_label": "Analysis",
            "label": "Analysis Services",
            "url_name": "web-model-list",
            "icon": "model",
            "actions": ("model.read", "audit.read"),
            "active_routes": ("web-model-list",),
        },
        {
            "section_id": "intelligence",
            "section_label": "Analysis",
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
