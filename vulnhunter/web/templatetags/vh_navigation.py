from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from django import template
from django.conf import settings

from vulnhunter.web.models import WebUserMapping
from vulnhunter.web.services import navigation_for, role_policy

register = template.Library()


@register.simple_tag
def professional_title(page_title: object) -> str:
    """Return concise product terminology for legacy route titles."""

    value = str(page_title)
    exact = {
        "Agent Runs": "Assessment History",
        "Assessments": "Assessment History",
        "Machine Oracle": "Verification",
        "Models": "Analysis Services",
        "Intelligence components": "Analysis Services",
        "New Bounded Scan": "Assessment Workspace",
    }
    if value.startswith("Agent Run "):
        return "Assessment " + value.removeprefix("Agent Run ")
    return exact.get(value, value)


@register.simple_tag
def user_can(user: Any, *actions: str) -> bool:
    """Return whether any mapped product role permits one supplied action."""

    if not getattr(user, "is_authenticated", False) or not actions:
        return False
    try:
        mapping = user.vulnhunter_mapping
    except WebUserMapping.DoesNotExist:
        return False
    roles = tuple(str(item) for item in mapping.product_roles if isinstance(item, str))
    return role_policy().any_role_allows(roles, *actions)


@register.simple_tag
def account_role_label(user: Any) -> str:
    """Return a human-friendly account role without exposing internal setup wording."""

    if not getattr(user, "is_authenticated", False):
        return "Signed out"
    try:
        mapping = user.vulnhunter_mapping
    except WebUserMapping.DoesNotExist:
        return "Unmapped account"
    labels = {
        "system-administrator": "Plan approver",
        "campaign-operator": "Assessment operator",
        "campaign-approver": "Campaign approver",
        "reviewer": "Evidence reviewer",
        "adjudicator": "Adjudicator",
        "security-auditor": "Security auditor",
        "model-analyst": "Model analyst",
        "read-only-observer": "Read-only observer",
    }
    roles = [
        labels.get(str(item), str(item).replace("-", " ").title()) for item in mapping.product_roles
    ]
    return " · ".join(roles) if roles else "Governed account"


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
    """Return the single blueprint-backed role-aware product navigation."""

    return navigation_for(user)
