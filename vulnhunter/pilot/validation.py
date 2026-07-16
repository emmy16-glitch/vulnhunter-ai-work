"""Fail-closed validation for controlled human pilot plans."""

from __future__ import annotations

import ipaddress
import re
from collections import Counter
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from vulnhunter.pilot.models import PilotPlan, PilotReadinessReport
from vulnhunter.pilot.reporting import pilot_plan_sha256, pilot_report_sha256

_CREDENTIAL_KEY_PATTERN = re.compile(
    r"(?:password|passwd|secret|token|api[_-]?key|private[_-]?key|"
    r"access[_-]?key|session[_-]?cookie)",
    re.IGNORECASE,
)
_CREDENTIAL_VALUE_PATTERNS = (
    re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{16,}\b", re.IGNORECASE),
)
_INSTRUCTION_LIKE = re.compile(
    r"\b(ignore previous|system prompt|developer message|execute this|"
    r"run this command|override policy)\b",
    re.IGNORECASE,
)


def _walk(value: Any, path: str = "") -> list[tuple[str, Any]]:
    items: list[tuple[str, Any]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            items.append((child_path, child))
            items.extend(_walk(child, child_path))
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            child_path = f"{path}[{index}]"
            items.append((child_path, child))
            items.extend(_walk(child, child_path))
    return items


def _target_reference_problem(value: str) -> str | None:
    lowered = value.strip().lower()
    if "://" in lowered:
        parsed = urlsplit(lowered)
        host = parsed.hostname
        if host:
            try:
                address = ipaddress.ip_address(host)
            except ValueError:
                return "target_reference must be a local inventory ID, not a URL"
            if not (address.is_loopback or address.is_private or address.is_link_local):
                return "public or external target reference is forbidden"
        return "target_reference must be a local inventory ID, not a URL"
    try:
        address = ipaddress.ip_address(lowered)
    except ValueError:
        return None
    if not (address.is_loopback or address.is_private or address.is_link_local):
        return "public or external target reference is forbidden"
    return "target_reference must use a local inventory identifier rather than embedding an address"


def assess_pilot_plan(
    plan: PilotPlan,
    *,
    assessed_at: datetime | None = None,
) -> PilotReadinessReport:
    """Assess a pilot plan without creating authorization or executing a pilot."""
    now = (assessed_at or datetime.now(UTC)).astimezone(UTC)
    blockers: list[str] = []
    warnings: list[str] = []

    if not plan.local_lab_only:
        blockers.append("pilot must be explicitly local or lab-only")

    authorization_refs = set(plan.authorization_references)
    families: Counter[str] = Counter()
    for application in plan.applications:
        families[application.application_family] += 1
        if application.authorization_reference not in authorization_refs:
            blockers.append(
                f"application {application.application_id} references an undeclared authorization"
            )
        problem = _target_reference_problem(application.target_reference)
        if problem:
            blockers.append(f"application {application.application_id}: {problem}")

    prohibited = " ".join(plan.prohibited_targets).lower()
    if "public" not in prohibited or "external" not in prohibited:
        blockers.append("prohibited targets must explicitly include public and external targets")

    identity_map = {item.identity_id: item for item in plan.identities}
    if len(identity_map) != len(plan.identities):
        blockers.append("identity identifiers must be unique")

    assigned_ids = set(plan.assignments.operator_ids)
    assigned_ids.update(plan.assignments.primary_reviewer_ids)
    assigned_ids.update(
        {
            plan.assignments.adjudicator_id,
            plan.assignments.dataset_quality_auditor_id,
            plan.assignments.test_verifier_id,
            plan.assignments.release_authority_id,
            plan.assignments.emergency_stop_owner_id,
            plan.accountable_owner_id,
        }
    )
    for identity_id in sorted(assigned_ids):
        identity = identity_map.get(identity_id)
        if identity is None:
            blockers.append(f"assigned identity is missing: {identity_id}")
            continue
        if identity.status != "active":
            blockers.append(f"assigned identity {identity_id} is not active: {identity.status}")
        if not identity.human_controlled:
            blockers.append(f"assigned identity {identity_id} must be human-controlled")

    reviewers = plan.assignments.primary_reviewer_ids
    if len(set(reviewers)) != 2:
        blockers.append("exactly two distinct primary reviewers are required")
    operator_ids = set(plan.assignments.operator_ids)
    overlap = operator_ids.intersection(reviewers)
    if overlap:
        blockers.append(
            "operators cannot review their own scan or evidence: " + ", ".join(sorted(overlap))
        )
    if plan.assignments.adjudicator_id in set(reviewers):
        blockers.append("the adjudicator must be separate from both primary reviewers")
    if plan.assignments.adjudicator_id in operator_ids:
        blockers.append("the adjudicator must be separate from scan operators")

    for identity_id in sorted(assigned_ids):
        declaration = plan.conflict_of_interest_declarations.get(identity_id)
        if declaration is None:
            blockers.append(f"conflict-of-interest declaration is missing: {identity_id}")
        elif declaration:
            blockers.append(f"assigned identity has a declared conflict of interest: {identity_id}")

    if plan.connector_policy != "disabled":
        blockers.append("connectors must remain disabled")
    if plan.automatic_campaign_approval:
        blockers.append("automatic campaign approval is forbidden")
    if plan.automatic_vulnerability_confirmation:
        blockers.append("automatic vulnerability confirmation is forbidden")
    if plan.automatic_adjudication:
        blockers.append("automatic adjudication is forbidden")
    if plan.automatic_release:
        blockers.append("automatic release is forbidden")
    if plan.model_training_during_collection:
        blockers.append("model training is forbidden during pilot collection")
    if not plan.release_authority_is_human:
        blockers.append("release authority must remain human")

    if not plan.stop_conditions:
        blockers.append("at least one explicit stop condition is required")
    if not plan.sensitive_data_redaction_policy.strip():
        blockers.append("a sensitive-data redaction policy is required")
    if not plan.duplicate_evidence_policy.strip():
        blockers.append("a duplicate-evidence policy is required")
    if "untrusted" not in plan.untrusted_content_policy.lower():
        blockers.append(
            "untrusted-content policy must explicitly treat external content as untrusted data"
        )

    dumped = plan.model_dump(mode="json")
    for path, value in _walk(dumped):
        final_key = path.rsplit(".", 1)[-1]
        if _CREDENTIAL_KEY_PATTERN.search(final_key):
            blockers.append(f"credential-like field is forbidden: {path}")
        if isinstance(value, str):
            if any(pattern.search(value) for pattern in _CREDENTIAL_VALUE_PATTERNS):
                blockers.append(f"credential-like value is forbidden at {path}")
            if _INSTRUCTION_LIKE.search(value):
                warnings.append(f"instruction-like text remains inert untrusted data at {path}")

    if plan.dataset_targets.minimum_application_families > len(plan.applications):
        warnings.append("application-family diversity target exceeds planned application count")
    class_minimum = plan.dataset_targets.minimum_per_class * len(
        plan.dataset_targets.required_classes
    )
    if plan.dataset_targets.minimum_samples < class_minimum:
        blockers.append("minimum sample target cannot satisfy the declared per-class minimums")

    unique_blockers = tuple(dict.fromkeys(blockers))
    unique_warnings = tuple(dict.fromkeys(warnings))
    metrics: dict[str, object] = {
        "application_count": len(plan.applications),
        "application_family_count": len(families),
        "application_families": dict(sorted(families.items())),
        "assigned_human_role_count": len(assigned_ids),
        "operator_count": len(plan.assignments.operator_ids),
        "reviewer_count": len(set(reviewers)),
        "adjudicator_count": 1,
        "authorization_reference_count": len(authorization_refs),
        "dataset_targets": plan.dataset_targets.model_dump(mode="json"),
        "connector_disabled": plan.connector_policy == "disabled",
        "automatic_actions_prohibited": not any(
            (
                plan.automatic_campaign_approval,
                plan.automatic_vulnerability_confirmation,
                plan.automatic_adjudication,
                plan.automatic_release,
            )
        ),
        "model_training_during_collection": (plan.model_training_during_collection),
        "release_authority_is_human": plan.release_authority_is_human,
    }
    data: dict[str, object] = {
        "plan_id": plan.plan_id,
        "assessed_at": now,
        "valid": not unique_blockers,
        "hard_blockers": unique_blockers,
        "warnings": unique_warnings,
        "informational_metrics": metrics,
        "plan_sha256": pilot_plan_sha256(plan),
        "report_sha256": "0" * 64,
    }
    data["report_sha256"] = pilot_report_sha256(data)
    return PilotReadinessReport.model_validate(data)
