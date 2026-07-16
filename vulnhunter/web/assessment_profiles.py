"""Presentation metadata for governed assessment launch choices.

These rows describe user-facing workflow choices only. Selecting a row creates a
bounded launch request; it never enables a scanner or bypasses runtime policy.
"""

from __future__ import annotations

from vulnhunter.advanced import AssessmentProfile

_ASSESSMENT_PROFILES: tuple[dict[str, str], ...] = (
    {
        "id": AssessmentProfile.DEEP_DISCOVERY.value,
        "name": "Deep Discovery",
        "description": "Authorised attack-surface and service mapping.",
        "gate": "Active authorization and network-discovery approval.",
        "risk": "Moderate",
    },
    {
        "id": AssessmentProfile.ACTIVE_ASSESSMENT.value,
        "name": "Active Assessment",
        "description": "Bounded web, TLS and vulnerability assessment.",
        "gate": "Separate active-testing approval and reviewed tool profile.",
        "risk": "High",
    },
    {
        "id": AssessmentProfile.EXPLOITABILITY_VALIDATION.value,
        "name": "Exploitability Validation",
        "description": "Minimum-impact validation of selected candidates.",
        "gate": "Exact-action approval and one-time consumption.",
        "risk": "Critical",
    },
    {
        "id": AssessmentProfile.PRIVILEGED_ENVIRONMENT.value,
        "name": "Privileged Environment",
        "description": "Short-lived brokered inspection without stored credentials.",
        "gate": "Owner reauthentication and an isolated privilege grant.",
        "risk": "Critical",
    },
    {
        "id": AssessmentProfile.ATTACK_PATH_SIMULATION.value,
        "name": "Attack-Path Simulation",
        "description": "Correlate authorised multi-stage attack paths.",
        "gate": "Stage-by-stage approval and evidence-backed edges.",
        "risk": "High",
    },
    {
        "id": AssessmentProfile.REMEDIATION_RETEST.value,
        "name": "Remediation Retest",
        "description": "Repeat only checks required to verify a fix.",
        "gate": "Exact retest scope and approved prior finding references.",
        "risk": "Moderate",
    },
)


def assessment_profiles() -> tuple[dict[str, str], ...]:
    """Return immutable copies suitable for forms and templates."""

    return tuple(dict(item) for item in _ASSESSMENT_PROFILES)


def assessment_profile(profile_id: str) -> dict[str, str]:
    """Resolve one known profile or raise a fail-closed validation error."""

    for item in _ASSESSMENT_PROFILES:
        if item["id"] == profile_id:
            return dict(item)
    raise ValueError("Unknown governed assessment profile.")
