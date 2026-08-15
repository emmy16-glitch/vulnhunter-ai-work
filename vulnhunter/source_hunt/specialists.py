"""Deterministic specialist assignment for Source Hunt Intelligence V2."""

from __future__ import annotations

from vulnhunter.source_hunt.intelligence_models import HunterRole, SpecialistAssignment
from vulnhunter.source_hunt.models import AttackSurface

_SPECIALIST_TASKS: dict[HunterRole, str] = {
    HunterRole.INJECTION: (
        "Focus on attacker-controlled data crossing interpreter, query, template, shell, "
        "or dynamic-code boundaries. Reject findings based only on suspicious syntax."
    ),
    HunterRole.ACCESS_CONTROL: (
        "Focus on missing or misplaced authorization, ownership, privilege, and tenant "
        "controls along only the supplied path."
    ),
    HunterRole.NAVIGATION: (
        "Focus on path traversal, filesystem selection, canonicalization, and boundary escape."
    ),
    HunterRole.NETWORK_BOUNDARY: (
        "Focus on attacker influence over server-side destinations without executing requests."
    ),
    HunterRole.DESERIALIZATION: (
        "Focus on attacker-controlled material reaching unsafe deserializers with a concrete "
        "capability gain."
    ),
    HunterRole.BUSINESS_LOGIC: (
        "Focus on concrete authorization or state-boundary breaks visible in supplied facts."
    ),
    HunterRole.CRYPTOGRAPHY: (
        "Focus on concrete security-boundary misuse of cryptographic operations in supplied facts."
    ),
    HunterRole.SINK_BACKSTOP: (
        "Act as an independent sink-driven backstop; use a different interpretation and abstain "
        "when evidence is insufficient."
    ),
}

_SINK_ROLE: dict[str, HunterRole] = {
    "command_execution": HunterRole.INJECTION,
    "subprocess_execution": HunterRole.INJECTION,
    "dynamic_code_execution": HunterRole.INJECTION,
    "database_query": HunterRole.INJECTION,
    "template_injection": HunterRole.INJECTION,
    "html_injection": HunterRole.INJECTION,
    "filesystem_access": HunterRole.NAVIGATION,
    "filesystem_write": HunterRole.NAVIGATION,
    "filesystem_delete": HunterRole.NAVIGATION,
    "outbound_request": HunterRole.NETWORK_BOUNDARY,
    "unsafe_deserialization": HunterRole.DESERIALIZATION,
}


def specialist_focus(role: HunterRole) -> str:
    return _SPECIALIST_TASKS[role]


class SpecialistPlanner:
    @staticmethod
    def assign(surface: AttackSurface) -> SpecialistAssignment:
        sink_kind = surface.sink_kinds[0] if surface.sink_kinds else "unknown"
        primary = _SINK_ROLE.get(sink_kind, HunterRole.SINK_BACKSTOP)
        roles: list[HunterRole] = [primary]
        if surface.guards and primary != HunterRole.ACCESS_CONTROL:
            roles.append(HunterRole.ACCESS_CONTROL)
        if HunterRole.SINK_BACKSTOP not in roles:
            roles.append(HunterRole.SINK_BACKSTOP)
        return SpecialistAssignment(
            surface_id=surface.surface_id,
            primary_role=primary,
            independent_roles=tuple(roles[:2]),
            reason=(
                f"sink={sink_kind}; guards={len(surface.guards)}; bounded independent passes "
                "share source facts but never conclusions"
            ),
        )
