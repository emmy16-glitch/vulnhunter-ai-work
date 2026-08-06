"""Cross-workflow contract for the one selected browser assessment.

The workflow-specific projection builders remain responsible for deriving truth from
persisted APK, website, or Source Hunt state. This module owns the common boundary
consumed by browser surfaces so clients do not branch into competing lifecycle
stores.
"""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy

_SUPPORTED_KINDS = frozenset({"apk", "source_hunt", "website"})
_REQUIRED_SURFACES = frozenset(
    {
        "activity",
        "chat",
        "evidence",
        "findings",
        "graph",
        "history",
        "inspector",
        "reports",
    }
)
_REQUIRED_RESULT_SURFACES = frozenset({"evidence", "findings", "graph", "reports"})


def _map(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _text(value: object) -> str | None:
    text = str(value or "").strip()
    return text or None


def _revision(projection: Mapping[str, object]) -> int:
    revision = projection.get("projection_revision")
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
        raise ValueError("Selected assessment state requires a non-negative projection revision.")
    return revision


def _payload_without_contract(projection: Mapping[str, object]) -> dict[str, object]:
    payload = deepcopy(dict(projection))
    payload.pop("projection_contract", None)
    return payload


def assert_selected_assessment_invariants(projection: Mapping[str, object]) -> None:
    """Reject contradictory or incomplete cross-workflow assessment state."""

    assessment_id = _text(projection.get("assessment_id"))
    assessment_kind = _text(projection.get("assessment_kind"))
    graph_id = _text(projection.get("graph_id"))
    surfaces = _map(projection.get("surface_identity"))
    result_identity = _map(projection.get("result_identity"))
    task_card = _map(projection.get("task_card"))
    health = _map(projection.get("health"))
    execution = _map(projection.get("execution"))

    if assessment_id is None or graph_id is None:
        raise ValueError("Selected assessment state requires assessment and graph identifiers.")
    if assessment_kind not in _SUPPORTED_KINDS:
        raise ValueError("Selected assessment state uses an unsupported assessment kind.")
    if projection.get("selected") is not True:
        raise ValueError("Selected assessment state must identify the current assessment.")
    _revision(projection)
    if set(surfaces) != _REQUIRED_SURFACES or any(
        _text(surfaces.get(surface)) != assessment_id for surface in _REQUIRED_SURFACES
    ):
        raise ValueError("Every browser surface must bind to the selected assessment.")
    if set(result_identity) != _REQUIRED_RESULT_SURFACES or any(
        _text(result_identity.get(surface)) != assessment_id
        for surface in _REQUIRED_RESULT_SURFACES
    ):
        raise ValueError("Every result projection must bind to the selected assessment.")
    if _text(task_card.get("assessment_id")) != assessment_id:
        raise ValueError("The persisted task card must bind to the selected assessment.")
    if _text(execution.get("state")) is None:
        raise ValueError("Selected assessment state requires an execution state.")
    for dimension in ("assessment", "provider", "worker"):
        if _text(health.get(dimension)) is None:
            raise ValueError("Assessment, provider, and worker health must remain separate.")


def selected_assessment_projection(
    projection: Mapping[str, object] | None,
) -> dict[str, object] | None:
    """Return a defensive, workflow-neutral selected-assessment snapshot."""

    if projection is None:
        return None
    assert_selected_assessment_invariants(projection)
    result = deepcopy(dict(projection))
    result["projection_contract"] = "selected-assessment/v1"
    return result


def replace_selected_assessment(
    current: Mapping[str, object] | None,
    incoming: Mapping[str, object] | None,
) -> dict[str, object] | None:
    """Atomically replace browser state with one authoritative server snapshot.

    Missing incoming state clears the selection. A different assessment replaces the
    old snapshot completely. For the same assessment, projection revisions are
    monotonic so a delayed poll, reconnect response, or timeout-after-success replay
    cannot roll the browser back to older lifecycle or result state.
    """

    replacement = selected_assessment_projection(incoming)
    if replacement is None or current is None:
        return replacement

    existing = selected_assessment_projection(current)
    assert existing is not None
    if _text(existing.get("assessment_id")) != _text(replacement.get("assessment_id")):
        return replacement

    current_revision = _revision(existing)
    incoming_revision = _revision(replacement)
    if incoming_revision < current_revision:
        return existing
    if incoming_revision == current_revision:
        if _payload_without_contract(existing) != _payload_without_contract(replacement):
            raise ValueError(
                "The same selected-assessment revision cannot describe different state."
            )
        return existing
    return replacement


__all__ = [
    "assert_selected_assessment_invariants",
    "replace_selected_assessment",
    "selected_assessment_projection",
]
