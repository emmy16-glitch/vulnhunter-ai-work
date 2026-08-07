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
_ACTIVE_STATES = frozenset({"prepared", "queued", "claimed", "running", "cancelling"})
_FAILURE_STATES = frozenset({"blocked", "failed", "gated", "rejected"})
_TERMINAL_STATES = _FAILURE_STATES | {"completed", "cancelled"}
_SUPPORTED_EXECUTION_STATES = _ACTIVE_STATES | _TERMINAL_STATES
_STATE_ALIASES = {
    "created": "prepared",
    "pending": "prepared",
    "executing": "running",
    "evaluating": "running",
    "execution_blocked": "blocked",
    "readiness_blocked": "blocked",
    "unavailable": "blocked",
    "timed_out": "failed",
    "denied": "rejected",
}
_EXPECTED_ASSESSMENT_HEALTH = {
    "completed": "completed",
    "cancelled": "cancelled",
    **{state: "attention_required" for state in _FAILURE_STATES},
    **{state: "in_progress" for state in _ACTIVE_STATES},
}
_PROGRESS_MEASUREMENTS = frozenset({"none", "bytes", "stage"})


def _map(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _text(value: object) -> str | None:
    text = str(value or "").strip()
    return text or None


def _non_negative_integer(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def canonical_execution_state(value: object) -> str:
    """Translate persisted workflow-specific labels into one product lifecycle state.

    The alias table is deliberately small and explicit. Unknown values fail closed so
    a new worker or queue state cannot silently become browser-owned lifecycle truth.
    """

    state = (_text(value) or "").casefold()
    state = _STATE_ALIASES.get(state, state)
    if state not in _SUPPORTED_EXECUTION_STATES:
        raise ValueError("Selected assessment state requires one supported execution state.")
    return state


def _revision(projection: Mapping[str, object]) -> int:
    revision = projection.get("projection_revision")
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
        raise ValueError("Selected assessment state requires a non-negative projection revision.")
    return revision


def _assert_measured_progress(task_card: Mapping[str, object]) -> None:
    """Require persisted byte/stage measurements and reject invented percentages."""

    if _text(task_card.get("activity_timeline_id")) is None:
        raise ValueError("The persisted task card requires one durable activity timeline.")
    progress = _map(task_card.get("progress"))
    measurement = _text(progress.get("measurement"))
    if measurement not in _PROGRESS_MEASUREMENTS:
        raise ValueError("Task progress must use none, byte, or stage measurement.")
    if "percent" in progress or "percentage" in progress:
        raise ValueError("Task progress cannot contain fabricated percentage values.")
    if measurement == "none":
        if set(progress) != {"measurement"}:
            raise ValueError("Unmeasured task progress cannot claim byte or stage completion.")
        return

    completed = _non_negative_integer(progress.get("completed"))
    total = _non_negative_integer(progress.get("total"))
    if completed is None or total is None or total == 0 or completed > total:
        raise ValueError(
            "Measured task progress requires bounded persisted completed and total values."
        )
    required = {"measurement", "completed", "total"}
    if measurement == "stage":
        required.add("stage")
        if _text(progress.get("stage")) is None:
            raise ValueError("Stage progress requires the current persisted stage name.")
    if set(progress) != required:
        raise ValueError("Task progress may expose only its canonical measured fields.")


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
    execution_state = _text(execution.get("state"))

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
    _assert_measured_progress(task_card)
    if execution_state not in _SUPPORTED_EXECUTION_STATES:
        raise ValueError("Selected assessment state requires one supported execution state.")
    if _text(task_card.get("state")) != execution_state:
        raise ValueError("The persisted task card must agree with the execution state.")
    if task_card.get("terminal") is not (execution_state in _TERMINAL_STATES):
        raise ValueError("The persisted task card terminal flag must agree with execution state.")
    for dimension in ("assessment", "provider", "worker"):
        if _text(health.get(dimension)) is None:
            raise ValueError("Assessment, provider, and worker health must remain separate.")
    if _text(health.get("assessment")) != _EXPECTED_ASSESSMENT_HEALTH[execution_state]:
        raise ValueError("Assessment health must agree with the authoritative execution state.")


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
    "canonical_execution_state",
    "replace_selected_assessment",
    "selected_assessment_projection",
]
