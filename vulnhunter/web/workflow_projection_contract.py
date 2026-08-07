"""Finalize workflow-specific read models through one selected-assessment contract.

APK, website and Source Hunt builders may retain workflow-specific detail for their
specialist views, but identity, lifecycle, result ownership, revision and measured
progress must converge before the browser receives the projection.
"""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy

from vulnhunter.web.selected_assessment_projection import (
    canonical_execution_state,
    selected_assessment_projection,
)

_RESULT_SURFACES = ("evidence", "findings", "graph", "reports")
_TERMINAL_STATES = frozenset({"blocked", "failed", "gated", "rejected", "completed", "cancelled"})
_FAILURE_STATES = frozenset({"blocked", "failed", "gated", "rejected"})


def _map(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _text(value: object) -> str | None:
    text = str(value or "").strip()
    return text or None


def _non_negative_integer(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _graph_revision(graph: Mapping[str, object]) -> int:
    revision = _non_negative_integer(graph.get("revision"))
    if revision is None:
        raise ValueError("A workflow projection requires the persisted task-graph revision.")
    return revision


def _assessment_health(state: str) -> str:
    if state == "completed":
        return "completed"
    if state == "cancelled":
        return "cancelled"
    if state in _FAILURE_STATES:
        return "attention_required"
    return "in_progress"


def _stage_progress(task_card: Mapping[str, object], state: str) -> dict[str, object]:
    progress = _map(task_card.get("stage_progress"))
    completed = _non_negative_integer(progress.get("completed"))
    total = _non_negative_integer(progress.get("total"))
    if completed is None or total is None or total <= 0 or completed > total:
        raise ValueError("A live assessment task requires persisted bounded stage progress.")
    current = _map(task_card.get("current_stage"))
    stage = _text(current.get("stage")) or state
    return {
        "measurement": "stage",
        "completed": completed,
        "total": total,
        "stage": stage,
    }


def finalize_workflow_projection(
    projection: Mapping[str, object],
    *,
    graph: Mapping[str, object],
    raw_state: object,
    assessment_kind: str,
) -> dict[str, object]:
    """Return one defensive canonical projection backed by the persisted graph.

    The function intentionally rejects missing graph revision or stage measurements
    instead of fabricating browser progress. Workflow-specific fields are preserved
    as a backwards-compatible superset while every primary surface consumes the same
    selected-assessment identity and lifecycle contract.
    """

    result = deepcopy(dict(projection))
    assessment_id = _text(result.get("assessment_id"))
    graph_id = _text(result.get("graph_id"))
    if assessment_id is None or graph_id is None:
        raise ValueError("A workflow projection requires assessment and graph identifiers.")

    state = canonical_execution_state(raw_state)
    result["assessment_kind"] = assessment_kind
    result["projection_revision"] = _graph_revision(graph)
    result["result_identity"] = {surface: assessment_id for surface in _RESULT_SURFACES}

    execution = dict(_map(result.get("execution")))
    execution["state"] = state
    execution["terminal"] = state in _TERMINAL_STATES
    result["execution"] = execution

    task_card = dict(_map(result.get("task_card")))
    task_card["assessment_id"] = assessment_id
    task_card["activity_timeline_id"] = graph_id
    task_card["state"] = state
    task_card["terminal"] = state in _TERMINAL_STATES
    task_card["progress"] = _stage_progress(task_card, state)
    result["task_card"] = task_card

    health = dict(_map(result.get("health")))
    health["assessment"] = _assessment_health(state)
    health.setdefault("provider", "not_evaluated")
    health.setdefault("worker", "available")
    result["health"] = health

    selected = selected_assessment_projection(result)
    if selected is None:  # pragma: no cover - mapping input cannot produce None
        raise ValueError("The selected assessment projection could not be finalized.")
    return selected


__all__ = ["finalize_workflow_projection"]
