"""Provider-neutral hierarchy for safe persisted conversation activity.

This module never creates operational steps. It only groups already-persisted,
redacted activity events into a stable tree for presentation. Provider attempts,
hidden model reasoning, raw stdout, and secrets are deliberately absent.
"""

from __future__ import annotations

from collections import OrderedDict
from typing import Any

ActivityStatus = str

_TERMINAL_RUN_STATES = frozenset(
    {"completed", "failed", "stopped", "cancelled", "blocked", "timed_out"}
)

_EVENT_STATUS: dict[str, ActivityStatus] = {
    "run_created": "completed",
    "planning_started": "running",
    "plan_proposed": "completed",
    "authorization_check_started": "running",
    "authorization_check_passed": "completed",
    "authorization_check_failed": "failed",
    "scope_check_started": "running",
    "scope_check_passed": "completed",
    "scope_check_failed": "failed",
    "policy_check_started": "running",
    "policy_allowed": "completed",
    "policy_denied": "blocked",
    "repository_inspection_started": "running",
    "repository_inspection_completed": "completed",
    "repository_inspection_failed": "failed",
    "approval_requested": "queued",
    "approval_granted": "completed",
    "approval_rejected": "blocked",
    "tool_execution_started": "running",
    "tool_progress": "running",
    "tool_execution_completed": "completed",
    "tool_execution_failed": "failed",
    "evaluation_started": "running",
    "evaluation_completed": "completed",
    "retry_scheduled": "queued",
    "run_paused": "blocked",
    "run_resumed": "running",
    "stop_requested": "blocked",
    "run_stopped": "blocked",
    "run_blocked": "blocked",
    "run_failed": "failed",
    "run_completed": "completed",
}

_EVENT_PARENT: dict[str, tuple[str, str]] = {
    "authorization_check_started": ("authorization", "Authorization and scope"),
    "authorization_check_passed": ("authorization", "Authorization and scope"),
    "authorization_check_failed": ("authorization", "Authorization and scope"),
    "scope_check_started": ("authorization", "Authorization and scope"),
    "scope_check_passed": ("authorization", "Authorization and scope"),
    "scope_check_failed": ("authorization", "Authorization and scope"),
    "policy_check_started": ("authorization", "Authorization and scope"),
    "policy_allowed": ("authorization", "Authorization and scope"),
    "policy_denied": ("authorization", "Authorization and scope"),
    "repository_inspection_started": ("inspection", "Repository and file inspection"),
    "repository_inspection_completed": ("inspection", "Repository and file inspection"),
    "repository_inspection_failed": ("inspection", "Repository and file inspection"),
    "planning_started": ("planning", "Planning"),
    "plan_proposed": ("planning", "Planning"),
    "approval_requested": ("planning", "Planning"),
    "approval_granted": ("planning", "Planning"),
    "approval_rejected": ("planning", "Planning"),
    "tool_execution_started": ("tools", "Tool execution"),
    "tool_progress": ("tools", "Tool execution"),
    "tool_execution_completed": ("tools", "Tool execution"),
    "tool_execution_failed": ("tools", "Tool execution"),
    "evaluation_started": ("validation", "Evidence correlation and candidate validation"),
    "evaluation_completed": ("validation", "Evidence correlation and candidate validation"),
    "retry_scheduled": ("tools", "Tool execution"),
    "run_paused": ("completion", "Completion and blockers"),
    "run_resumed": ("completion", "Completion and blockers"),
    "stop_requested": ("completion", "Completion and blockers"),
    "run_stopped": ("completion", "Completion and blockers"),
    "run_blocked": ("completion", "Completion and blockers"),
    "run_failed": ("completion", "Completion and blockers"),
    "run_completed": ("completion", "Completion and blockers"),
}

_PARENT_ORDER = ("authorization", "inspection", "planning", "tools", "validation", "completion")


def _text(value: object) -> str:
    return str(value or "").strip()


def _event_type(event: object) -> str:
    if not isinstance(event, dict):
        return ""
    return _text(event.get("event_type") or event.get("type")).casefold()


def _status_for_event(event: dict[str, Any]) -> ActivityStatus:
    event_type = _event_type(event)
    explicit = _text(event.get("activity_status") or event.get("status")).casefold()
    if explicit in {"queued", "running", "completed", "blocked", "failed"}:
        return explicit
    return _EVENT_STATUS.get(event_type, "running")


def _parent_status(children: list[dict[str, Any]]) -> ActivityStatus:
    statuses = [str(child.get("status") or "running") for child in children]
    if any(status == "failed" for status in statuses):
        return "failed"
    if any(status == "blocked" for status in statuses):
        return "blocked"
    # Events are an immutable transition history. The latest persisted transition
    # represents the current stage state; earlier `started` events do not keep a
    # completed stage looking active.
    latest = statuses[-1] if statuses else "running"
    if latest in {"queued", "running", "completed"}:
        return latest
    return "running"


def _parent_summary(parent_key: str, status: ActivityStatus) -> str:
    if parent_key == "inspection" and status == "completed":
        return "The configured repository and scanner compatibility manifests were verified."
    if parent_key == "inspection" and status == "failed":
        return "Repository and scanner compatibility verification failed closed."
    if parent_key == "inspection" and status == "running":
        return "The configured repository and scanner compatibility manifests are being verified."
    if status == "completed":
        return "Persisted operational events for this stage are complete."
    if status == "blocked":
        return "This stage is blocked by a recorded governance or runtime boundary."
    if status == "failed":
        return "This stage contains a recorded failure."
    if status == "queued":
        return "This stage is queued; no completion is claimed yet."
    if parent_key == "validation":
        return "Persisted evidence-correlation or candidate-validation work is in progress."
    return "Persisted operational work for this stage is in progress."


def build_activity_tree(
    events: list[object] | tuple[object, ...],
    *,
    task_id: str,
    run_state: str | None = None,
    last_sequence: int = 0,
) -> dict[str, object]:
    """Build a safe hierarchical projection from genuine public events only.

    The function is intentionally a pure projection. If a tool, file inspection,
    evidence receipt, or validation event was not persisted by the backend, no node
    for it is emitted.
    """

    grouped: OrderedDict[str, list[dict[str, Any]]] = OrderedDict(
        (key, []) for key in _PARENT_ORDER
    )
    for raw_event in events:
        if not isinstance(raw_event, dict):
            continue
        event_type = _event_type(raw_event)
        parent_key, parent_label = _EVENT_PARENT.get(
            event_type,
            ("completion", "Completion and blockers"),
        )
        event_id = _text(raw_event.get("event_id")) or f"sequence-{raw_event.get('sequence', 0)}"
        summary = _text(raw_event.get("summary") or raw_event.get("message"))
        if not summary:
            continue
        status = _status_for_event(raw_event)
        child: dict[str, Any] = {
            "activity_id": f"{task_id}:event:{event_id}",
            "parent_activity_id": f"{task_id}:stage:{parent_key}",
            "label": summary,
            "status": status,
            "summary": summary,
            "event_type": event_type or "recorded_activity",
            "source": _text(raw_event.get("source")) or "system",
            "sequence": int(raw_event.get("sequence") or 0),
            "timestamp": _text(raw_event.get("timestamp") or raw_event.get("created_at")),
        }
        tool_id = _text(raw_event.get("tool_id"))
        if tool_id:
            child["tool_id"] = tool_id
        error_message = _text(raw_event.get("error_message"))
        if error_message:
            child["detail"] = error_message
        grouped[parent_key].append(child)

    stages: list[dict[str, Any]] = []
    for parent_key in _PARENT_ORDER:
        children = grouped[parent_key]
        if not children:
            continue
        parent_label = next(label for key, label in _EVENT_PARENT.values() if key == parent_key)
        status = _parent_status(children)
        completed = sum(child["status"] == "completed" for child in children)
        stages.append(
            {
                "activity_id": f"{task_id}:stage:{parent_key}",
                "parent_activity_id": None,
                "label": parent_label,
                "status": status,
                "summary": _parent_summary(parent_key, status),
                "children": children,
                "completed_count": completed,
                "total_count": len(children),
            }
        )

    normalized_run_state = _text(run_state) or None
    root_status: ActivityStatus = "running"
    if normalized_run_state in _TERMINAL_RUN_STATES:
        root_status = (
            "completed"
            if normalized_run_state == "completed"
            else "failed"
            if normalized_run_state in {"failed", "timed_out"}
            else "blocked"
        )
    elif normalized_run_state in {"created", "awaiting_approval", "queued"}:
        root_status = "queued"
    elif stages:
        root_status = "running"
    return {
        "schema_version": "1.0",
        "task_id": task_id,
        "status": root_status,
        "last_sequence": max(0, int(last_sequence)),
        "nodes": stages,
    }
