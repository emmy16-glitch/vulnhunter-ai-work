"""Authoritative browser projection for one selected mobile assessment."""

from __future__ import annotations

from collections.abc import Mapping

_SURFACES = (
    "chat",
    "activity",
    "inspector",
    "history",
    "findings",
    "evidence",
    "graph",
    "reports",
)
_ACTIVE = frozenset({"queued", "claimed", "running", "cancelling"})
_FAILURE = frozenset({"blocked", "failed", "gated", "rejected"})
_TERMINAL = _FAILURE | {"completed", "cancelled"}


def _map(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _text(value: object) -> str | None:
    text = str(value or "").strip()
    return text or None


def _integer(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None


def _rows(value: object) -> tuple[dict[str, object], ...]:
    if not isinstance(value, list):
        return ()
    return tuple(dict(item) for item in value if isinstance(item, Mapping))


def _stage(stages: tuple[dict[str, object], ...], name: str) -> str | None:
    for item in stages:
        if item.get("stage") == name:
            return _text(item.get("status"))
    return None


def _failure(execution: Mapping[str, object]) -> dict[str, object] | None:
    raw = _map(execution.get("failure"))
    if not raw:
        return None
    preserved = raw.get("preserved") if isinstance(raw.get("preserved"), list) else []
    return {
        "category": _text(raw.get("category")),
        "stage": _text(raw.get("stage")),
        "reason_code": _text(raw.get("reason_code")),
        "reference": _text(raw.get("reference")),
        "message": _text(raw.get("message")),
        "user_action": _text(raw.get("user_action")),
        "operator_action": _text(raw.get("operator_action")),
        "safe_retry": raw.get("safe_retry") is True,
        "retry_scope": _text(raw.get("retry_scope")),
        "preserved": [text for item in preserved if (text := _text(item))],
    }


def _health(state: str, failure: Mapping[str, object] | None) -> dict[str, str]:
    if state in _ACTIVE:
        worker = "active"
    elif state in _FAILURE:
        category = _text((failure or {}).get("category"))
        worker = (
            "unavailable"
            if category
            in {
                "dependency_unavailable",
                "storage_failure",
                "tool_failure",
                "tool_missing",
                "tool_timeout",
                "worker_lost",
                "worker_unavailable",
            }
            else "blocked"
        )
    else:
        worker = "available"
    assessment = "in_progress"
    if state == "completed":
        assessment = "completed"
    elif state in _FAILURE:
        assessment = "attention_required"
    elif state == "cancelled":
        assessment = "cancelled"
    return {
        "assessment": assessment,
        "worker": worker,
        "provider": "not_evaluated",
    }


def _actions(
    state: str,
    report_ready: bool,
    failure: Mapping[str, object] | None,
) -> list[str]:
    actions = ["view_activity", "view_evidence", "view_findings"]
    if state in _ACTIVE:
        actions.append("request_cancel")
    if (
        state in _FAILURE
        and failure
        and failure.get("safe_retry") is True
        and _text(failure.get("retry_scope"))
    ):
        actions.append("request_retry")
    if report_ready:
        actions.append("view_report")
    return actions


def _current_stage(stages: tuple[dict[str, object], ...]) -> dict[str, object] | None:
    for item in stages:
        status = _text(item.get("status"))
        if status in {"active", "blocked", "failed", "queued", "running"}:
            return {
                "stage": _text(item.get("stage")),
                "status": status,
            }
    for item in stages:
        if _text(item.get("status")) not in {"completed", "skipped"}:
            return {
                "stage": _text(item.get("stage")),
                "status": _text(item.get("status")) or "pending",
            }
    if stages:
        return {
            "stage": _text(stages[-1].get("stage")),
            "status": _text(stages[-1].get("status")) or "completed",
        }
    return None


def _task_card(
    *,
    assessment_id: str,
    state: str,
    stages: tuple[dict[str, object], ...],
    progress: Mapping[str, object],
    events: tuple[dict[str, object], ...],
    captures: tuple[dict[str, object], ...],
    observations: tuple[dict[str, object], ...],
    failure: Mapping[str, object] | None,
) -> dict[str, object]:
    received_bytes = _integer(progress.get("received_bytes"))
    expected_bytes = _integer(progress.get("expected_bytes"))
    if expected_bytes is not None and received_bytes is not None:
        received_bytes = min(received_bytes, expected_bytes)
    completed_stages = sum(
        _text(item.get("status")) in {"completed", "skipped"} for item in stages
    )
    return {
        "task_id": f"{assessment_id}:mobile-assessment",
        "assessment_id": assessment_id,
        "state": state,
        "terminal": state in _TERMINAL,
        "current_stage": _current_stage(stages),
        "stage_progress": {
            "completed": completed_stages,
            "total": len(stages),
        },
        "byte_progress": {
            "received": received_bytes,
            "expected": expected_bytes,
        },
        "activity": {
            "event_count": len(events),
            "receipt_count": len(captures),
            "candidate_count": len(observations),
            "latest_event": dict(events[-1]) if events else None,
        },
        "failure": dict(failure) if failure else None,
    }


def mobile_assessment_projection(
    plan: Mapping[str, object] | None,
) -> dict[str, object] | None:
    if plan is None:
        return None
    graph = _map(plan.get("assessment_graph"))
    assessment_id = _text(plan.get("run_id"))
    graph_id = _text(graph.get("graph_id"))
    if assessment_id is None or graph_id is None:
        return None

    artifact = _map(plan.get("artifact"))
    execution = _map(plan.get("execution"))
    progress = _map(execution.get("progress"))
    receipt = _map(execution.get("receipt"))
    result_summary = _map(progress.get("result_summary"))
    hunt = _map(result_summary.get("hunt"))
    stages = _rows(graph.get("nodes"))
    captures = _rows(receipt.get("captures")) or _rows(result_summary.get("captures"))
    observations = _rows(receipt.get("candidate_observations")) or _rows(hunt.get("candidates"))
    events = _rows(progress.get("events"))
    state = _text(execution.get("state")) or "prepared"
    failure = _failure(execution)
    report_status = _stage(stages, "report") or "pending"
    report_ready = report_status in {"ready", "completed"}
    label = (
        _text(artifact.get("original_filename"))
        or _text(artifact.get("artifact_id"))
        or "Android APK"
    )

    projection = {
        "assessment_id": assessment_id,
        "graph_id": graph_id,
        "workspace_id": _text(graph.get("workspace_id")),
        "assessment_kind": _text(graph.get("assessment_kind")) or "apk",
        "selected": True,
        "surface_identity": {surface: assessment_id for surface in _SURFACES},
        "subject": {
            "kind": "artifact",
            "label": label,
            "artifact_id": _text(artifact.get("artifact_id")),
            "sha256": _text(artifact.get("artifact_sha256")),
        },
        "authority": {
            "authorization_id": _text(graph.get("authorization_id")),
            "plan_digest": _text(plan.get("plan_digest")),
            "profile": _text(plan.get("profile")),
            "approval_status": _stage(stages, "approval") or "pending",
        },
        "lifecycle": _text(graph.get("chat_stage")) or "understanding_request",
        "health": _health(state, failure),
        "execution": {
            "state": state,
            "reason": _text(execution.get("reason")),
            "job_id": _text(execution.get("job_id")),
            "terminal": state in _TERMINAL,
            "failure": failure,
        },
        "stages": list(stages),
        "stage_summary": {
            "total": len(stages),
            "completed": sum(_text(item.get("status")) == "completed" for item in stages),
            "blocked": sum(
                _text(item.get("status")) in {"blocked", "failed", "rejected"} for item in stages
            ),
        },
        "task_card": _task_card(
            assessment_id=assessment_id,
            state=state,
            stages=stages,
            progress=progress,
            events=events,
            captures=captures,
            observations=observations,
            failure=failure,
        ),
        "activity": {
            "event_count": len(events),
            "tool_receipt_count": len(captures),
            "active_tool": _text(progress.get("active_tool")),
        },
        "evidence": {"record_count": len(captures)},
        "findings": {"candidate_count": len(observations)},
        "report": {"status": report_status, "ready": report_ready},
        "allowed_actions": _actions(state, report_ready, failure),
    }
    assert_mobile_projection_invariants(projection)
    return projection


def assert_mobile_projection_invariants(projection: Mapping[str, object]) -> None:
    assessment_id = _text(projection.get("assessment_id"))
    graph_id = _text(projection.get("graph_id"))
    surfaces = _map(projection.get("surface_identity"))
    subject = _map(projection.get("subject"))
    execution = _map(projection.get("execution"))
    report = _map(projection.get("report"))
    task_card = _map(projection.get("task_card"))
    stage_progress = _map(task_card.get("stage_progress"))
    byte_progress = _map(task_card.get("byte_progress"))
    failure = _map(execution.get("failure"))
    actions = projection.get("allowed_actions")
    if assessment_id is None or graph_id is None:
        raise ValueError("An assessment projection requires assessment and graph identifiers.")
    if projection.get("selected") is not True:
        raise ValueError("An assessment projection must identify the selected assessment.")
    invalid_surfaces = set(surfaces) != set(_SURFACES) or any(
        _text(surfaces.get(name)) != assessment_id for name in _SURFACES
    )
    if invalid_surfaces:
        raise ValueError(
            "Every assessment surface must bind to the selected assessment identifier."
        )
    if _text(subject.get("label")) is None:
        raise ValueError("An assessment projection requires a selected subject.")
    if _text(execution.get("state")) is None:
        raise ValueError("An assessment projection requires an execution state.")
    if _text(task_card.get("assessment_id")) != assessment_id:
        raise ValueError("The task card must bind to the selected assessment identifier.")
    completed = _integer(stage_progress.get("completed"))
    total = _integer(stage_progress.get("total"))
    if completed is None or total is None or completed > total:
        raise ValueError("Task-card stage progress must come from persisted stages.")
    received = _integer(byte_progress.get("received"))
    expected = _integer(byte_progress.get("expected"))
    if received is not None and expected is not None and received > expected:
        raise ValueError("Task-card byte progress cannot exceed the declared byte total.")
    if report.get("ready") is True and _text(report.get("status")) not in {
        "ready",
        "completed",
    }:
        raise ValueError("Report readiness must agree with the persisted report stage.")
    if (
        isinstance(actions, list)
        and "request_retry" in actions
        and (failure.get("safe_retry") is not True or _text(failure.get("retry_scope")) is None)
    ):
        raise ValueError("Retry actions require an exact persisted safe-retry contract.")


__all__ = ["assert_mobile_projection_invariants", "mobile_assessment_projection"]
