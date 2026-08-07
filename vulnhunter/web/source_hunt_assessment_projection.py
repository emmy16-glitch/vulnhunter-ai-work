"""Authoritative browser projection for one selected Source Hunt assessment."""

from __future__ import annotations

from collections.abc import Mapping

from vulnhunter.web.workflow_projection_contract import finalize_workflow_projection

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
_FAILURE = frozenset({"blocked", "failed", "gated", "rejected", "unavailable"})
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


def _current_stage(stages: tuple[dict[str, object], ...]) -> dict[str, object] | None:
    for item in stages:
        status = _text(item.get("status"))
        if status in {"active", "blocked", "failed", "queued", "running"}:
            return {"stage": _text(item.get("stage")), "status": status}
    for item in stages:
        status = _text(item.get("status"))
        if status not in {"completed", "skipped"}:
            return {"stage": _text(item.get("stage")), "status": status or "pending"}
    if stages:
        return {
            "stage": _text(stages[-1].get("stage")),
            "status": _text(stages[-1].get("status")) or "completed",
        }
    return None


def _health(state: str) -> dict[str, str]:
    if state in _ACTIVE:
        worker = "active"
        assessment = "in_progress"
    elif state in _FAILURE:
        worker = "unavailable" if state == "unavailable" else "blocked"
        assessment = "attention_required"
    elif state == "completed":
        worker = "available"
        assessment = "completed"
    elif state == "cancelled":
        worker = "available"
        assessment = "cancelled"
    else:
        worker = "available"
        assessment = "prepared"
    return {
        "assessment": assessment,
        "worker": worker,
        "provider": "not_evaluated",
    }


def source_hunt_assessment_projection(
    plan: Mapping[str, object] | None,
) -> dict[str, object] | None:
    """Project one persisted Source Hunt plan across every assessment surface."""

    if plan is None:
        return None
    graph = _map(plan.get("assessment_graph"))
    repository = _map(plan.get("repository"))
    approval = _map(plan.get("approval"))
    execution = _map(plan.get("execution"))
    report = _map(plan.get("report"))
    assessment_id = _text(plan.get("run_id") or plan.get("job_id"))
    graph_id = _text(graph.get("graph_id") or plan.get("task_graph_id"))
    repository_id = _text(repository.get("repository_id"))
    revision = _text(repository.get("revision"))
    snapshot_sha256 = _text(repository.get("snapshot_sha256"))
    if not all((assessment_id, graph_id, repository_id, revision, snapshot_sha256)):
        return None
    if _integer(graph.get("revision")) is None:
        return None

    stages = _rows(graph.get("nodes"))
    state = _text(execution.get("state")) or "prepared"
    candidate_count = _integer(report.get("candidate_count")) or 0
    rejected_count = _integer(report.get("rejected_count")) or 0
    abstained_count = _integer(report.get("abstained_count")) or 0
    surfaces_examined = _integer(report.get("surfaces_examined")) or 0
    report_status = _text(report.get("stage")) or "pending"
    report_ready = state == "completed" and bool(_text(report.get("report_id")))
    completed_stages = sum(_text(item.get("status")) in {"completed", "skipped"} for item in stages)
    safe_error = _text(execution.get("safe_error") or report.get("safe_error"))
    latest_event = None
    completed_at = _text(execution.get("completed_at"))
    started_at = _text(execution.get("started_at"))
    created_at = _text(execution.get("created_at"))
    if completed_at:
        latest_event = {"stage": "source_hunt", "status": state, "at": completed_at}
    elif started_at:
        latest_event = {"stage": "source_hunt", "status": state, "at": started_at}
    elif created_at:
        latest_event = {"stage": "source_hunt", "status": state, "at": created_at}

    allowed_actions = ["view_activity", "view_evidence", "view_findings"]
    if report_ready:
        allowed_actions.append("view_report")

    failure = (
        {
            "category": "source_hunt_failure",
            "stage": _text((_current_stage(stages) or {}).get("stage")),
            "reason_code": state,
            "message": safe_error,
            "safe_retry": False,
            "retry_scope": None,
            "preserved": [
                "repository_snapshot",
                "remote_processing_approval",
                "assessment_graph",
            ],
        }
        if state in _FAILURE
        else None
    )

    projection = {
        "assessment_id": assessment_id,
        "graph_id": graph_id,
        "workspace_id": _text(graph.get("workspace_id")),
        "assessment_kind": "source_hunt",
        "selected": True,
        "surface_identity": {surface: assessment_id for surface in _SURFACES},
        "subject": {
            "kind": "repository_snapshot",
            "label": f"{repository_id}@{revision}",
            "repository_id": repository_id,
            "revision": revision,
            "sha256": snapshot_sha256,
            "visibility": _text(repository.get("visibility")),
            "permitted_paths": [
                value for item in repository.get("permitted_paths", []) if (value := _text(item))
            ]
            if isinstance(repository.get("permitted_paths"), list)
            else [],
        },
        "authority": {
            "authorization_id": _text(approval.get("approval_id")),
            "approval_sha256": _text(approval.get("approval_sha256")),
            "expires_at": _text(approval.get("expires_at")),
        },
        "lifecycle": _text(graph.get("chat_stage")) or "understanding_request",
        "health": _health(state),
        "execution": {
            "state": state,
            "terminal": state in _TERMINAL,
            "reason": safe_error,
            "job_id": assessment_id,
            "failure": failure,
        },
        "stages": list(stages),
        "stage_summary": {
            "total": len(stages),
            "completed": completed_stages,
            "blocked": sum(
                _text(item.get("status")) in {"blocked", "failed", "rejected"} for item in stages
            ),
        },
        "task_card": {
            "task_id": f"{assessment_id}:source-hunt",
            "assessment_id": assessment_id,
            "state": state,
            "terminal": state in _TERMINAL,
            "current_stage": _current_stage(stages),
            "stage_progress": {"completed": completed_stages, "total": len(stages)},
            "byte_progress": {
                "received": _integer(repository.get("total_bytes")),
                "expected": _integer(repository.get("total_bytes")),
            },
            "activity": {
                "event_count": 1 if latest_event else 0,
                "receipt_count": surfaces_examined,
                "candidate_count": candidate_count,
                "latest_event": latest_event,
            },
            "failure": failure,
            "retry": {"available": False, "scope": None, "user_action": None},
        },
        "activity": {
            "event_count": 1 if latest_event else 0,
            "tool_receipt_count": surfaces_examined,
            "active_tool": None,
        },
        "evidence": {"record_count": surfaces_examined},
        "findings": {
            "candidate_count": candidate_count,
            "rejected_count": rejected_count,
            "abstained_count": abstained_count,
        },
        "report": {
            "status": report_status,
            "ready": report_ready,
            "report_id": _text(report.get("report_id")),
        },
        "allowed_actions": allowed_actions,
    }
    projection = finalize_workflow_projection(
        projection,
        graph=graph,
        raw_state=state,
        assessment_kind="source_hunt",
    )
    assert_source_hunt_projection_invariants(projection)
    return projection


def assert_source_hunt_projection_invariants(projection: Mapping[str, object]) -> None:
    assessment_id = _text(projection.get("assessment_id"))
    graph_id = _text(projection.get("graph_id"))
    surfaces = _map(projection.get("surface_identity"))
    subject = _map(projection.get("subject"))
    task_card = _map(projection.get("task_card"))
    report = _map(projection.get("report"))
    if not assessment_id or not graph_id:
        raise ValueError("A Source Hunt projection requires assessment and graph identifiers.")
    if projection.get("selected") is not True:
        raise ValueError("A Source Hunt projection must identify the selected assessment.")
    if set(surfaces) != set(_SURFACES) or any(
        _text(surfaces.get(surface)) != assessment_id for surface in _SURFACES
    ):
        raise ValueError("Every Source Hunt surface must bind to one selected assessment.")
    if not all(
        _text(subject.get(field)) for field in ("repository_id", "revision", "sha256", "label")
    ):
        raise ValueError("Source Hunt requires one exact repository snapshot identity.")
    if _text(task_card.get("assessment_id")) != assessment_id:
        raise ValueError("The Source Hunt task card must bind to the selected assessment.")
    if report.get("ready") is True and not _text(report.get("report_id")):
        raise ValueError("A ready Source Hunt report requires a persisted report identity.")
    retry = _map(task_card.get("retry"))
    if retry.get("available") is True or _text(retry.get("scope")):
        raise ValueError("Source Hunt must not invent retry authority.")


__all__ = [
    "assert_source_hunt_projection_invariants",
    "source_hunt_assessment_projection",
]
