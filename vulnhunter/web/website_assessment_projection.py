"""Authoritative browser projection for one selected website assessment."""

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
_ACTIVE = frozenset({"queued", "running", "executing", "evaluating", "cancelling"})
_FAILURE = frozenset(
    {
        "blocked",
        "denied",
        "execution_blocked",
        "failed",
        "readiness_blocked",
        "timed_out",
    }
)
_TERMINAL = _FAILURE | {"completed", "cancelled"}


def _map(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _text(value: object) -> str | None:
    text = str(value or "").strip()
    return text or None


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
        return {
            "assessment": "in_progress",
            "worker": "active",
            "provider": "not_evaluated",
        }
    if state in _FAILURE:
        return {
            "assessment": "attention_required",
            "worker": "blocked",
            "provider": "not_evaluated",
        }
    if state == "completed":
        return {
            "assessment": "completed",
            "worker": "available",
            "provider": "not_evaluated",
        }
    if state == "cancelled":
        return {
            "assessment": "cancelled",
            "worker": "available",
            "provider": "not_evaluated",
        }
    return {
        "assessment": "prepared",
        "worker": "available",
        "provider": "not_evaluated",
    }


def website_assessment_projection(
    payload: Mapping[str, object] | None,
) -> dict[str, object] | None:
    """Project one governed website run across every assessment surface."""

    if payload is None:
        return None
    graph = _map(payload.get("task_graph"))
    assessment_id = _text(payload.get("run_id"))
    graph_id = _text(graph.get("graph_id"))
    target = _text(payload.get("target"))
    authorization_id = _text(payload.get("authorization_id")) or _text(
        graph.get("authorization_id")
    )
    if not all((assessment_id, graph_id, target, authorization_id)):
        return None

    state = _text(payload.get("state")) or "created"
    stages = _rows(graph.get("nodes"))
    findings = _rows(payload.get("findings"))
    artifacts = _rows(payload.get("artifacts"))
    events = _rows(payload.get("events"))
    completed_stages = sum(_text(item.get("status")) in {"completed", "skipped"} for item in stages)
    blocked_stages = sum(
        _text(item.get("status")) in {"blocked", "failed", "rejected"} for item in stages
    )
    blocking_reason = _text(payload.get("blocking_reason"))
    failure = None
    if state in _FAILURE:
        failure = {
            "category": "website_assessment_failure",
            "stage": _text((_current_stage(stages) or {}).get("stage")),
            "reason_code": state,
            "message": blocking_reason,
            "safe_retry": False,
            "retry_scope": None,
            "preserved": [
                "authorization",
                "assessment_graph",
                "activity_receipts",
                "evidence",
            ],
        }

    allowed_actions = ["view_activity", "view_evidence", "view_findings"]
    if state in _ACTIVE:
        allowed_actions.append("request_cancel")

    projection = {
        "assessment_id": assessment_id,
        "graph_id": graph_id,
        "workspace_id": _text(graph.get("workspace_id")),
        "assessment_kind": "website",
        "selected": True,
        "surface_identity": {surface: assessment_id for surface in _SURFACES},
        "subject": {
            "kind": "website_target",
            "label": target,
            "target": target,
            "profile": _text(payload.get("profile")),
            "scanner": _text(payload.get("scanner")),
        },
        "authority": {
            "authorization_id": authorization_id,
            "approval_status": _text(payload.get("approval_state")) or "not_required",
            "plan_digest": _text(_map(payload.get("approval")).get("plan_digest")),
        },
        "lifecycle": _text(graph.get("chat_stage")) or state,
        "health": _health(state),
        "execution": {
            "state": state,
            "terminal": state in _TERMINAL,
            "reason": blocking_reason,
            "job_id": assessment_id,
            "failure": failure,
        },
        "stages": list(stages),
        "stage_summary": {
            "total": len(stages),
            "completed": completed_stages,
            "blocked": blocked_stages,
        },
        "task_card": {
            "task_id": f"{assessment_id}:website-assessment",
            "assessment_id": assessment_id,
            "state": state,
            "terminal": state in _TERMINAL,
            "current_stage": _current_stage(stages),
            "stage_progress": {"completed": completed_stages, "total": len(stages)},
            "byte_progress": {"received": None, "expected": None},
            "activity": {
                "event_count": len(events),
                "receipt_count": len(artifacts),
                "candidate_count": len(findings),
                "latest_event": dict(events[-1]) if events else None,
            },
            "failure": failure,
            "retry": {"available": False, "scope": None, "user_action": None},
        },
        "activity": {
            "event_count": len(events),
            "tool_receipt_count": len(artifacts),
            "active_tool": None,
        },
        "evidence": {"record_count": len(artifacts)},
        "findings": {"candidate_count": len(findings)},
        "report": {"status": "not_available", "ready": False, "report_id": None},
        "allowed_actions": allowed_actions,
    }
    assert_website_projection_invariants(projection)
    return projection


def assert_website_projection_invariants(projection: Mapping[str, object]) -> None:
    assessment_id = _text(projection.get("assessment_id"))
    graph_id = _text(projection.get("graph_id"))
    surfaces = _map(projection.get("surface_identity"))
    subject = _map(projection.get("subject"))
    authority = _map(projection.get("authority"))
    task_card = _map(projection.get("task_card"))
    report = _map(projection.get("report"))
    if not assessment_id or not graph_id:
        raise ValueError("A website projection requires assessment and graph identifiers.")
    if projection.get("selected") is not True:
        raise ValueError("A website projection must identify the selected assessment.")
    if set(surfaces) != set(_SURFACES) or any(
        _text(surfaces.get(surface)) != assessment_id for surface in _SURFACES
    ):
        raise ValueError("Every website surface must bind to one selected assessment.")
    if not _text(subject.get("target")):
        raise ValueError("A website projection requires one exact target.")
    if not _text(authority.get("authorization_id")):
        raise ValueError("A website projection requires an authorization binding.")
    if _text(task_card.get("assessment_id")) != assessment_id:
        raise ValueError("The website task card must bind to the selected assessment.")
    if report.get("ready") is True:
        raise ValueError("Website report readiness cannot be invented without a persisted report.")
    retry = _map(task_card.get("retry"))
    if retry.get("available") is True or _text(retry.get("scope")):
        raise ValueError("Website assessment must not invent retry authority.")


__all__ = ["assert_website_projection_invariants", "website_assessment_projection"]
