"""Authoritative browser projection for one selected assessment.

The projection deliberately contains only persisted backend state. It gives chat,
inspector, history, findings, evidence, graph and report surfaces one shared
assessment identifier and lifecycle vocabulary without granting the browser any
execution or authority.
"""

from __future__ import annotations

from collections.abc import Mapping

_TERMINAL_EXECUTION_STATES = frozenset({"completed", "failed", "rejected", "cancelled"})
_ACTIVE_EXECUTION_STATES = frozenset({"queued", "claimed", "running", "cancelling"})


def _mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _records(value: object) -> tuple[dict[str, object], ...]:
    if not isinstance(value, list):
        return ()
    return tuple(dict(item) for item in value if isinstance(item, Mapping))


def _non_empty_text(value: object) -> str | None:
    text = str(value or "").strip()
    return text or None


def _stage_status(stages: tuple[dict[str, object], ...], name: str) -> str | None:
    for stage in stages:
        if str(stage.get("stage") or "") == name:
            return _non_empty_text(stage.get("status"))
    return None


def _allowed_actions(*, execution_state: str, report_ready: bool) -> list[str]:
    """Return state-derived UI actions without granting authority.

    These values are presentation hints only. Every endpoint must still re-check
    identity, role, policy, immutable plan and current backend state.
    """

    actions = ["view_activity", "view_evidence", "view_findings"]
    if execution_state in _ACTIVE_EXECUTION_STATES:
        actions.append("request_cancel")
    if execution_state in {"failed", "rejected"}:
        actions.append("request_retry")
    if report_ready:
        actions.append("view_report")
    return actions


def mobile_assessment_projection(plan: Mapping[str, object] | None) -> dict[str, object] | None:
    """Return one assessment-scoped read model for a persisted mobile plan.

    Older incomplete session payloads may not have an authoritative graph. They
    return ``None`` rather than inventing an assessment. Current validated APK
    flows bind the graph before the plan is exposed to the browser.
    """

    if plan is None:
        return None
    graph = _mapping(plan.get("assessment_graph"))
    run_id = _non_empty_text(plan.get("run_id"))
    graph_id = _non_empty_text(graph.get("graph_id"))
    if run_id is None or graph_id is None:
        return None

    artifact = _mapping(plan.get("artifact"))
    execution = _mapping(plan.get("execution"))
    receipt = _mapping(execution.get("receipt"))
    progress = _mapping(execution.get("progress"))
    stages = _records(graph.get("nodes"))
    captures = _records(receipt.get("captures")) or _records(
        _mapping(progress.get("result_summary")).get("captures")
    )
    observations = _records(receipt.get("candidate_observations")) or _records(
        _mapping(_mapping(progress.get("result_summary")).get("hunt")).get("candidates")
    )
    events = _records(progress.get("events"))

    execution_state = _non_empty_text(execution.get("state")) or "prepared"
    lifecycle = _non_empty_text(graph.get("chat_stage")) or "understanding_request"
    approval_status = _stage_status(stages, "approval") or "pending"
    report_status = _stage_status(stages, "report") or "pending"
    report_ready = report_status in {"ready", "completed"}

    original_filename = _non_empty_text(artifact.get("original_filename"))
    artifact_id = _non_empty_text(artifact.get("artifact_id"))
    artifact_sha256 = _non_empty_text(artifact.get("artifact_sha256"))
    subject_label = original_filename or artifact_id or "Android APK"

    completed_stage_count = sum(
        1 for stage in stages if _non_empty_text(stage.get("status")) == "completed"
    )
    blocked_stage_count = sum(
        1
        for stage in stages
        if _non_empty_text(stage.get("status")) in {"blocked", "failed", "rejected"}
    )

    projection = {
        "assessment_id": run_id,
        "graph_id": graph_id,
        "workspace_id": _non_empty_text(graph.get("workspace_id")),
        "assessment_kind": _non_empty_text(graph.get("assessment_kind")) or "apk",
        "selected": True,
        "subject": {
            "kind": "artifact",
            "label": subject_label,
            "artifact_id": artifact_id,
            "sha256": artifact_sha256,
        },
        "authority": {
            "authorization_id": _non_empty_text(graph.get("authorization_id")),
            "plan_digest": _non_empty_text(plan.get("plan_digest")),
            "profile": _non_empty_text(plan.get("profile")),
            "approval_status": approval_status,
        },
        "lifecycle": lifecycle,
        "execution": {
            "state": execution_state,
            "reason": _non_empty_text(execution.get("reason")),
            "job_id": _non_empty_text(execution.get("job_id")),
            "terminal": execution_state in _TERMINAL_EXECUTION_STATES,
        },
        "stages": list(stages),
        "stage_summary": {
            "total": len(stages),
            "completed": completed_stage_count,
            "blocked": blocked_stage_count,
        },
        "activity": {
            "event_count": len(events),
            "tool_receipt_count": len(captures),
            "active_tool": _non_empty_text(progress.get("active_tool")),
        },
        "evidence": {
            "record_count": len(captures),
        },
        "findings": {
            "candidate_count": len(observations),
        },
        "report": {
            "status": report_status,
            "ready": report_ready,
        },
        "allowed_actions": _allowed_actions(
            execution_state=execution_state,
            report_ready=report_ready,
        ),
    }
    assert_mobile_projection_invariants(projection)
    return projection


def assert_mobile_projection_invariants(projection: Mapping[str, object]) -> None:
    """Reject contradictory assessment state before it reaches a browser surface."""

    assessment_id = _non_empty_text(projection.get("assessment_id"))
    graph_id = _non_empty_text(projection.get("graph_id"))
    subject = _mapping(projection.get("subject"))
    execution = _mapping(projection.get("execution"))
    report = _mapping(projection.get("report"))
    if assessment_id is None or graph_id is None:
        raise ValueError("An assessment projection requires assessment and graph identifiers.")
    if projection.get("selected") is not True:
        raise ValueError("An assessment projection must identify the selected assessment.")
    if _non_empty_text(subject.get("label")) is None:
        raise ValueError("An assessment projection requires a selected subject.")
    if _non_empty_text(execution.get("state")) is None:
        raise ValueError("An assessment projection requires an execution state.")
    if report.get("ready") is True and _non_empty_text(report.get("status")) not in {
        "ready",
        "completed",
    }:
        raise ValueError("Report readiness must agree with the persisted report stage.")


__all__ = ["assert_mobile_projection_invariants", "mobile_assessment_projection"]
