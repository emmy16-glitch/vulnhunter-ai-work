"""Authoritative browser projection for one selected assessment.

The projection deliberately contains only persisted backend state. It gives chat,
inspector, history, findings, evidence, graph and report surfaces one shared
assessment identifier and lifecycle vocabulary without granting the browser any
execution or authority.
"""

from __future__ import annotations

from collections.abc import Mapping

_TERMINAL_EXECUTION_STATES = frozenset({"completed", "failed", "rejected", "cancelled"})


def _mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _records(value: object) -> tuple[dict[str, object], ...]:
    if not isinstance(value, list):
        return ()
    return tuple(dict(item) for item in value if isinstance(item, Mapping))


def _non_empty_text(value: object) -> str | None:
    text = str(value or "").strip()
    return text or None


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
    stages = _records(graph.get("nodes"))
    captures = _records(receipt.get("captures"))
    observations = _records(receipt.get("candidate_observations"))

    execution_state = _non_empty_text(execution.get("state")) or "prepared"
    lifecycle = _non_empty_text(graph.get("chat_stage")) or "understanding_request"
    report_stage = next(
        (stage for stage in stages if str(stage.get("stage") or "") == "report"),
        None,
    )
    report_status = _non_empty_text(report_stage.get("status")) if report_stage else None

    original_filename = _non_empty_text(artifact.get("original_filename"))
    artifact_id = _non_empty_text(artifact.get("artifact_id"))
    artifact_sha256 = _non_empty_text(artifact.get("artifact_sha256"))
    subject_label = original_filename or artifact_id or "Android APK"

    return {
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
        },
        "lifecycle": lifecycle,
        "execution": {
            "state": execution_state,
            "reason": _non_empty_text(execution.get("reason")),
            "job_id": _non_empty_text(execution.get("job_id")),
            "terminal": execution_state in _TERMINAL_EXECUTION_STATES,
        },
        "stages": list(stages),
        "activity": {
            "tool_receipt_count": len(captures),
        },
        "evidence": {
            "record_count": len(captures),
        },
        "findings": {
            "candidate_count": len(observations),
        },
        "report": {
            "status": report_status or "pending",
            "ready": report_status in {"ready", "completed"},
        },
    }


def assert_mobile_projection_invariants(projection: Mapping[str, object]) -> None:
    """Reject contradictory assessment state before it reaches a browser surface."""

    assessment_id = _non_empty_text(projection.get("assessment_id"))
    graph_id = _non_empty_text(projection.get("graph_id"))
    subject = _mapping(projection.get("subject"))
    if assessment_id is None or graph_id is None:
        raise ValueError("An assessment projection requires assessment and graph identifiers.")
    if _non_empty_text(subject.get("label")) is None:
        raise ValueError("An assessment projection requires a selected subject.")


__all__ = ["assert_mobile_projection_invariants", "mobile_assessment_projection"]
