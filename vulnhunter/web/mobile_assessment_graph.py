"""Bind conversational APK hunts to the authoritative assessment graph store."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

from django.conf import settings

from vulnhunter.assessment_graph import MobileAssessmentGraphService

_IDENTIFIER_SANITIZER = re.compile(r"[^a-z0-9._-]+")


def _service() -> MobileAssessmentGraphService:
    return MobileAssessmentGraphService(Path(settings.VULNHUNTER_TASK_GRAPH_ROOT))


def _workspace_id(request: object) -> str | None:
    thread = getattr(request, "vulnhunter_thread", None)
    thread_id = getattr(thread, "thread_id", None)
    return str(thread_id) if thread_id is not None else None


def _owner_id(request: object) -> str:
    user = getattr(request, "user", None)
    username = str(getattr(user, "username", "") or "chat-operator").casefold()
    normalized = _IDENTIFIER_SANITIZER.sub("-", username).strip("-._")
    return (normalized or "chat-operator")[:120]


def bind_mobile_assessment_graph(
    request: object,
    *,
    plan: dict[str, object],
) -> dict[str, object]:
    """Persist the shared lifecycle graph and return the enriched plan projection."""

    artifact = plan.get("artifact")
    if not isinstance(artifact, dict):
        raise RuntimeError("The APK plan is missing its immutable artifact binding.")
    execution = plan.get("execution")
    execution = execution if isinstance(execution, dict) else {}
    state = str(execution.get("state") or "prepared")
    reason = str(execution.get("reason") or "") or None
    run_id = str(plan["run_id"])
    legacy_graph_id = str(plan.get("task_graph_id") or "")
    service = _service()
    service.create(
        run_id=run_id,
        workspace_id=_workspace_id(request),
        owner_id=_owner_id(request),
        authorization_id=str(artifact["attachment_id"]),
        artifact_id=str(artifact["artifact_id"]),
        artifact_sha256=str(artifact["artifact_sha256"]),
        expires_at=datetime.now(UTC) + timedelta(hours=2),
        profile=str(plan["profile"]),
        plan_digest=str(plan["plan_digest"]),
        execution_state=state,
        execution_reason=reason,
    )
    graph = service.status_payload(run_id)
    if graph is None:
        raise RuntimeError("The APK assessment graph was not persisted.")
    enriched = dict(plan)
    if legacy_graph_id and legacy_graph_id != graph["graph_id"]:
        enriched["tool_task_graph_id"] = legacy_graph_id
    enriched["task_graph_id"] = graph["graph_id"]
    enriched["assessment_graph"] = graph
    return enriched


def refresh_mobile_assessment_graph(plan: dict[str, object]) -> dict[str, object]:
    """Project observed worker state into the persisted graph and refresh chat state."""

    run_id = str(plan.get("run_id") or "")
    if not run_id:
        return plan
    execution = plan.get("execution")
    execution = execution if isinstance(execution, dict) else {}
    state = str(execution.get("state") or "prepared")
    reason = str(execution.get("reason") or "") or None
    service = _service()
    service.project_execution(run_id, state=state, reason=reason)
    graph = service.status_payload(run_id)
    if graph is None:
        return plan
    enriched = dict(plan)
    enriched["task_graph_id"] = graph["graph_id"]
    enriched["assessment_graph"] = graph
    return enriched


__all__ = ["bind_mobile_assessment_graph", "refresh_mobile_assessment_graph"]
