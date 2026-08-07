"""Bind conversational APK hunts to the authoritative assessment graph store."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

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


def _assert_existing_binding(
    service: MobileAssessmentGraphService,
    *,
    run_id: str,
    workspace_id: str | None,
    owner_id: str,
    authorization_id: str,
    artifact_id: str,
    artifact_sha256: str,
    profile: str,
    plan_digest: str,
) -> None:
    """Fail closed unless an existing assessment is the exact requested binding."""

    graph_id = service.core.graph_id_for_run(run_id)
    bundle = service.core._load_bundle(graph_id)
    parsed_workspace = UUID(workspace_id) if workspace_id else None
    expected_targets = {
        artifact_id,
        f"apk-sha256:{artifact_sha256}",
        f"plan-sha256:{plan_digest}",
    }
    if (
        bundle.run_id != run_id
        or bundle.assessment_kind.value != "apk"
        or bundle.workspace_id != parsed_workspace
        or bundle.owner_id != owner_id
        or bundle.authorization_id != authorization_id
        or bundle.target_reference != f"apk-sha256:{artifact_sha256}"
    ):
        raise RuntimeError("The existing APK assessment binding does not match this request.")
    if not bundle.manifests or any(
        manifest.operation != profile
        or manifest.parent_manifest_sha256 != plan_digest
        or set(manifest.target_references) != expected_targets
        or tuple(manifest.authorization_references) != (authorization_id,)
        for manifest in bundle.manifests
    ):
        raise RuntimeError("The existing APK assessment plan binding does not match this request.")


def bind_mobile_assessment_graph(
    request: object,
    *,
    plan: dict[str, object],
) -> dict[str, object]:
    """Create or bind the shared lifecycle graph and return the enriched projection."""

    artifact = plan.get("artifact")
    if not isinstance(artifact, dict):
        raise RuntimeError("The APK plan is missing its immutable artifact binding.")
    execution = plan.get("execution")
    execution = execution if isinstance(execution, dict) else {}
    state = str(execution.get("state") or "prepared")
    reason = str(execution.get("reason") or "") or None
    run_id = str(plan["run_id"])
    legacy_graph_id = str(plan.get("task_graph_id") or "")
    workspace_id = _workspace_id(request)
    owner_id = _owner_id(request)
    artifact_id = str(artifact["artifact_id"])
    authorization_id = f"uploaded-artifact-{artifact_id}"
    artifact_sha256 = str(artifact["artifact_sha256"])
    profile = str(plan["profile"])
    plan_digest = str(plan["plan_digest"])
    service = _service()
    existing = service.status_payload(run_id)
    if existing is None:
        service.create(
            run_id=run_id,
            workspace_id=workspace_id,
            owner_id=owner_id,
            authorization_id=authorization_id,
            artifact_id=artifact_id,
            artifact_sha256=artifact_sha256,
            expires_at=datetime.now(UTC) + timedelta(hours=2),
            profile=profile,
            plan_digest=plan_digest,
            execution_state=state,
            execution_reason=reason,
        )
    else:
        _assert_existing_binding(
            service,
            run_id=run_id,
            workspace_id=workspace_id,
            owner_id=owner_id,
            authorization_id=authorization_id,
            artifact_id=artifact_id,
            artifact_sha256=artifact_sha256,
            profile=profile,
            plan_digest=plan_digest,
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
