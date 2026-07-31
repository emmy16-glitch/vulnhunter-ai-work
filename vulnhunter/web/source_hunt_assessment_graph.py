"""Bind chat-selected Source Hunt jobs to the authoritative graph store."""

from __future__ import annotations

import re
from pathlib import Path

from django.conf import settings

from vulnhunter.actions.models import sha256_json
from vulnhunter.assessment_graph import SourceAssessmentGraphService
from vulnhunter.source_hunt.jobs import SourceHuntJob

_IDENTIFIER_SANITIZER = re.compile(r"[^a-z0-9._-]+")


def _service() -> SourceAssessmentGraphService:
    return SourceAssessmentGraphService(Path(settings.VULNHUNTER_TASK_GRAPH_ROOT))


def _workspace_id(request: object) -> str | None:
    thread = getattr(request, "vulnhunter_thread", None)
    thread_id = getattr(thread, "thread_id", None)
    return str(thread_id) if thread_id is not None else None


def _owner_id(request: object) -> str:
    user = getattr(request, "user", None)
    username = str(getattr(user, "username", "") or "chat-operator").casefold()
    normalized = _IDENTIFIER_SANITIZER.sub("-", username).strip("-._")
    return (normalized or "chat-operator")[:120]


def source_hunt_plan_digest(job: SourceHuntJob) -> str:
    """Hash the exact immutable queue contract that the graph represents."""

    return sha256_json(
        {
            "job_id": job.job_id,
            "repository_id": job.snapshot.repository_id,
            "revision": job.snapshot.revision,
            "snapshot_sha256": job.snapshot.snapshot_sha256,
            "approval_id": job.approval.approval_id,
            "approval_sha256": job.approval.approval_sha256,
            "permitted_paths": list(job.approval.permitted_paths),
            "model": job.model,
            "expected_report_id": job.expected_report_id,
        }
    )


def bind_source_hunt_assessment_graph(
    request: object,
    *,
    job: SourceHuntJob,
) -> dict[str, object]:
    """Persist the shared source lifecycle graph for one exact queued job."""

    service = _service()
    service.create(
        run_id=job.job_id,
        workspace_id=_workspace_id(request),
        owner_id=_owner_id(request),
        authorization_id=job.approval.approval_id,
        repository_id=job.snapshot.repository_id,
        revision=job.snapshot.revision,
        snapshot_sha256=job.snapshot.snapshot_sha256,
        approval_sha256=job.approval.approval_sha256,
        plan_digest=source_hunt_plan_digest(job),
        expires_at=job.approval.expires_at,
        model=job.model,
        execution_state=job.status.value,
        execution_reason=job.safe_error,
    )
    graph = service.status_payload(job.job_id)
    if graph is None:
        raise RuntimeError("The Source Hunt assessment graph was not persisted.")
    return graph


def project_source_hunt_state(
    job_id: str,
    *,
    state: str,
    reason: str | None = None,
) -> dict[str, object] | None:
    """Project an observed state when the queue operation itself fails safely."""

    service = _service()
    service.project_execution(job_id, state=state, reason=reason)
    return service.status_payload(job_id)


def project_source_hunt_job(job: SourceHuntJob) -> dict[str, object] | None:
    """Project one observed queue/worker state into an existing source graph."""

    return project_source_hunt_state(
        job.job_id,
        state=job.status.value,
        reason=job.safe_error,
    )


__all__ = [
    "bind_source_hunt_assessment_graph",
    "project_source_hunt_job",
    "project_source_hunt_state",
    "source_hunt_plan_digest",
]
