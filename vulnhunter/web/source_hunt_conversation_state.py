"""Durable chat projection for one workspace-bound Source Hunt job."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlencode

from django.conf import settings
from django.urls import reverse

from vulnhunter.source_hunt import SourceHuntStore
from vulnhunter.source_hunt.jobs import SourceHuntJob, SourceHuntJobStore
from vulnhunter.web.source_hunt_assessment_graph import project_source_hunt_job

_SESSION_SOURCE_HUNT = "vulnhunter_conversation_source_hunt"
_SESSION_MESSAGES = "vulnhunter_conversation_messages"
_MAX_MESSAGES = 400


def _job_store() -> SourceHuntJobStore:
    root = Path(
        os.environ.get(
            "VULNHUNTER_SOURCE_HUNT_JOB_ROOT",
            str(settings.BASE_DIR / ".local" / "source-hunt-jobs"),
        )
    )
    return SourceHuntJobStore(root)


def _report_store() -> SourceHuntStore:
    root = Path(
        os.environ.get(
            "VULNHUNTER_SOURCE_HUNT_REPORT_ROOT",
            str(settings.BASE_DIR / ".local" / "source-hunt-reports"),
        )
    )
    return SourceHuntStore(root)


def source_hunt_setup_url(request: object) -> str:
    thread = getattr(request, "vulnhunter_thread", None)
    thread_id = getattr(thread, "thread_id", None)
    base = reverse("web-source-hunt")
    return f"{base}?{urlencode({'thread': str(thread_id)})}" if thread_id else base


def source_hunt_workspace_url(request: object) -> str:
    thread = getattr(request, "vulnhunter_thread", None)
    thread_id = getattr(thread, "thread_id", None)
    base = reverse("web-dashboard")
    return f"{base}?{urlencode({'thread': str(thread_id)})}" if thread_id else base


def _execution_payload(job: SourceHuntJob) -> dict[str, object]:
    return {
        "state": job.status.value,
        "report_id": job.report_id,
        "safe_error": job.safe_error,
        "created_at": job.created_at.isoformat(),
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "completed_at": job.completed_at.isoformat() if job.completed_at else None,
    }


def _report_payload(job: SourceHuntJob) -> dict[str, object] | None:
    if not job.report_id:
        return None
    try:
        report = _report_store().load(job.report_id)
    except (FileNotFoundError, OSError, ValueError):
        return None
    return {
        "report_id": report.report_id,
        "stage": report.stage.value,
        "surfaces_examined": report.surfaces_examined,
        "model_calls": report.model_calls,
        "candidate_count": len(report.candidates),
        "rejected_count": report.rejected_count,
        "abstained_count": report.abstained_count,
        "safe_error": report.safe_error,
    }


def remember_source_hunt_plan(
    request: object,
    *,
    job: SourceHuntJob,
    graph: dict[str, object],
) -> dict[str, object]:
    """Store only bounded repository metadata, never source text or credentials."""

    plan: dict[str, object] = {
        "schema_version": "1.0",
        "job_id": job.job_id,
        "run_id": job.job_id,
        "task_graph_id": graph["graph_id"],
        "repository": {
            "repository_id": job.snapshot.repository_id,
            "revision": job.snapshot.revision,
            "snapshot_sha256": job.snapshot.snapshot_sha256,
            "file_count": len(job.snapshot.files),
            "total_bytes": job.snapshot.total_bytes,
            "visibility": job.approval.visibility.value,
            "permitted_paths": list(job.approval.permitted_paths),
        },
        "approval": {
            "approval_id": job.approval.approval_id,
            "approval_sha256": job.approval.approval_sha256,
            "expires_at": job.approval.expires_at.isoformat(),
        },
        "model": job.model,
        "execution": _execution_payload(job),
        "report": _report_payload(job),
        "assessment_graph": graph,
        "setup_url": source_hunt_setup_url(request),
        "workspace_url": source_hunt_workspace_url(request),
    }
    request.session[_SESSION_SOURCE_HUNT] = plan
    request.session.modified = True
    return plan


def current_source_hunt_plan(request: object) -> dict[str, object] | None:
    """Refresh the chat projection from the authoritative queue and graph stores."""

    raw = request.session.get(_SESSION_SOURCE_HUNT)
    if not isinstance(raw, dict):
        return None
    plan = dict(raw)
    job_id = str(plan.get("job_id") or "")
    if not job_id:
        return None
    try:
        job = _job_store().load(job_id)
    except (FileNotFoundError, OSError, ValueError):
        execution = plan.get("execution")
        execution = dict(execution) if isinstance(execution, dict) else {}
        execution["state"] = "unavailable"
        execution["safe_error"] = "The persisted Source Hunt job is currently unavailable."
        plan["execution"] = execution
        request.session[_SESSION_SOURCE_HUNT] = plan
        request.session.modified = True
        return plan
    graph = project_source_hunt_job(job)
    if graph is not None:
        plan["task_graph_id"] = graph["graph_id"]
        plan["assessment_graph"] = graph
    plan["execution"] = _execution_payload(job)
    plan["report"] = _report_payload(job)
    plan["setup_url"] = source_hunt_setup_url(request)
    plan["workspace_url"] = source_hunt_workspace_url(request)
    request.session[_SESSION_SOURCE_HUNT] = plan
    request.session.modified = True
    return plan


def clear_source_hunt_plan(request: object) -> None:
    request.session.pop(_SESSION_SOURCE_HUNT, None)
    request.session.modified = True


def record_source_hunt_event(request: object, plan: dict[str, object]) -> None:
    """Return the specialist-page decision to the originating conversation once."""

    if getattr(request, "vulnhunter_thread", None) is None:
        return
    job_id = str(plan.get("job_id") or "")
    execution = plan.get("execution")
    state = str(execution.get("state") or "queued") if isinstance(execution, dict) else "queued"
    event_key = f"source-hunt:{job_id}:{state}"
    raw = request.session.get(_SESSION_MESSAGES, [])
    messages = [item for item in raw if isinstance(item, dict)] if isinstance(raw, list) else []
    for item in messages:
        metadata = item.get("metadata")
        if isinstance(metadata, dict) and metadata.get("source_hunt_event") == event_key:
            return
    repository = plan.get("repository")
    repository = repository if isinstance(repository, dict) else {}
    graph = plan.get("assessment_graph")
    graph = graph if isinstance(graph, dict) else {}
    message = {
        "role": "assistant",
        "kind": "status",
        "content": (
            f"Source Hunt {state} for repository "
            f"{repository.get('repository_id', 'snapshot')} at revision "
            f"{repository.get('revision', 'unknown')}. The exact snapshot, "
            "remote-processing approval and worker state are now bound to this workspace."
        ),
        "timestamp": datetime.now(UTC).isoformat(),
        "metadata": {
            "source_hunt_event": event_key,
            "source_hunt": {
                "job_id": job_id,
                "repository_id": repository.get("repository_id"),
                "revision": repository.get("revision"),
                "snapshot_sha256": repository.get("snapshot_sha256"),
                "state": state,
                "chat_stage": graph.get("chat_stage"),
                "task_graph_id": plan.get("task_graph_id"),
            },
        },
    }
    messages.append(message)
    request.session[_SESSION_MESSAGES] = messages[-_MAX_MESSAGES:]
    request.session.modified = True


def source_hunt_chat_reply(intent: str, plan: dict[str, object]) -> str:
    """Explain Source Hunt from persisted queue, report and graph state."""

    execution = plan.get("execution")
    execution = execution if isinstance(execution, dict) else {}
    state = str(execution.get("state") or "queued")
    safe_error = str(execution.get("safe_error") or "")
    graph = plan.get("assessment_graph")
    graph = graph if isinstance(graph, dict) else {}
    chat_stage = str(graph.get("chat_stage") or "queued_for_analysis")
    repository = plan.get("repository")
    repository = repository if isinstance(repository, dict) else {}
    repository_id = str(repository.get("repository_id") or "the selected repository")
    revision = str(repository.get("revision") or "the bound revision")

    if intent == "status":
        suffix = f" {safe_error}" if safe_error else ""
        return (
            f"Source Hunt for {repository_id} at {revision} is {state}. "
            f"Authoritative stage: {chat_stage}.{suffix}"
        ).strip()
    if intent == "results":
        report = plan.get("report")
        if state == "failed":
            return f"Source Hunt failed safely. {safe_error or 'No report was produced.'}"
        if not isinstance(report, dict):
            return "Source Hunt has not produced a persisted report yet."
        return (
            "The persisted Source Hunt report examined "
            f"{report.get('surfaces_examined', 0)} attack surface(s) and retained "
            f"{report.get('candidate_count', 0)} candidate(s), with "
            f"{report.get('rejected_count', 0)} rejected and "
            f"{report.get('abstained_count', 0)} abstained. Retained candidates still require "
            "independent verification and review."
        )
    if intent == "next_step":
        if state in {"queued", "running"}:
            return "No browser action is required while the separate Source Hunt worker continues."
        if state == "completed":
            return (
                "Review the evidence-bound candidates, then run independent verification before "
                "requesting review, remediation or a final report."
            )
        if state == "failed":
            return (
                "Inspect the bounded safe error, repair the provider, approval or repository "
                "issue, then create a new exact snapshot rather than reusing stale authority."
            )
        return "Open the protected Source Hunt setup to create a new exact approved snapshot."
    return (
        f"Source Hunt is tracking {repository_id} at {revision}. Ask for its status, results or "
        "next step."
    )


__all__ = [
    "clear_source_hunt_plan",
    "current_source_hunt_plan",
    "record_source_hunt_event",
    "remember_source_hunt_plan",
    "source_hunt_chat_reply",
    "source_hunt_setup_url",
    "source_hunt_workspace_url",
]
