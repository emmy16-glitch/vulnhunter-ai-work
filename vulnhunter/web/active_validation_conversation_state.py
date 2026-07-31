"""Durable chat projection for one workspace-bound Active Validation run."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlencode

from django.conf import settings
from django.db import transaction
from django.urls import reverse

from vulnhunter.adversary_lab.models import LabRecord
from vulnhunter.web.active_validation_assessment_graph import (
    ProjectingAdversaryLabStore,
    project_active_validation_record,
)
from vulnhunter.web.models import ConversationThread

_SESSION_ACTIVE_VALIDATION = "vulnhunter_conversation_active_validation"
_SESSION_MESSAGES = "vulnhunter_conversation_messages"
_MAX_MESSAGES = 400


def _store() -> ProjectingAdversaryLabStore:
    store = ProjectingAdversaryLabStore(Path(settings.VULNHUNTER_ADVERSARY_LAB_DATABASE))
    store.initialize()
    return store


def active_validation_workspace_url(request: object) -> str:
    thread = getattr(request, "vulnhunter_thread", None)
    thread_id = getattr(thread, "thread_id", None)
    base = reverse("web-dashboard")
    return f"{base}?{urlencode({'thread': str(thread_id)})}" if thread_id else base


def _record_payload(
    record: LabRecord,
    *,
    graph: dict[str, object] | None,
    workspace_url: str,
) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "lab_id": record.plan.lab_id,
        "run_id": record.plan.lab_id,
        "task_graph_id": graph.get("graph_id") if isinstance(graph, dict) else None,
        "parent": {
            "assessment_id": record.plan.assessment_id,
            "finding_reference": record.plan.finding_reference,
            "authorization_id": record.plan.authorization_id,
            "target_reference": record.plan.target_reference,
        },
        "scenario": {
            "scenario_id": record.plan.scenario_id,
            "scenario_version": record.plan.scenario_version,
            "maximum_trials": record.plan.maximum_trials,
            "minimum_trials": record.plan.minimum_trials,
            "required_confirmations": record.plan.required_confirmations,
            "plan_digest": record.plan.plan_digest,
        },
        "execution": {
            "state": record.state.value,
            "current_trial": record.current_trial,
            "confirmed_trials": record.confirmed_trials,
            "inconclusive_trials": record.inconclusive_trials,
            "failed_trials": record.failed_trials,
            "trial_count": len(record.trials),
            "cleanup_verified": record.cleanup_verified,
            "cancellation_requested": record.cancellation_requested,
            "cancellation_reason": record.cancellation_reason,
            "active_summary": record.active_summary,
            "terminal": record.terminal,
            "updated_at": record.updated_at.isoformat(),
            "revision": record.revision,
        },
        "review": {
            "result": record.result,
            "human_review_state": record.human_review_state,
        },
        "assessment_graph": graph,
        "detail_url": reverse("web-lab-detail", kwargs={"lab_id": record.plan.lab_id}),
        "workspace_url": workspace_url,
    }


def remember_active_validation_workspace(
    *,
    owner: object,
    workspace_id: str,
    record: LabRecord,
    graph: dict[str, object],
) -> dict[str, object]:
    """Bind bounded lab metadata to the parent assessment's durable workspace."""

    with transaction.atomic():
        thread = ConversationThread.objects.select_for_update().get(
            thread_id=workspace_id,
            owner=owner,
            archived=False,
        )
        workspace_url = f"{reverse('web-dashboard')}?{urlencode({'thread': workspace_id})}"
        plan = _record_payload(record, graph=graph, workspace_url=workspace_url)
        data = dict(thread.data) if isinstance(thread.data, dict) else {}
        data[_SESSION_ACTIVE_VALIDATION] = plan
        thread.data = data
        thread.save(update_fields=("data", "updated_at"))
    record_active_validation_event_for_thread(thread, plan)
    return plan


def current_active_validation_plan(request: object) -> dict[str, object] | None:
    """Refresh chat state from the authoritative SQLite record and child graph."""

    raw = request.session.get(_SESSION_ACTIVE_VALIDATION)
    if not isinstance(raw, dict):
        return None
    lab_id = str(raw.get("lab_id") or "")
    if not lab_id:
        return None
    try:
        record = _store().get(lab_id)
    except (OSError, RuntimeError, ValueError):
        plan = dict(raw)
        execution = plan.get("execution")
        execution = dict(execution) if isinstance(execution, dict) else {}
        execution["state"] = "unavailable"
        execution["active_summary"] = "The persisted Active Validation record is unavailable."
        plan["execution"] = execution
        request.session[_SESSION_ACTIVE_VALIDATION] = plan
        request.session.modified = True
        return plan
    graph = project_active_validation_record(record)
    plan = _record_payload(
        record,
        graph=graph,
        workspace_url=active_validation_workspace_url(request),
    )
    request.session[_SESSION_ACTIVE_VALIDATION] = plan
    request.session.modified = True
    return plan


def clear_active_validation_plan(request: object) -> None:
    request.session.pop(_SESSION_ACTIVE_VALIDATION, None)
    request.session.modified = True


def _event_message(plan: dict[str, object]) -> dict[str, object]:
    execution = plan.get("execution")
    execution = execution if isinstance(execution, dict) else {}
    scenario = plan.get("scenario")
    scenario = scenario if isinstance(scenario, dict) else {}
    graph = plan.get("assessment_graph")
    graph = graph if isinstance(graph, dict) else {}
    state = str(execution.get("state") or "unknown")
    trial = int(execution.get("current_trial") or 0)
    lab_id = str(plan.get("lab_id") or "")
    event_key = f"active-validation:{lab_id}:{state}:{trial}"
    return {
        "role": "assistant",
        "kind": "status" if state != "completed" else "result",
        "content": (
            f"Active Validation {state} for scenario "
            f"{scenario.get('scenario_id', 'reviewed-scenario')}. "
            f"Authoritative stage: {graph.get('chat_stage', 'unknown')}. "
            f"Trial {trial} of {scenario.get('maximum_trials', 0)}."
        ),
        "timestamp": datetime.now(UTC).isoformat(),
        "metadata": {
            "active_validation_event": event_key,
            "active_validation": {
                "lab_id": lab_id,
                "state": state,
                "current_trial": trial,
                "chat_stage": graph.get("chat_stage"),
                "task_graph_id": plan.get("task_graph_id"),
            },
        },
    }


def record_active_validation_event(request: object, plan: dict[str, object]) -> None:
    if getattr(request, "vulnhunter_thread", None) is None:
        return
    message = _event_message(plan)
    event_key = message["metadata"]["active_validation_event"]
    raw = request.session.get(_SESSION_MESSAGES, [])
    messages = [item for item in raw if isinstance(item, dict)] if isinstance(raw, list) else []
    if any(
        isinstance(item.get("metadata"), dict)
        and item["metadata"].get("active_validation_event") == event_key
        for item in messages
    ):
        return
    messages.append(message)
    request.session[_SESSION_MESSAGES] = messages[-_MAX_MESSAGES:]
    request.session.modified = True


def record_active_validation_event_for_thread(
    thread: ConversationThread,
    plan: dict[str, object],
) -> None:
    message = _event_message(plan)
    event_key = message["metadata"]["active_validation_event"]
    with transaction.atomic():
        current = ConversationThread.objects.select_for_update().get(
            thread_id=thread.thread_id,
            owner=thread.owner,
            archived=False,
        )
        data = dict(current.data) if isinstance(current.data, dict) else {}
        raw = data.get(_SESSION_MESSAGES, [])
        messages = [item for item in raw if isinstance(item, dict)] if isinstance(raw, list) else []
        if any(
            isinstance(item.get("metadata"), dict)
            and item["metadata"].get("active_validation_event") == event_key
            for item in messages
        ):
            return
        messages.append(message)
        data[_SESSION_MESSAGES] = messages[-_MAX_MESSAGES:]
        current.data = data
        current.save(update_fields=("data", "updated_at"))


def active_validation_chat_reply(intent: str, plan: dict[str, object]) -> str:
    execution = plan.get("execution")
    execution = execution if isinstance(execution, dict) else {}
    scenario = plan.get("scenario")
    scenario = scenario if isinstance(scenario, dict) else {}
    graph = plan.get("assessment_graph")
    graph = graph if isinstance(graph, dict) else {}
    review = plan.get("review")
    review = review if isinstance(review, dict) else {}
    state = str(execution.get("state") or "unknown")
    trial = int(execution.get("current_trial") or 0)
    maximum = int(scenario.get("maximum_trials") or 0)

    if intent == "status":
        return (
            f"Active Validation is {state}. Authoritative stage: "
            f"{graph.get('chat_stage', 'unknown')}. Trial {trial} of {maximum}. "
            f"{execution.get('active_summary', '')}"
        ).strip()
    if intent == "results":
        if state == "failed":
            return "Active Validation failed closed. No finding was automatically confirmed."
        if state == "cancelled":
            return "Active Validation was cancelled; no final validation result was produced."
        if state != "completed":
            return "Active Validation has not completed its bounded evidence evaluation yet."
        return (
            f"The synthetic validation result is {review.get('result', 'unavailable')} after "
            f"{execution.get('trial_count', 0)} trial(s), including "
            f"{execution.get('confirmed_trials', 0)} confirmed trial(s). Cleanup verified: "
            f"{bool(execution.get('cleanup_verified'))}. Human review remains "
            f"{review.get('human_review_state', 'pending')}."
        )
    if intent == "next_step":
        if state == "awaiting_approval":
            return (
                "A different governed approver must approve the exact plan on the protected page."
            )
        if state == "approved":
            return "An authorised operator must complete password step-up and queue the exact plan."
        if state in {"queued", "provisioning", "running", "evaluating", "cleaning"}:
            return "No browser action is required while the isolated worker continues."
        if state == "completed":
            return (
                "Send the evidence-bound result to governed human review before any release claim."
            )
        if state in {"failed", "blocked"}:
            return (
                "Inspect the failed-closed state and create a new exact plan instead of reusing it."
            )
        return "Open the protected Active Validation workspace to review the current plan."
    return "Ask for Active Validation status, results, or the next governed step."


__all__ = [
    "active_validation_chat_reply",
    "active_validation_workspace_url",
    "clear_active_validation_plan",
    "current_active_validation_plan",
    "record_active_validation_event",
    "remember_active_validation_workspace",
]
