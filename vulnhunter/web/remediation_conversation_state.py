"""Durable chat projection for one workspace-bound remediation plan."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlencode

from django.conf import settings
from django.db import transaction
from django.urls import reverse

from vulnhunter.findings import Finding, FindingStore
from vulnhunter.web.models import ConversationThread
from vulnhunter.web.remediation_assessment_graph import project_remediation_finding

_SESSION_REMEDIATION = "vulnhunter_conversation_remediation"
_SESSION_MESSAGES = "vulnhunter_conversation_messages"
_MAX_MESSAGES = 400


def remediation_finding_store() -> FindingStore:
    raw = os.environ.get(
        "VULNHUNTER_FINDING_DATABASE",
        str(
            getattr(
                settings,
                "VULNHUNTER_FINDING_DATABASE",
                settings.BASE_DIR / ".local" / "findings" / "findings.sqlite3",
            )
        ),
    )
    return FindingStore(Path(raw))


def _thread_plan(request: object) -> dict[str, object] | None:
    thread = getattr(request, "vulnhunter_thread", None)
    data = getattr(thread, "data", None)
    if not isinstance(data, dict):
        return None
    raw = data.get(_SESSION_REMEDIATION)
    return dict(raw) if isinstance(raw, dict) else None


def _write_thread_plan(request: object, plan: dict[str, object] | None) -> None:
    thread = getattr(request, "vulnhunter_thread", None)
    if not isinstance(thread, ConversationThread):
        return
    with transaction.atomic():
        current = ConversationThread.objects.select_for_update().get(
            thread_id=thread.thread_id,
            owner=thread.owner,
            archived=False,
        )
        data = dict(current.data) if isinstance(current.data, dict) else {}
        if plan is None:
            data.pop(_SESSION_REMEDIATION, None)
        else:
            data[_SESSION_REMEDIATION] = plan
        current.data = data
        current.save(update_fields=("data", "updated_at"))
    thread.data = data
    thread.updated_at = current.updated_at


def remediation_workspace_url(workspace_id: str | None) -> str:
    base = reverse("web-dashboard")
    return f"{base}?{urlencode({'thread': workspace_id})}" if workspace_id else base


def remediation_create_url(finding_id: str, workspace_id: str | None) -> str:
    base = reverse("web-remediation-create", kwargs={"finding_id": finding_id})
    return f"{base}?{urlencode({'thread': workspace_id})}" if workspace_id else base


def remediation_detail_url(finding_id: str, workspace_id: str | None) -> str:
    base = reverse("web-remediation-detail", kwargs={"finding_id": finding_id})
    return f"{base}?{urlencode({'thread': workspace_id})}" if workspace_id else base


def _finding_payload(
    finding: Finding,
    *,
    graph: dict[str, object] | None,
    workspace_id: str | None,
) -> dict[str, object]:
    remediation = finding.remediation
    if remediation is None or remediation.remediation_id is None:
        raise ValueError("the finding has no governed remediation plan")
    return {
        "schema_version": "1.0",
        "finding_id": finding.finding_id,
        "run_id": remediation.remediation_id,
        "remediation_id": remediation.remediation_id,
        "task_graph_id": graph.get("graph_id") if isinstance(graph, dict) else None,
        "finding": {
            "campaign_id": finding.campaign_id,
            "fingerprint": finding.fingerprint,
            "title": finding.title,
            "severity": finding.severity.value,
            "verification": finding.verification.value,
            "status": finding.status.value,
            "affected_asset": finding.affected_asset,
            "affected_component": finding.affected_component,
            "evidence_count": len(finding.evidence),
            "revision": finding.revision,
        },
        "plan": {
            "state": remediation.state.value if remediation.state else "unknown",
            "plan_sha256": remediation.plan_sha256,
            "source_finding_revision": remediation.source_finding_revision,
            "source_finding_fingerprint": remediation.source_finding_fingerprint,
            "owner_id": remediation.owner_id,
            "summary": remediation.summary,
            "target_references": list(remediation.target_references),
            "regression_test": remediation.regression_test,
            "verification_recipe": remediation.verification_recipe,
            "compatibility_risks": list(remediation.compatibility_risks),
            "references": list(remediation.references),
            "created_at": remediation.created_at.isoformat() if remediation.created_at else None,
            "expires_at": remediation.expires_at.isoformat() if remediation.expires_at else None,
            "due_at": remediation.due_at.isoformat() if remediation.due_at else None,
            "cancellation_reason": remediation.cancellation_reason,
        },
        "assessment_graph": graph,
        "create_url": remediation_create_url(finding.finding_id, workspace_id),
        "detail_url": remediation_detail_url(finding.finding_id, workspace_id),
        "workspace_url": remediation_workspace_url(workspace_id),
    }


def remember_remediation_workspace(
    *,
    owner: object,
    workspace_id: str,
    finding: Finding,
    graph: dict[str, object],
) -> dict[str, object]:
    """Bind bounded plan metadata to the originating durable conversation."""

    with transaction.atomic():
        thread = ConversationThread.objects.select_for_update().get(
            thread_id=workspace_id,
            owner=owner,
            archived=False,
        )
        plan = _finding_payload(finding, graph=graph, workspace_id=workspace_id)
        data = dict(thread.data) if isinstance(thread.data, dict) else {}
        data[_SESSION_REMEDIATION] = plan
        thread.data = data
        thread.save(update_fields=("data", "updated_at"))
    record_remediation_event_for_thread(thread, plan)
    return plan


def current_remediation_plan(request: object) -> dict[str, object] | None:
    """Refresh chat state from the CAS finding and immutable child graph."""

    raw = _thread_plan(request)
    if raw is None:
        return None
    finding_id = str(raw.get("finding_id") or "")
    remediation_id = str(raw.get("remediation_id") or "")
    if not finding_id or not remediation_id:
        return None
    try:
        finding = remediation_finding_store().get(finding_id)
    except (OSError, RuntimeError, ValueError):
        plan = dict(raw)
        plan_data = plan.get("plan")
        plan_data = dict(plan_data) if isinstance(plan_data, dict) else {}
        plan_data["state"] = "unavailable"
        plan_data["cancellation_reason"] = "The persisted remediation finding is unavailable."
        plan["plan"] = plan_data
        _write_thread_plan(request, plan)
        return plan
    remediation = finding.remediation
    if remediation is None or remediation.remediation_id != remediation_id:
        return None
    graph = project_remediation_finding(finding)
    thread = getattr(request, "vulnhunter_thread", None)
    workspace_id = str(getattr(thread, "thread_id", "") or "") or None
    plan = _finding_payload(finding, graph=graph, workspace_id=workspace_id)
    _write_thread_plan(request, plan)
    return plan


def clear_remediation_plan(request: object) -> None:
    _write_thread_plan(request, None)


def _event_message(plan: dict[str, object]) -> dict[str, object]:
    finding = plan.get("finding")
    finding = finding if isinstance(finding, dict) else {}
    remediation = plan.get("plan")
    remediation = remediation if isinstance(remediation, dict) else {}
    graph = plan.get("assessment_graph")
    graph = graph if isinstance(graph, dict) else {}
    state = str(remediation.get("state") or "unknown")
    revision = int(finding.get("revision") or 0)
    remediation_id = str(plan.get("remediation_id") or "")
    event_key = f"remediation:{remediation_id}:{state}:{revision}"
    return {
        "role": "assistant",
        "kind": "status",
        "content": (
            f"Remediation plan {state} for finding {plan.get('finding_id', 'unknown')}. "
            f"Authoritative stage: {graph.get('chat_stage', 'unknown')}. "
            "Developer implementation, fix verification, review and merge remain separate."
        ),
        "timestamp": datetime.now(UTC).isoformat(),
        "metadata": {
            "remediation_event": event_key,
            "remediation": {
                "remediation_id": remediation_id,
                "finding_id": plan.get("finding_id"),
                "state": state,
                "chat_stage": graph.get("chat_stage"),
                "task_graph_id": plan.get("task_graph_id"),
                "finding_revision": revision,
            },
        },
    }


def record_remediation_event(request: object, plan: dict[str, object]) -> None:
    if getattr(request, "vulnhunter_thread", None) is None:
        return
    message = _event_message(plan)
    event_key = message["metadata"]["remediation_event"]
    raw = request.session.get(_SESSION_MESSAGES, [])
    messages = [item for item in raw if isinstance(item, dict)] if isinstance(raw, list) else []
    if any(
        isinstance(item.get("metadata"), dict)
        and item["metadata"].get("remediation_event") == event_key
        for item in messages
    ):
        return
    messages.append(message)
    request.session[_SESSION_MESSAGES] = messages[-_MAX_MESSAGES:]
    request.session.modified = True


def record_remediation_event_for_thread(
    thread: ConversationThread,
    plan: dict[str, object],
) -> None:
    message = _event_message(plan)
    event_key = message["metadata"]["remediation_event"]
    with transaction.atomic():
        current = ConversationThread.objects.select_for_update().get(
            thread_id=thread.thread_id,
            owner=thread.owner,
            archived=False,
        )
        data = dict(current.data) if isinstance(current.data, dict) else {}
        raw = data.get(_SESSION_MESSAGES, [])
        messages = [item for item in raw if isinstance(item, dict)] if isinstance(raw, list) else []
        if not any(
            isinstance(item.get("metadata"), dict)
            and item["metadata"].get("remediation_event") == event_key
            for item in messages
        ):
            messages.append(message)
            data[_SESSION_MESSAGES] = messages[-_MAX_MESSAGES:]
            current.data = data
            current.save(update_fields=("data", "updated_at"))
    thread.data = data
    thread.updated_at = current.updated_at


def remediation_chat_reply(intent: str, plan: dict[str, object]) -> str:
    """Explain remediation only from persisted finding and graph state."""

    finding = plan.get("finding")
    finding = finding if isinstance(finding, dict) else {}
    remediation = plan.get("plan")
    remediation = remediation if isinstance(remediation, dict) else {}
    graph = plan.get("assessment_graph")
    graph = graph if isinstance(graph, dict) else {}
    state = str(remediation.get("state") or "unknown")
    chat_stage = str(graph.get("chat_stage") or "unknown")
    finding_id = str(plan.get("finding_id") or "the selected finding")

    if intent == "status":
        return (
            f"Remediation for {finding_id} is {state}. Authoritative stage: {chat_stage}. "
            "No source change, fix verification, merge or finding closure has been recorded."
        )
    if intent == "results":
        return (
            f"The exact plan targets {len(remediation.get('target_references') or [])} "
            "bounded component(s). It defines a RED security test and an independent "
            "verification recipe, but there is no implementation or fix verdict yet."
        )
    if intent == "next_step":
        if state == "ready_for_implementation":
            return (
                "A human developer must implement only the declared targets through separately "
                "controlled engineering tools. The next VulnHunter milestone will record the fixed "
                "revision and run read-only fix verification before retest or review."
            )
        if state == "cancelled":
            return (
                "The verified finding remains triaged. Create a new exact remediation plan if the "
                "issue still needs work; terminal plan authority is never reused."
            )
        return "Open the protected remediation workspace to inspect the exact plan and safe state."
    return (
        f"Remediation is tracking {finding_id}. Ask for status, plan results or the next step."
    )


__all__ = [
    "clear_remediation_plan",
    "current_remediation_plan",
    "record_remediation_event",
    "record_remediation_event_for_thread",
    "remember_remediation_workspace",
    "remediation_chat_reply",
    "remediation_create_url",
    "remediation_detail_url",
    "remediation_finding_store",
    "remediation_workspace_url",
]
