"""Durable chat projection for one workspace-bound governed retest."""

from __future__ import annotations

from datetime import UTC, datetime
from urllib.parse import urlencode

from django.db import transaction
from django.urls import reverse

from vulnhunter.findings import Finding
from vulnhunter.web.models import ConversationThread
from vulnhunter.web.remediation_assessment_graph import project_remediation_finding
from vulnhunter.web.remediation_conversation_state import remediation_finding_store
from vulnhunter.web.retest_assessment_graph import project_retest_finding

_SESSION_RETEST = "vulnhunter_conversation_retest"
_SESSION_MESSAGES = "vulnhunter_conversation_messages"
_MAX_MESSAGES = 400


def _thread_state(request: object) -> dict[str, object] | None:
    thread = getattr(request, "vulnhunter_thread", None)
    data = getattr(thread, "data", None)
    if not isinstance(data, dict):
        return None
    raw = data.get(_SESSION_RETEST)
    return dict(raw) if isinstance(raw, dict) else None


def _write_thread_state(request: object, state: dict[str, object] | None) -> None:
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
        if state is None:
            data.pop(_SESSION_RETEST, None)
        else:
            data[_SESSION_RETEST] = state
        current.data = data
        current.save(update_fields=("data", "updated_at"))
    thread.data = data
    thread.updated_at = current.updated_at


def retest_workspace_url(workspace_id: str | None) -> str:
    base = reverse("web-dashboard")
    return f"{base}?{urlencode({'thread': workspace_id})}" if workspace_id else base


def retest_create_url(finding_id: str, workspace_id: str | None) -> str:
    base = reverse("web-retest-create", kwargs={"finding_id": finding_id})
    return f"{base}?{urlencode({'thread': workspace_id})}" if workspace_id else base


def retest_detail_url(finding_id: str, workspace_id: str | None) -> str:
    base = reverse("web-retest-detail", kwargs={"finding_id": finding_id})
    return f"{base}?{urlencode({'thread': workspace_id})}" if workspace_id else base


def _result_payload(result) -> dict[str, object]:
    return {
        "receipt_id": result.receipt_id,
        "retest_id": result.retest_id,
        "sha256": result.sha256,
        "outcome": result.outcome.value,
        "fixed_revision": result.fixed_revision,
        "created_at": result.created_at.isoformat(),
    }


def _finding_payload(
    finding: Finding,
    *,
    retest_graph: dict[str, object] | None,
    remediation_graph: dict[str, object] | None,
    workspace_id: str | None,
) -> dict[str, object]:
    if not finding.retest_plans:
        raise ValueError("the finding has no governed retest plan")
    plan = finding.retest_plans[-1]
    result = next(
        (item for item in reversed(finding.retest_results) if item.retest_id == plan.retest_id),
        None,
    )
    result_payload = _result_payload(result) if result is not None else None
    report_state = None
    if isinstance(retest_graph, dict):
        report_state = retest_graph.get("report_state")
    if report_state is None and isinstance(remediation_graph, dict):
        report_state = remediation_graph.get("report_state")
    return {
        "schema_version": "1.0",
        "finding_id": finding.finding_id,
        "retest_id": plan.retest_id,
        "run_id": plan.retest_id,
        "task_graph_id": (
            retest_graph.get("graph_id") if isinstance(retest_graph, dict) else None
        ),
        "finding": {
            "campaign_id": finding.campaign_id,
            "fingerprint": finding.fingerprint,
            "title": finding.title,
            "severity": finding.severity.value,
            "verification": finding.verification.value,
            "status": finding.status.value,
            "revision": finding.revision,
        },
        "plan": {
            "owner_id": plan.owner_id,
            "source_finding_revision": plan.source_finding_revision,
            "source_finding_fingerprint": plan.source_finding_fingerprint,
            "remediation_id": plan.remediation_id,
            "fix_verification_receipt_id": plan.fix_verification_receipt_id,
            "fixed_revision": plan.fixed_revision,
            "plan_sha256": plan.plan_sha256,
            "check_references": list(plan.check_references),
            "before_evidence_ids": list(plan.before_evidence_ids),
            "created_at": plan.created_at.isoformat(),
            "expires_at": plan.expires_at.isoformat(),
        },
        "result": result_payload,
        "assessment_graph": retest_graph,
        "remediation_graph": remediation_graph,
        "report_state": report_state,
        "create_url": retest_create_url(finding.finding_id, workspace_id),
        "detail_url": retest_detail_url(finding.finding_id, workspace_id),
        "workspace_url": retest_workspace_url(workspace_id),
    }


def remember_retest_workspace(
    *,
    owner: object,
    workspace_id: str,
    finding: Finding,
    retest_graph: dict[str, object],
    remediation_graph: dict[str, object] | None,
) -> dict[str, object]:
    with transaction.atomic():
        thread = ConversationThread.objects.select_for_update().get(
            thread_id=workspace_id,
            owner=owner,
            archived=False,
        )
        state = _finding_payload(
            finding,
            retest_graph=retest_graph,
            remediation_graph=remediation_graph,
            workspace_id=workspace_id,
        )
        data = dict(thread.data) if isinstance(thread.data, dict) else {}
        data[_SESSION_RETEST] = state
        thread.data = data
        thread.save(update_fields=("data", "updated_at"))
    record_retest_event_for_thread(thread, state)
    return state


def current_retest_plan(request: object) -> dict[str, object] | None:
    raw = _thread_state(request)
    if raw is None:
        return None
    finding_id = str(raw.get("finding_id") or "")
    retest_id = str(raw.get("retest_id") or "")
    if not finding_id or not retest_id:
        return None
    try:
        finding = remediation_finding_store().get(finding_id)
    except (OSError, RuntimeError, ValueError):
        state = dict(raw)
        state["report_state"] = "unavailable"
        _write_thread_state(request, state)
        return state
    if not any(item.retest_id == retest_id for item in finding.retest_plans):
        return None
    retest_graph = project_retest_finding(finding)
    remediation_graph = project_remediation_finding(finding)
    thread = getattr(request, "vulnhunter_thread", None)
    workspace_id = str(getattr(thread, "thread_id", "") or "") or None
    state = _finding_payload(
        finding,
        retest_graph=retest_graph,
        remediation_graph=remediation_graph,
        workspace_id=workspace_id,
    )
    _write_thread_state(request, state)
    return state


def _event_message(state: dict[str, object]) -> dict[str, object]:
    finding = state.get("finding")
    finding = finding if isinstance(finding, dict) else {}
    result = state.get("result")
    result = result if isinstance(result, dict) else {}
    graph = state.get("assessment_graph")
    graph = graph if isinstance(graph, dict) else {}
    outcome = str(result.get("outcome") or "pending")
    revision = int(finding.get("revision") or 0)
    event_key = f"retest:{state.get('retest_id')}:{outcome}:{revision}"
    if outcome == "passed":
        boundary = "Independent review is ready; report, merge, closure and release remain blocked."
    elif outcome == "cancelled":
        boundary = "The fixed finding remains ready for another separately approved retest."
    elif outcome == "pending":
        boundary = "No retest evidence or outcome has been recorded yet."
    else:
        boundary = "Independent review and reporting remain blocked until rework is completed."
    return {
        "role": "assistant",
        "kind": "status",
        "content": (
            f"Governed retest {outcome} for finding {state.get('finding_id', 'unknown')}. "
            f"Authoritative stage: {graph.get('chat_stage', 'unknown')}. {boundary}"
        ),
        "timestamp": datetime.now(UTC).isoformat(),
        "metadata": {
            "retest_event": event_key,
            "retest": {
                "retest_id": state.get("retest_id"),
                "finding_id": state.get("finding_id"),
                "outcome": outcome,
                "chat_stage": graph.get("chat_stage"),
                "report_state": state.get("report_state"),
                "task_graph_id": state.get("task_graph_id"),
                "receipt_id": result.get("receipt_id"),
                "finding_revision": revision,
            },
        },
    }


def record_retest_event(request: object, state: dict[str, object]) -> None:
    if getattr(request, "vulnhunter_thread", None) is None:
        return
    message = _event_message(state)
    event_key = message["metadata"]["retest_event"]
    raw = request.session.get(_SESSION_MESSAGES, [])
    messages = [item for item in raw if isinstance(item, dict)] if isinstance(raw, list) else []
    if any(
        isinstance(item.get("metadata"), dict)
        and item["metadata"].get("retest_event") == event_key
        for item in messages
    ):
        return
    messages.append(message)
    request.session[_SESSION_MESSAGES] = messages[-_MAX_MESSAGES:]
    request.session.modified = True


def record_retest_event_for_thread(
    thread: ConversationThread,
    state: dict[str, object],
) -> None:
    message = _event_message(state)
    event_key = message["metadata"]["retest_event"]
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
            and item["metadata"].get("retest_event") == event_key
            for item in messages
        ):
            messages.append(message)
            data[_SESSION_MESSAGES] = messages[-_MAX_MESSAGES:]
            current.data = data
            current.save(update_fields=("data", "updated_at"))
    thread.data = data
    thread.updated_at = current.updated_at


def retest_chat_reply(intent: str, state: dict[str, object]) -> str:
    finding = state.get("finding")
    finding = finding if isinstance(finding, dict) else {}
    result = state.get("result")
    result = result if isinstance(result, dict) else {}
    graph = state.get("assessment_graph")
    graph = graph if isinstance(graph, dict) else {}
    finding_id = str(state.get("finding_id") or "the selected finding")
    outcome = str(result.get("outcome") or "pending")
    chat_stage = str(graph.get("chat_stage") or "unknown")

    if intent == "status":
        return (
            f"Retest for {finding_id} is {outcome}. Authoritative stage: {chat_stage}. "
            f"Report state: {state.get('report_state', 'unknown')}."
        )
    if intent == "results":
        if not result:
            return (
                "The exact fixed revision and bounded checks are recorded, but no before/after "
                "evidence comparison receipt exists yet."
            )
        return (
            f"The immutable retest receipt {result.get('receipt_id', 'unknown')} returned "
            f"{outcome} for fixed revision {result.get('fixed_revision', 'unknown')}. "
            "This result does not merge code, close the finding or publish a report."
        )
    if intent == "next_step":
        if outcome == "pending":
            return (
                "Open the protected retest page, run only the declared checks through separately "
                "controlled tools, then submit typed before/after evidence and deterministic receipts."
            )
        if outcome == "passed":
            return (
                "The next step is independent remediation review. Reporting, merge, closure and "
                "release remain blocked until that separate authority is implemented and consumed."
            )
        if outcome == "cancelled":
            return "Start a new protected retest when the authorised test conditions are available."
        return (
            "The retest requires rework. The prior receipt remains append-only evidence; no review "
            "or report claim is allowed."
        )
    return f"VulnHunter is tracking the governed retest for {finding_id}."


__all__ = [
    "current_retest_plan",
    "record_retest_event",
    "record_retest_event_for_thread",
    "remember_retest_workspace",
    "retest_chat_reply",
    "retest_create_url",
    "retest_detail_url",
    "retest_workspace_url",
]
