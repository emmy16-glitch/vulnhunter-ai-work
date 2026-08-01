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


def remediation_verify_url(finding_id: str, workspace_id: str | None) -> str:
    base = reverse("web-remediation-verify", kwargs={"finding_id": finding_id})
    return f"{base}?{urlencode({'thread': workspace_id})}" if workspace_id else base


def remediation_review_url(finding_id: str, workspace_id: str | None) -> str:
    base = reverse("web-remediation-review", kwargs={"finding_id": finding_id})
    return f"{base}?{urlencode({'thread': workspace_id})}" if workspace_id else base


def remediation_final_report_url(finding_id: str, workspace_id: str | None) -> str:
    base = reverse("web-remediation-final-report", kwargs={"finding_id": finding_id})
    return f"{base}?{urlencode({'thread': workspace_id})}" if workspace_id else base


def _verification_payload(reference) -> dict[str, object]:
    return {
        "receipt_id": reference.receipt_id,
        "sha256": reference.sha256,
        "verdict": reference.verdict,
        "original_revision": reference.original_revision,
        "fixed_revision": reference.fixed_revision,
        "created_at": reference.created_at.isoformat(),
    }


def _review_payload(reference) -> dict[str, object]:
    return {
        "receipt_id": reference.receipt_id,
        "review_id": reference.review_id,
        "sha256": reference.sha256,
        "outcome": reference.outcome.value,
        "reviewer_id": reference.reviewer_id,
        "reviewer_identity_sha256": reference.reviewer_identity_sha256,
        "fixed_revision": reference.fixed_revision,
        "retest_receipt_id": reference.retest_receipt_id,
        "created_at": reference.created_at.isoformat(),
    }


def _report_payload(reference) -> dict[str, object]:
    return {
        "report_id": reference.report_id,
        "manifest_id": reference.manifest_id,
        "report_sha256": reference.report_sha256,
        "manifest_sha256": reference.manifest_sha256,
        "generator_id": reference.generator_id,
        "generator_identity_sha256": reference.generator_identity_sha256,
        "fixed_revision": reference.fixed_revision,
        "review_receipt_id": reference.review_receipt_id,
        "formats": list(reference.formats),
        "release_state": "unreleased",
        "created_at": reference.created_at.isoformat(),
    }


def _publication_projection(
    graph: dict[str, object] | None,
) -> tuple[str, list[dict[str, object]], dict[str, object] | None]:
    if not isinstance(graph, dict):
        return "unreleased", [], None
    raw_history = graph.get("publication_history")
    history = (
        [dict(item) for item in raw_history if isinstance(item, dict)]
        if isinstance(raw_history, list)
        else []
    )
    raw_latest = graph.get("latest_publication")
    latest = dict(raw_latest) if isinstance(raw_latest, dict) else None
    state = str(graph.get("publication_state") or "unreleased")
    return state, history, latest


def _finding_payload(
    finding: Finding,
    *,
    graph: dict[str, object] | None,
    workspace_id: str | None,
) -> dict[str, object]:
    remediation = finding.remediation
    if remediation is None or remediation.remediation_id is None:
        raise ValueError("the finding has no governed remediation plan")
    verification_history = [
        _verification_payload(item) for item in remediation.verification_history
    ]
    latest_verification = verification_history[-1] if verification_history else None
    review_history = [_review_payload(item) for item in remediation.review_history]
    latest_review = review_history[-1] if review_history else None
    report_history = [_report_payload(item) for item in remediation.report_history]
    publication_state, publication_history, latest_publication = _publication_projection(graph)
    publications_by_report: dict[str, list[dict[str, object]]] = {}
    for publication in publication_history:
        source_report_id = str(publication.get("source_report_id") or "")
        if source_report_id:
            publications_by_report.setdefault(source_report_id, []).append(publication)
    for report in report_history:
        matches = publications_by_report.get(str(report.get("report_id") or ""), [])
        if matches:
            selected = matches[-1]
            report["release_state"] = selected.get("release_state")
            report["publication_id"] = selected.get("publication_id")
            report["publication_sha256"] = selected.get("publication_sha256")
            report["publication_destination_id"] = selected.get("destination_id")
    latest_report = report_history[-1] if report_history else None
    if latest_report is not None and publication_state == "integrity_error":
        latest_report["release_state"] = "integrity_error"
    return {
        "schema_version": "1.4",
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
            "verification_history": verification_history,
            "latest_verification": latest_verification,
            "review_history": review_history,
            "latest_review": latest_review,
            "report_history": report_history,
            "latest_report": latest_report,
            "publication_state": publication_state,
            "publication_history": publication_history,
            "latest_publication": latest_publication,
            "created_at": remediation.created_at.isoformat() if remediation.created_at else None,
            "expires_at": remediation.expires_at.isoformat() if remediation.expires_at else None,
            "due_at": remediation.due_at.isoformat() if remediation.due_at else None,
            "cancellation_reason": remediation.cancellation_reason,
        },
        "assessment_graph": graph,
        "create_url": remediation_create_url(finding.finding_id, workspace_id),
        "detail_url": remediation_detail_url(finding.finding_id, workspace_id),
        "verify_url": remediation_verify_url(finding.finding_id, workspace_id),
        "review_url": remediation_review_url(finding.finding_id, workspace_id),
        "report_url": remediation_final_report_url(finding.finding_id, workspace_id),
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
    latest = remediation.get("latest_verification")
    latest = latest if isinstance(latest, dict) else {}
    latest_review = remediation.get("latest_review")
    latest_review = latest_review if isinstance(latest_review, dict) else {}
    latest_report = remediation.get("latest_report")
    latest_report = latest_report if isinstance(latest_report, dict) else {}
    latest_publication = remediation.get("latest_publication")
    latest_publication = latest_publication if isinstance(latest_publication, dict) else {}
    publication_state = str(
        remediation.get("publication_state")
        or graph.get("publication_state")
        or latest_report.get("release_state")
        or "unreleased"
    )
    publication_id = str(latest_publication.get("publication_id") or "")
    event_key = f"remediation:{remediation_id}:{state}:{revision}"
    if publication_id or publication_state not in {"unreleased", "unconfigured"}:
        event_key = f"{event_key}:{publication_state}:{publication_id or 'none'}"
    if publication_state == "published":
        boundary = (
            "The final report was separately authorised and published; finding closure, merge and "
            "deployment remain separate."
        )
    elif publication_state == "revoked":
        boundary = (
            "The publication was revoked by signed notice; retained artifacts remain audit "
            "evidence and no active release claim is made."
        )
    elif publication_state == "superseded":
        boundary = (
            "The publication was superseded by a signed correction; use the replacement record."
        )
    elif publication_state == "integrity_error":
        boundary = "Publication-state integrity verification failed, so no release claim is made."
    elif state == "ready_for_retest":
        boundary = "Fix verification passed; retest, review, merge and release remain separate."
    elif state in {"needs_rework", "review_needs_rework"}:
        boundary = "Bounded rework is required; report, merge and closure remain blocked."
    elif state == "awaiting_review":
        boundary = "The retest passed; an independent governed reviewer must decide next."
    elif state == "review_approved":
        boundary = (
            "Independent review approved report readiness; merge and closure remain separate."
        )
    elif state == "report_generated":
        boundary = (
            "The signed final report is generated but unreleased; closure and publication remain "
            "separate."
        )
    else:
        boundary = "Developer implementation, fix verification, review and merge remain separate."
    return {
        "role": "assistant",
        "kind": "status",
        "content": (
            f"Remediation plan {state} for finding {plan.get('finding_id', 'unknown')}. "
            f"Authoritative stage: {graph.get('chat_stage', 'unknown')}. {boundary}"
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
                "verification_receipt_id": latest.get("receipt_id"),
                "verification_verdict": latest.get("verdict"),
                "review_receipt_id": latest_review.get("receipt_id"),
                "review_outcome": latest_review.get("outcome"),
                "final_report_id": latest_report.get("report_id"),
                "final_report_manifest_id": latest_report.get("manifest_id"),
                "release_state": publication_state,
                "publication_id": latest_publication.get("publication_id"),
                "publication_destination_id": latest_publication.get("destination_id"),
                "report_state": graph.get("report_state"),
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
    latest = remediation.get("latest_verification")
    latest = latest if isinstance(latest, dict) else {}
    latest_review = remediation.get("latest_review")
    latest_review = latest_review if isinstance(latest_review, dict) else {}
    latest_report = remediation.get("latest_report")
    latest_report = latest_report if isinstance(latest_report, dict) else {}
    latest_publication = remediation.get("latest_publication")
    latest_publication = latest_publication if isinstance(latest_publication, dict) else {}
    publication_state = str(
        remediation.get("publication_state")
        or graph.get("publication_state")
        or latest_report.get("release_state")
        or "unreleased"
    )
    publication_destination = str(
        latest_publication.get("destination_label")
        or latest_publication.get("destination_id")
        or "the authorised destination"
    )

    if intent == "status":
        if latest_report:
            if publication_state == "published":
                return (
                    f"Remediation for {finding_id} is {state}. Final report "
                    f"{latest_report.get('report_id', 'unknown')} was separately published as "
                    f"{latest_publication.get('publication_id', 'unknown')} to "
                    f"{publication_destination}. Finding closure, merge and deployment are not "
                    "implied."
                )
            if publication_state == "revoked":
                return (
                    f"Remediation for {finding_id} is {state}. Publication "
                    f"{latest_publication.get('publication_id', 'unknown')} is revoked by signed "
                    "notice. Its retained artifacts remain audit evidence, but there is no active "
                    "release claim and the finding is not closed."
                )
            if publication_state == "superseded":
                correction = latest_publication.get("correction")
                correction = correction if isinstance(correction, dict) else {}
                return (
                    f"Remediation for {finding_id} is {state}. Publication "
                    f"{latest_publication.get('publication_id', 'unknown')} is superseded by "
                    f"{correction.get('replacement_publication_id', 'a signed replacement')}. "
                    "Finding closure, merge and deployment remain separate."
                )
            if publication_state == "integrity_error":
                return (
                    f"Remediation for {finding_id} is {state}. Final report "
                    f"{latest_report.get('report_id', 'unknown')} exists, but signed publication "
                    "state failed integrity verification. No publication claim is made."
                )
            return (
                f"Remediation for {finding_id} is {state}. Final report "
                f"{latest_report.get('report_id', 'unknown')} is generated with signed manifest "
                f"{latest_report.get('manifest_id', 'unknown')} and remains unreleased. Finding "
                "closure, release and publication are not implied."
            )
        if latest_review:
            return (
                f"Remediation for {finding_id} is {state}. Independent review returned "
                f"{latest_review.get('outcome', 'unknown')} in signed receipt "
                f"{latest_review.get('receipt_id', 'unknown')}. Report state: "
                f"{graph.get('report_state', 'unknown')}. Merge, closure and publication are not "
                "implied."
            )
        if latest:
            return (
                f"Remediation for {finding_id} is {state}. Authoritative stage: {chat_stage}. "
                f"Latest read-only verdict: {latest.get('verdict', 'unknown')} for revisions "
                f"{latest.get('original_revision', 'unknown')} → "
                f"{latest.get('fixed_revision', 'unknown')}. Retest, review and merge are not "
                "implied by this verdict."
            )
        return (
            f"Remediation for {finding_id} is {state}. Authoritative stage: {chat_stage}. "
            "No source change, fix verification, merge or finding closure has been recorded."
        )
    if intent == "results":
        if latest_report:
            if publication_state == "integrity_error":
                return (
                    f"The immutable final report is {latest_report.get('report_id', 'unknown')}, "
                    "but publication-state integrity verification failed. Its release state is "
                    "blocked and no destination claim is trusted."
                )
            publication_suffix = ""
            if latest_publication:
                publication_suffix = (
                    f" Publication {latest_publication.get('publication_id', 'unknown')} is "
                    f"{publication_state} for destination "
                    f"{latest_publication.get('destination_id', 'unknown')}."
                )
            return (
                f"The immutable final report is {latest_report.get('report_id', 'unknown')} with "
                f"manifest {latest_report.get('manifest_id', 'unknown')}. Available formats: "
                f"{', '.join(latest_report.get('formats') or []) or 'unknown'}. The release state "
                f"is {publication_state}.{publication_suffix}"
            )
        if latest_review:
            return (
                f"The signed independent review receipt is "
                f"{latest_review.get('receipt_id', 'unknown')} with outcome "
                f"{latest_review.get('outcome', 'unknown')}. It binds reviewer identity, fixed "
                "revision and passed retest, but it is not a final report, merge or closure."
            )
        if latest:
            return (
                f"The latest immutable receipt is {latest.get('receipt_id', 'unknown')} with "
                f"verdict {latest.get('verdict', 'unknown')}. It binds the fixed revision and "
                "deterministic receipts, but it is not a retest, review or merge decision."
            )
        return (
            f"The exact plan targets {len(remediation.get('target_references') or [])} "
            "bounded component(s). It defines a RED security test and an independent "
            "verification recipe, but there is no implementation or fix verdict yet."
        )
    if intent == "next_step":
        if state == "ready_for_implementation":
            return (
                "A human developer must implement only the declared targets through separately "
                "controlled engineering tools, then open the protected handoff to submit exact "
                "snapshot metadata and deterministic receipts for read-only verification."
            )
        if state == "needs_rework":
            return (
                "The developer must revise only the approved targets and submit a new exact fixed "
                "revision and fresh deterministic receipts. The prior verifier receipt remains "
                "append-only evidence."
            )
        if state == "ready_for_retest":
            return (
                "The fix verifier passed. The next milestone is a separately governed retest "
                "that preserves before-and-after evidence; review, merge and closure still "
                "require their own authority."
            )
        if state == "awaiting_review":
            return (
                "The exact passed retest is ready for an independent reviewer. Open the protected "
                "review workspace; governance authentication and checklist authority stay "
                "outside chat."
            )
        if state == "review_needs_rework":
            return (
                "The signed reviewer decision requires bounded remediation rework. The prior "
                "review "
                "receipt remains append-only and report generation stays blocked."
            )
        if state == "review_approved":
            return (
                "Independent review approved the evidence. The next milestone is governed final "
                "report generation; merge, closure, release and publication remain separate."
            )
        if state == "report_generated":
            if publication_state == "published":
                return (
                    "The report has been separately authorised and published. Any finding "
                    "closure, merge or deployment now requires its own governed evidence and "
                    "human authority."
                )
            if publication_state == "revoked":
                return (
                    "The signed publication is revoked. Prepare a corrected report and new "
                    "three-person release flow if another publication is required; retained "
                    "history must not be deleted."
                )
            if publication_state == "integrity_error":
                return (
                    "The owner must restore and verify the signed publication state before any "
                    "release, correction or revocation claim can continue."
                )
            if publication_state == "superseded":
                return (
                    "Use the signed replacement publication and preserve the superseded record. "
                    "Finding closure, merge and deployment remain separate."
                )
            return (
                "The signed report and artifact manifest are complete but unreleased. The next "
                "milestone is a dedicated human-authorised release/publication service; this "
                "report does not close the finding."
            )
        if state == "cancelled":
            return (
                "The verified finding remains triaged. This slice does not create a replacement "
                "plan, and terminal plan authority is never reused."
            )
        return "Open the protected remediation workspace to inspect the exact plan and safe state."
    return f"Remediation is tracking {finding_id}. Ask for status, plan results or the next step."


__all__ = [
    "clear_remediation_plan",
    "current_remediation_plan",
    "record_remediation_event",
    "record_remediation_event_for_thread",
    "remember_remediation_workspace",
    "remediation_chat_reply",
    "remediation_create_url",
    "remediation_detail_url",
    "remediation_final_report_url",
    "remediation_finding_store",
    "remediation_review_url",
    "remediation_verify_url",
    "remediation_workspace_url",
]
