"""Session-scoped conversational projection of one mobile hunt plan."""

from __future__ import annotations

from django.http import HttpRequest

from vulnhunter.web.assessment_projection import (
    assert_mobile_projection_invariants,
    mobile_assessment_projection,
)
from vulnhunter.web.mobile_assessment_graph import (
    bind_mobile_assessment_graph,
    refresh_mobile_assessment_graph,
)
from vulnhunter.web.mobile_execution import mobile_static_status

_SESSION_MOBILE_PLAN = "vulnhunter_conversation_mobile_plan"


def _supports_authoritative_graph(plan: dict[str, object]) -> bool:
    artifact = plan.get("artifact")
    if not isinstance(artifact, dict):
        return False
    required_plan = ("run_id", "plan_digest", "profile")
    required_artifact = ("attachment_id", "artifact_id", "artifact_sha256")
    return all(isinstance(plan.get(key), str) and plan.get(key) for key in required_plan) and all(
        isinstance(artifact.get(key), str) and artifact.get(key) for key in required_artifact
    )


def _attach_assessment_projection(plan: dict[str, object]) -> dict[str, object]:
    projection = mobile_assessment_projection(plan)
    enriched = dict(plan)
    if projection is None:
        enriched.pop("assessment", None)
        return enriched
    assert_mobile_projection_invariants(projection)
    enriched["assessment"] = projection
    return enriched


def remember_mobile_plan(request: HttpRequest, plan: dict[str, object]) -> None:
    """Persist bounded plan metadata, never APK bytes or raw tool output."""

    stored = plan
    if not isinstance(plan.get("assessment_graph"), dict) and _supports_authoritative_graph(plan):
        stored = bind_mobile_assessment_graph(request, plan=plan)
    stored = _attach_assessment_projection(stored)
    plan.clear()
    plan.update(stored)
    request.session[_SESSION_MOBILE_PLAN] = stored
    request.session.modified = True


def clear_mobile_plan(request: HttpRequest) -> None:
    request.session.pop(_SESSION_MOBILE_PLAN, None)
    request.session.modified = True


def current_mobile_plan(
    request: HttpRequest,
    *,
    requested_by: str,
) -> dict[str, object] | None:
    raw = request.session.get(_SESSION_MOBILE_PLAN)
    if not isinstance(raw, dict):
        return None
    plan = dict(raw)
    execution = plan.get("execution")
    if isinstance(execution, dict):
        job_id = execution.get("job_id")
        if isinstance(job_id, str) and job_id:
            status = mobile_static_status(
                request,
                job_id=job_id,
                requested_by=requested_by,
            )
            if status is not None:
                status_url = execution.get("status_url")
                if isinstance(status_url, str):
                    status["status_url"] = status_url
                plan["execution"] = status
    if isinstance(plan.get("assessment_graph"), dict):
        plan = refresh_mobile_assessment_graph(plan)
    plan = _attach_assessment_projection(plan)
    remember_mobile_plan(request, plan)
    return plan


def _round_summary(plan: dict[str, object]) -> str:
    raw = plan.get("rounds")
    rounds = raw if isinstance(raw, list) else []
    labels = [
        str(item.get("label")) for item in rounds if isinstance(item, dict) and item.get("label")
    ]
    if not labels:
        return "The mobile hunt has no recorded rounds."
    return "The hunt moves through: " + "; ".join(labels) + "."


def _tool_summary(plan: dict[str, object]) -> str:
    raw = plan.get("tools")
    tools = raw if isinstance(raw, list) else []
    names = [
        str(item.get("name") or item.get("tool_id")) for item in tools if isinstance(item, dict)
    ]
    execution = plan.get("execution")
    active: list[str] = []
    if isinstance(execution, dict):
        raw_active = execution.get("tools")
        if isinstance(raw_active, list):
            active = [str(item) for item in raw_active]
    planned = ", ".join(names) or "no registered tools"
    if active:
        return (
            f"The planner selected {planned}. This deployment activated the fixed read-only "
            f"worker tools: {', '.join(active)}. Other tools stay gated until their adapters "
            "and isolation requirements are ready."
        )
    return f"The planner selected {planned}. The execution worker is currently gated."


def _results_summary(plan: dict[str, object]) -> str:
    execution = plan.get("execution")
    if not isinstance(execution, dict):
        return "The APK plan exists, but no static worker execution record is attached yet."
    state = str(execution.get("state") or "prepared")
    if state in {"queued", "running"}:
        return f"The APK inspection is {state}. Findings are not final until evidence is complete."
    if state in {"gated", "blocked", "failed", "rejected"}:
        reason = str(execution.get("reason") or "The governed worker did not complete.")
        return f"The APK inspection is {state}. {reason}"
    receipt = execution.get("receipt")
    if state != "completed" or not isinstance(receipt, dict):
        return "The APK hunt is prepared, but no completed evidence receipt is available yet."
    captures = receipt.get("captures") if isinstance(receipt.get("captures"), list) else []
    observations = (
        receipt.get("candidate_observations")
        if isinstance(receipt.get("candidate_observations"), list)
        else []
    )
    if observations:
        leading = observations[0] if isinstance(observations[0], dict) else {}
        title = str(leading.get("title") or "Candidate mobile observation")
        return (
            f"Static inspection completed with {len(captures)} tool receipt(s) and "
            f"{len(observations)} candidate observation(s). The first is: {title}. "
            "These remain candidates until the judge and verifier stages establish reachability "
            "and impact."
        )
    return (
        f"Static inspection completed with {len(captures)} tool receipt(s) and no candidate "
        "observations from the activated checks."
    )


def mobile_chat_reply(
    *,
    text: str,
    intent: str,
    plan: dict[str, object],
    fallback: str | None,
) -> str:
    """Answer mobile follow-ups from authoritative plan and worker state."""

    lowered = " ".join(text.casefold().split())
    if intent == "status":
        execution = plan.get("execution")
        graph = plan.get("assessment_graph")
        graph_stage = str(graph.get("chat_stage") or "") if isinstance(graph, dict) else ""
        if isinstance(execution, dict):
            state = str(execution.get("state") or "prepared")
            reason = str(execution.get("reason") or "")
            stage_copy = f" Authoritative stage: {graph_stage}." if graph_stage else ""
            return f"The mobile hunt is {state}. {reason}{stage_copy}".strip()
        return "The mobile hunt plan is prepared; no worker state is available yet."
    if intent == "results" or any(term in lowered for term in ("finding", "evidence", "result")):
        return _results_summary(plan)
    if intent == "next_step":
        execution = plan.get("execution")
        state = (
            str(execution.get("state") or "prepared") if isinstance(execution, dict) else "prepared"
        )
        if state in {"queued", "running"}:
            return "No action is required while the networkless static worker is running."
        if state == "completed":
            return (
                "Review the candidate observations, then let the judge and deterministic verifier "
                "trace reachability and impact before confirming a vulnerability."
            )
        reason = str(execution.get("reason") or "") if isinstance(execution, dict) else ""
        return f"Activate or repair the governed static worker before retrying. {reason}".strip()
    if any(term in lowered for term in ("round", "loop", "raptor", "altitude", "stage")):
        return _round_summary(plan)
    if any(term in lowered for term in ("tool", "jadx", "apktool", "apkid", "apksigner")):
        return _tool_summary(plan)
    if any(term in lowered for term in ("dynamic", "emulator", "frida", "mobsf", "adb")):
        note = plan.get("dynamic_note")
        return str(note or "Dynamic analysis was not requested for this APK.")
    if any(term in lowered for term in ("apk", "file", "hash", "sha")):
        artifact = plan.get("artifact")
        if isinstance(artifact, dict):
            name = str(artifact.get("original_filename") or "the uploaded APK")
            digest = str(artifact.get("artifact_sha256") or "")
            return f"The selected artifact is {name}, bound to SHA-256 {digest}."
    if fallback:
        return fallback
    return (
        "I am tracking the uploaded APK and its governed hunt plan. Ask about the selected tools, "
        "hunt rounds, live status, evidence, results or the dynamic-analysis gate."
    )


__all__ = [
    "clear_mobile_plan",
    "current_mobile_plan",
    "mobile_chat_reply",
    "remember_mobile_plan",
]
