"""User-facing projection of one authoritative governed assessment state."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

_HIDDEN_EVENT_TYPES = {
    "objective_received",
    "role_selected",
    "skill_selected",
    "policy_check_started",
}
_INTERNAL_COPY = (
    "advisory reasoning abstained",
    "provider stage unavailable",
    "provider unavailable",
    "advisory stage abstained",
)
_EVENT_COPY = {
    "run_created": "Assessment created.",
    "planning_started": "Preparing the bounded passive assessment…",
    "plan_proposed": "The exact Nuclei plan is ready.",
    "approval_requested": "Waiting for confirmation of the exact passive plan.",
    "approval_granted": "Plan approved. Starting the assessment…",
    "scanner_started": "Running passive checks…",
    "scanner_progress": "Running passive checks…",
    "verification_started": "Verifying scanner observations…",
    "run_completed": "Analysis complete.",
    "run_failed": "The assessment stopped because a governed step failed.",
    "run_blocked": "The assessment stopped at a governance boundary.",
    "stop_requested": "Cancellation requested.",
}
_TERMINAL_STATES = {
    "completed",
    "failed",
    "cancelled",
    "blocked",
    "denied",
    "timed_out",
    "readiness_blocked",
    "execution_blocked",
}
_STAGE = {
    "created": (1, "Checking authorised scope…"),
    "scope_validated": (1, "Checking authorised scope…"),
    "plan_generated": (2, "Building the exact Nuclei plan…"),
    "awaiting_approval": (3, "Waiting for confirmation of the exact passive plan."),
    "queued": (4, "Approved. Waiting for the isolated scanner worker…"),
    "running": (4, "Running passive checks…"),
    "executing": (4, "Running passive checks…"),
    "evaluating": (5, "Verifying scanner observations…"),
    "completed": (6, "Analysis complete."),
}
_STAGE_TOTAL = 6


def _text(value: object) -> str:
    return str(value or "").strip()


def _parse_time(value: object) -> datetime | None:
    text = _text(value)
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(UTC)


def _elapsed_seconds(payload: dict[str, Any]) -> int:
    created = _parse_time(payload.get("created_at"))
    if created is None:
        return 0
    updated = _parse_time(payload.get("updated_at")) or datetime.now(UTC)
    if not payload.get("terminal"):
        updated = datetime.now(UTC)
    return max(0, int((updated - created).total_seconds()))


def _duration(seconds: int) -> str:
    minutes, remaining = divmod(max(0, seconds), 60)
    if minutes:
        return f"{minutes}m {remaining:02d}s"
    return f"{remaining}s"


def _event_type(event: object) -> str:
    if not isinstance(event, dict):
        return ""
    return _text(event.get("event_type") or event.get("type")).casefold()


def _event_summary(event: object) -> str:
    if not isinstance(event, dict):
        return ""
    return _text(event.get("summary") or event.get("message"))


def _is_internal_event(event: object) -> bool:
    event_type = _event_type(event)
    summary = _event_summary(event).casefold()
    return event_type in _HIDDEN_EVENT_TYPES or any(term in summary for term in _INTERNAL_COPY)


def public_events(events: list[object]) -> list[dict[str, object]]:
    projected: list[dict[str, object]] = []
    for event in events:
        if not isinstance(event, dict) or _is_internal_event(event):
            continue
        copy = dict(event)
        friendly = _EVENT_COPY.get(_event_type(event)) or _event_summary(event)
        if friendly:
            copy["summary"] = " ".join(friendly.split())[:500]
        projected.append(copy)
    return projected


def _analysis_note(events: list[object]) -> str | None:
    if any(_is_internal_event(event) for event in events):
        return (
            "The optional AI advisory stage was unavailable, so this result is based on "
            "persisted scanner evidence and deterministic verification only."
        )
    return None


def _top_finding(payload: dict[str, Any]) -> dict[str, object] | None:
    findings = payload.get("findings")
    if not isinstance(findings, list) or not findings:
        return None
    first = findings[0]
    return first if isinstance(first, dict) else None


def final_result_reply(payload: dict[str, Any]) -> str:
    state = _text(payload.get("state")).casefold()
    elapsed = _text(payload.get("elapsed_label")) or "the recorded runtime"
    reason = _text(payload.get("blocking_reason"))
    if state != "completed":
        if state == "cancelled":
            return (
                f"The assessment was cancelled after {elapsed}. No further scanner work is running."
            )
        if state in _TERMINAL_STATES:
            detail = f" {reason}" if reason else ""
            return f"The assessment stopped before completion after {elapsed}.{detail}"
        return _text(payload.get("current_step")) or "The assessment is still in progress."

    findings = payload.get("findings") if isinstance(payload.get("findings"), list) else []
    artifacts = payload.get("artifacts") if isinstance(payload.get("artifacts"), list) else []
    count = len(findings)
    if count == 0:
        copy = (
            f"Analysis complete in {elapsed}. No evidence-backed vulnerabilities were persisted "
            f"from this passive assessment. {len(artifacts)} evidence item"
            f"{' was' if len(artifacts) == 1 else 's were'} retained for review."
        )
    else:
        top = _top_finding(payload) or {}
        severity = _text(top.get("severity") or "informational").lower()
        title = _text(top.get("title") or "Evidence-backed security observation")
        label = "one issue" if count == 1 else f"{count} issues"
        copy = (
            f"Analysis complete in {elapsed}. I found {label}. The leading {severity} finding is: "
            f"{title}. Review the evidence and remediation guidance below."
        )
    note = _text(payload.get("analysis_note"))
    return f"{copy} {note}".strip()


def next_step_reply(payload: dict[str, Any]) -> str:
    state = _text(payload.get("state")).casefold()
    if payload.get("approval"):
        return (
            "Review the displayed target, port, passive templates and limits, then "
            "confirm the exact plan. No scanner traffic starts before confirmation."
        )
    if state in {"queued", "running", "executing", "evaluating"}:
        return (
            "No action is required right now. The governed assessment is still running, and I will "
            "surface the final evidence-backed result when it completes."
        )
    if state == "completed":
        findings = payload.get("findings")
        count = len(findings) if isinstance(findings, list) else 0
        if count:
            return (
                "Open the evidence, verify the affected service, apply the recommended "
                "control, then request a bounded remediation retest."
            )
        return (
            "Review the tested coverage and technical details. Expand the profile or "
            "scope only when the additional checks are explicitly authorised."
        )
    reason = _text(payload.get("blocking_reason"))
    if state in _TERMINAL_STATES:
        return f"Resolve the recorded blocking condition before retrying. {reason}".strip()
    return "Provide an authorised target so I can prepare the passive assessment plan."


def status_reply(payload: dict[str, Any]) -> str:
    step = _text(payload.get("current_step")) or "The current assessment state is available below."
    elapsed = _text(payload.get("elapsed_label"))
    progress = _text(payload.get("check_progress"))
    pieces = [step]
    if progress:
        pieces.append(progress)
    if elapsed:
        pieces.append(f"Elapsed time: {elapsed}.")
    return " ".join(pieces)


def results_reply(payload: dict[str, Any]) -> str:
    if payload.get("terminal"):
        return final_result_reply(payload)
    return (
        f"The assessment is not finished yet. {status_reply(payload)} Findings are "
        "shown only after they are persisted and verified."
    )


def contextual_chat_reply(
    text: str,
    payload: dict[str, Any] | None,
    fallback: str | None,
) -> str:
    lowered = " ".join(text.casefold().split())
    if payload:
        if re.search(r"\b(link|url|address|target)\b", lowered):
            target = _text(payload.get("target"))
            if target:
                return f"The authoritative target for the current assessment is {target}."
        if "approval" in lowered:
            if payload.get("approval"):
                return "The exact passive plan is waiting for your confirmation below."
            approval_state = _text(payload.get("approval_state")) or "not required"
            return f"The current approval state is {approval_state}."
        return (
            f"I am tracking the current assessment for {_text(payload.get('target'))}. "
            f"{_text(payload.get('current_step'))} You can ask for status, results, "
            "evidence or the next step."
        )
    return fallback or (
        "Paste an authorised http or https target. I will check scope, prepare the passive plan, "
        "pause for confirmation and report progress in this conversation."
    )


def reply_for_intent(intent: str, payload: dict[str, Any]) -> str:
    if intent == "status":
        return status_reply(payload)
    if intent == "results":
        return results_reply(payload)
    if intent == "next_step":
        return next_step_reply(payload)
    return contextual_chat_reply("", payload, None)


def enrich_run_payload(
    payload: dict[str, Any],
    *,
    raw_events: list[object],
    template_count: int = 0,
) -> dict[str, Any]:
    result = dict(payload)
    state = _text(result.get("state")).casefold()
    terminal = bool(result.get("terminal") or state in _TERMINAL_STATES)
    result["terminal"] = terminal
    result["events"] = public_events(raw_events)[-30:]
    result["analysis_note"] = _analysis_note(raw_events)
    elapsed = _elapsed_seconds(result)
    result["elapsed_seconds"] = elapsed
    result["elapsed_label"] = _duration(elapsed)

    stage_index, default_step = _STAGE.get(state, (1, "Preparing the governed assessment…"))
    if state in _TERMINAL_STATES and state != "completed":
        reason = _text(result.get("blocking_reason"))
        default_step = f"Assessment stopped: {reason}" if reason else "Assessment stopped."
        stage_index = _STAGE_TOTAL
    events = result["events"]
    latest = events[-1] if events else None
    latest_summary = _event_summary(latest) if latest else ""
    current_step = default_step
    if (
        latest_summary
        and state not in {"awaiting_approval", "completed"}
        and state not in _TERMINAL_STATES
    ):
        current_step = latest_summary
    result["current_step"] = current_step
    result["progress_label"] = f"Step {stage_index} of {_STAGE_TOTAL}"
    result["progress_percent"] = round((stage_index / _STAGE_TOTAL) * 100)

    if template_count > 0:
        if state == "completed":
            result["check_progress"] = (
                f"{template_count} of {template_count} reviewed checks completed."
            )
        elif state in {"queued", "running", "executing", "evaluating"}:
            result["check_progress"] = f"Running {template_count} reviewed passive checks."
        else:
            result["check_progress"] = f"{template_count} reviewed passive checks are planned."
    else:
        result["check_progress"] = ""
    result["next_action"] = next_step_reply(result)
    result["final_message"] = final_result_reply(result) if terminal else None
    return result
