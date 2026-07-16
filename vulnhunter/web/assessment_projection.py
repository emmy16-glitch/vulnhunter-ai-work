"""Truthful presentation projection for the assessment workstream.

The browser must never invent stage progress, findings, artifacts, or verification.
This module derives the visual workflow exclusively from persisted run fields and
hash-linked backend events.
"""

from __future__ import annotations

from typing import Any


def _text(value: object | None, default: str = "") -> str:
    if value is None:
        return default
    raw = getattr(value, "value", value)
    return str(raw)


def _event_rows(run: Any) -> tuple[dict[str, object], ...]:
    rows: list[dict[str, object]] = []
    for event in getattr(run, "recent_events", ()) or ():
        if not isinstance(event, dict):
            continue
        digest = str(event.get("event_sha256") or "")
        rows.append(
            {
                "name": str(event.get("event_type") or "audit event").replace("_", " "),
                "created_at": str(event.get("created_at") or ""),
                "sha256": digest,
                "short_sha256": f"{digest[:20]}…" if digest else "Not recorded",
            }
        )
    return tuple(rows)


def _stage(
    number: int,
    title: str,
    summary: str,
    status: str,
    state: str,
    *facts: tuple[str, object],
) -> dict[str, object]:
    return {
        "number": f"{number:02d}",
        "title": title,
        "summary": summary,
        "status": status.replace("_", " ").title(),
        "state": state,
        "marker": "✓" if state == "complete" else "Ⅱ" if state == "warning" else f"{number:02d}",
        "facts": tuple(
            {"label": label, "value": _text(value, "Waiting")} for label, value in facts
        ),
    }


def build_assessment_projection(run: Any) -> dict[str, object]:
    """Build one demo-inspired but backend-authoritative assessment view model."""

    current_state = _text(getattr(run, "current_state", None), "created")
    policy_result = _text(getattr(run, "policy_result", None), "unavailable")
    approval_state = _text(getattr(run, "approval_state", None), "not_required")
    execution_state = _text(getattr(run, "execution_state", None), "not_started")
    evaluation_result = _text(getattr(run, "evaluation_result", None))
    scope_summary = _text(getattr(run, "scope_summary", None), "Scope awaiting runtime validation")
    selected_role = _text(getattr(run, "selected_role", None), "orchestrator")
    selected_skill = _text(getattr(run, "selected_skill", None), "bounded task")
    requested_tool = _text(getattr(run, "requested_tool", None))
    requested_operation = _text(getattr(run, "requested_operation", None))
    proposed_action = _text(getattr(run, "proposed_action", None))
    final_digest = _text(getattr(run, "final_event_sha256", None))
    artifacts = _event_rows(run)

    terminal_failure = current_state in {"blocked", "failed", "cancelled", "timed_out"}
    completed = current_state == "completed"
    policy_allowed = policy_result == "allowed"
    policy_denied = policy_result == "denied"
    tool_succeeded = execution_state == "tool_executed"
    tool_failed = execution_state == "tool_failed"
    approval_pending = approval_state == "pending"

    stages = (
        _stage(
            1,
            "Planning & Scope Confirmation",
            scope_summary,
            "Bound" if scope_summary else "Waiting",
            "complete",
            ("Run", getattr(run, "run_id", "")),
            ("Role", selected_role),
        ),
        _stage(
            2,
            "Authorization Validation",
            (
                "The launch request is bound to a stored authorization record; "
                "runtime checks remain authoritative."
            ),
            "Bound",
            "complete",
            ("Skill", selected_skill),
            ("Risk", getattr(run, "risk_classification", None) or "Not elevated"),
        ),
        _stage(
            3,
            "Passive Reconnaissance",
            _text(
                getattr(run, "policy_reason", None),
                "Policy evaluation has not produced a decision.",
            ),
            policy_result,
            "danger" if policy_denied else "complete" if policy_allowed else "active",
            ("Policy", policy_result),
            ("Action", proposed_action or "Not proposed"),
        ),
        _stage(
            4,
            f"Tool Invocation{f' – {requested_tool}' if requested_tool else ''}",
            requested_operation or "No governed tool operation has started.",
            "Awaiting approval" if approval_pending else execution_state,
            (
                "complete"
                if tool_succeeded or completed
                else "danger"
                if tool_failed
                else "warning"
                if approval_pending
                else "active"
            ),
            ("Tool", requested_tool or "No live tool"),
            ("Operation", requested_operation or "Not started"),
        ),
        _stage(
            5,
            "Evidence Normalization",
            (
                "Normalize tool output into hash-linked candidate evidence without "
                "copying unsafe raw exchanges."
            ),
            "Available" if artifacts and tool_succeeded else "Pending",
            (
                "complete"
                if artifacts and tool_succeeded
                else "active"
                if tool_succeeded
                else "pending"
            ),
            ("Artifacts", len(artifacts)),
            ("Integrity", "Hash linked" if final_digest else "Waiting"),
        ),
        _stage(
            6,
            "Oracle Verification",
            (
                "Independent verification remains evidence-bound and cannot be inferred "
                "from a scanner match."
            ),
            evaluation_result or "Pending",
            "complete" if evaluation_result else "pending",
            ("Result", evaluation_result or "Waiting"),
            ("Mode", "Independent"),
        ),
        _stage(
            7,
            "Findings Packaging",
            "Only reviewed findings and permitted evidence can enter a release package.",
            "Ready" if completed else "Blocked" if terminal_failure else "Pending",
            "complete" if completed else "danger" if terminal_failure else "pending",
            ("Run state", current_state),
            ("Release", "Human gated"),
        ),
    )

    complete_count = sum(stage["state"] == "complete" for stage in stages)
    progress = 100 if completed else min(94, round((complete_count / len(stages)) * 100))
    current_stage = next(
        (stage for stage in stages if stage["state"] in {"active", "warning", "danger"}),
        stages[-1],
    )

    has_candidate = bool(proposed_action and (tool_succeeded or artifacts))
    finding = {
        "status": evaluation_result or "Candidate" if has_candidate else "Awaiting evidence",
        "title": proposed_action or "No candidate findings",
        "summary": (
            _text(getattr(run, "denial_or_failure_reason", None))
            or "A scanner observation remains a candidate until independent and human review."
        ),
        "is_candidate": has_candidate and not completed,
        "is_complete": completed and bool(evaluation_result),
    }

    attack_path = (
        {"label": "Authorized scope", "state": "discovered"},
        {"label": f"Policy: {policy_result}", "state": "danger" if policy_denied else "discovered"},
        {
            "label": "Candidate evidence" if tool_succeeded else "Evidence pending",
            "state": "exploitable" if tool_succeeded else "muted",
        },
        {
            "label": "Independent review" if evaluation_result else "Review pending",
            "state": "reached" if evaluation_result else "muted",
        },
    )

    return {
        "progress": progress,
        "completed": completed,
        "terminal_failure": terminal_failure,
        "stages": stages,
        "current_stage": current_stage,
        "artifacts": artifacts,
        "artifact_count": len(artifacts),
        "finding": finding,
        "attack_path": attack_path,
        "tool": {
            "name": requested_tool or "No active tool",
            "operation": requested_operation or "Execution disabled or pending",
            "live": execution_state in {"running", "tool_running"},
        },
        "oracle": evaluation_result or "Awaiting evidence",
        "scope_status": "Bound" if scope_summary else "Not bound",
        "approval_status": approval_state,
        "run_state": current_state,
        "updated_at": _text(getattr(run, "updated_at", None)),
    }


def build_live_assessment_projection(run: Any) -> dict[str, object]:
    """Return the JSON-safe subset consumed by the assessment JavaScript."""

    projection = build_assessment_projection(run)
    return {
        "progress": projection["progress"],
        "completed": projection["completed"],
        "run_state": projection["run_state"],
        "approval_status": projection["approval_status"],
        "oracle": projection["oracle"],
        "current_stage": projection["current_stage"],
        "stages": projection["stages"],
        "artifact_count": projection["artifact_count"],
        "updated_at": projection["updated_at"],
    }
