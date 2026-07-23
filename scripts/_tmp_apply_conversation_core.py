from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def write(path: str, content: str) -> None:
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def replace_once(path: str, old: str, new: str) -> None:
    content = read(path)
    count = content.count(old)
    if count != 1:
        raise RuntimeError(f"Expected one match in {path}, found {count}: {old[:120]!r}")
    write(path, content.replace(old, new, 1))


def regex_once(path: str, pattern: str, replacement: str) -> None:
    content = read(path)
    updated, count = re.subn(pattern, replacement, content, count=1, flags=re.DOTALL)
    if count != 1:
        raise RuntimeError(f"Expected one regex match in {path}, found {count}: {pattern[:120]!r}")
    write(path, updated)


# ---------------------------------------------------------------------------
# Deterministic conversational command parsing.
# ---------------------------------------------------------------------------
replace_once(
    "vulnhunter/web/conversation_service.py",
    '''_AUTHORIZE_WORDS = (\n    "authorize",\n    "authorise",\n    "i own this target",\n    "i control this target",\n    "i am authorized",\n    "i am authorised",\n)\n_STATUS_WORDS = (\n''',
    '''_AUTHORIZE_WORDS = (\n    "authorize",\n    "authorise",\n    "i own this target",\n    "i control this target",\n    "i am authorized",\n    "i am authorised",\n)\n_APPROVE_WORDS = (\n    "confirm",\n    "approve",\n    "confirm and continue",\n    "go ahead",\n    "start the assessment",\n    "run it",\n)\n_RESULTS_WORDS = (\n    "result",\n    "results",\n    "finding",\n    "findings",\n    "evidence",\n    "vulnerability",\n    "vulnerabilities",\n    "what did you find",\n    "show me",\n)\n_NEXT_STEP_WORDS = (\n    "next step",\n    "what next",\n    "what should i do",\n    "what do i do next",\n    "next action",\n)\n_STATUS_WORDS = (\n''',
)
replace_once(
    "vulnhunter/web/conversation_service.py",
    '''    if any(_contains_term(lowered, word) for word in _AUTHORIZE_WORDS):\n        return "authorize"\n    if any(_contains_term(lowered, word) for word in _CANCEL_WORDS):\n        return "cancel"\n    if any(_contains_term(lowered, word) for word in _STATUS_WORDS):\n        return "status"\n    if any(_contains_term(lowered, word) for word in _SCAN_WORDS) or extract_target(text):\n        return "scan"\n''',
    '''    if any(_contains_term(lowered, word) for word in _AUTHORIZE_WORDS):\n        return "authorize"\n    if any(_contains_term(lowered, word) for word in _CANCEL_WORDS):\n        return "cancel"\n    if any(_contains_term(lowered, word) for word in _APPROVE_WORDS):\n        return "approve"\n    if any(_contains_term(lowered, word) for word in _STATUS_WORDS):\n        return "status"\n    if any(_contains_term(lowered, word) for word in _NEXT_STEP_WORDS):\n        return "next_step"\n    if any(_contains_term(lowered, word) for word in _RESULTS_WORDS):\n        return "results"\n    if any(_contains_term(lowered, word) for word in _SCAN_WORDS) or extract_target(text):\n        return "scan"\n''',
)
replace_once(
    "vulnhunter/web/conversation_service.py",
    '''        "keys intent, message, recommended_profile, and missing. intent must be scan, status, or "\n        "chat. Use scan only when the user is asking to assess a target, status only for progress "\n        "questions, and chat for greetings, explanations, help, links, results questions, or other "\n''',
    '''        "keys intent, message, recommended_profile, and missing. intent must be scan, status, or "\n        "chat. Deterministic commands such as approve, cancel, results and next step are handled "\n        "locally and cannot be changed by the provider. Use scan only when the user is asking to "\n        "assess a target, status only for progress questions, and chat for greetings, explanations, "\n        "help, links, or other ordinary conversation. "\n''',
)
replace_once(
    "vulnhunter/web/conversation_service.py",
    '''    elif deterministic == "status":\n        assistant_copy = (\n            "No assessment is active yet. Send an authorised target to start one, or ask what "\n            "VulnHunter can do."\n        )\n    else:\n        assistant_copy = None\n''',
    '''    elif deterministic == "status":\n        assistant_copy = (\n            "No assessment is active yet. Send an authorised target to start one, or ask what "\n            "VulnHunter can do."\n        )\n    else:\n        assistant_copy = None\n''',
)

# ---------------------------------------------------------------------------
# Pure authoritative conversation-state projection and natural replies.
# ---------------------------------------------------------------------------
write(
    "vulnhunter/web/conversation_state.py",
    '''"""User-facing projection of one authoritative governed assessment state."""\n\nfrom __future__ import annotations\n\nimport re\nfrom datetime import UTC, datetime\nfrom typing import Any\n\n\n_HIDDEN_EVENT_TYPES = {\n    "objective_received",\n    "role_selected",\n    "skill_selected",\n    "policy_check_started",\n}\n_INTERNAL_COPY = (\n    "advisory reasoning abstained",\n    "provider stage unavailable",\n    "provider unavailable",\n    "advisory stage abstained",\n)\n_EVENT_COPY = {\n    "run_created": "Assessment created.",\n    "planning_started": "Preparing the bounded passive assessment…",\n    "plan_proposed": "The exact Nuclei plan is ready.",\n    "approval_requested": "Waiting for confirmation of the exact passive plan.",\n    "approval_granted": "Plan approved. Starting the assessment…",\n    "scanner_started": "Running passive checks…",\n    "scanner_progress": "Running passive checks…",\n    "verification_started": "Verifying scanner observations…",\n    "run_completed": "Analysis complete.",\n    "run_failed": "The assessment stopped because a governed step failed.",\n    "run_blocked": "The assessment stopped at a governance boundary.",\n    "stop_requested": "Cancellation requested.",\n}\n_TERMINAL_STATES = {\n    "completed",\n    "failed",\n    "cancelled",\n    "blocked",\n    "denied",\n    "timed_out",\n    "readiness_blocked",\n    "execution_blocked",\n}\n_STAGE = {\n    "created": (1, "Checking authorised scope…"),\n    "scope_validated": (1, "Checking authorised scope…"),\n    "plan_generated": (2, "Building the exact Nuclei plan…"),\n    "awaiting_approval": (3, "Waiting for confirmation of the exact passive plan."),\n    "queued": (4, "Approved. Waiting for the isolated scanner worker…"),\n    "running": (4, "Running passive checks…"),\n    "executing": (4, "Running passive checks…"),\n    "evaluating": (5, "Verifying scanner observations…"),\n    "completed": (6, "Analysis complete."),\n}\n_STAGE_TOTAL = 6\n\n\ndef _text(value: object) -> str:\n    return str(value or "").strip()\n\n\ndef _parse_time(value: object) -> datetime | None:\n    text = _text(value)\n    if not text:\n        return None\n    try:\n        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))\n    except ValueError:\n        return None\n    if parsed.tzinfo is None or parsed.utcoffset() is None:\n        return None\n    return parsed.astimezone(UTC)\n\n\ndef _elapsed_seconds(payload: dict[str, Any]) -> int:\n    created = _parse_time(payload.get("created_at"))\n    if created is None:\n        return 0\n    updated = _parse_time(payload.get("updated_at")) or datetime.now(UTC)\n    if not payload.get("terminal"):\n        updated = datetime.now(UTC)\n    return max(0, int((updated - created).total_seconds()))\n\n\ndef _duration(seconds: int) -> str:\n    minutes, remaining = divmod(max(0, seconds), 60)\n    if minutes:\n        return f"{minutes}m {remaining:02d}s"\n    return f"{remaining}s"\n\n\ndef _event_type(event: object) -> str:\n    if not isinstance(event, dict):\n        return ""\n    return _text(event.get("event_type") or event.get("type")).casefold()\n\n\ndef _event_summary(event: object) -> str:\n    if not isinstance(event, dict):\n        return ""\n    return _text(event.get("summary") or event.get("message"))\n\n\ndef _is_internal_event(event: object) -> bool:\n    event_type = _event_type(event)\n    summary = _event_summary(event).casefold()\n    return event_type in _HIDDEN_EVENT_TYPES or any(term in summary for term in _INTERNAL_COPY)\n\n\ndef public_events(events: list[object]) -> list[dict[str, object]]:\n    projected: list[dict[str, object]] = []\n    for event in events:\n        if not isinstance(event, dict) or _is_internal_event(event):\n            continue\n        copy = dict(event)\n        friendly = _EVENT_COPY.get(_event_type(event)) or _event_summary(event)\n        if friendly:\n            copy["summary"] = " ".join(friendly.split())[:500]\n        projected.append(copy)\n    return projected\n\n\ndef _analysis_note(events: list[object]) -> str | None:\n    if any(_is_internal_event(event) for event in events):\n        return (\n            "The optional AI advisory stage was unavailable, so this result is based on "\n            "persisted scanner evidence and deterministic verification only."\n        )\n    return None\n\n\ndef _top_finding(payload: dict[str, Any]) -> dict[str, object] | None:\n    findings = payload.get("findings")\n    if not isinstance(findings, list) or not findings:\n        return None\n    first = findings[0]\n    return first if isinstance(first, dict) else None\n\n\ndef final_result_reply(payload: dict[str, Any]) -> str:\n    state = _text(payload.get("state")).casefold()\n    elapsed = _text(payload.get("elapsed_label")) or "the recorded runtime"\n    reason = _text(payload.get("blocking_reason"))\n    if state != "completed":\n        if state == "cancelled":\n            return f"The assessment was cancelled after {elapsed}. No further scanner work is running."\n        if state in _TERMINAL_STATES:\n            detail = f" {reason}" if reason else ""\n            return f"The assessment stopped before completion after {elapsed}.{detail}"\n        return _text(payload.get("current_step")) or "The assessment is still in progress."\n\n    findings = payload.get("findings") if isinstance(payload.get("findings"), list) else []\n    artifacts = payload.get("artifacts") if isinstance(payload.get("artifacts"), list) else []\n    count = len(findings)\n    if count == 0:\n        copy = (\n            f"Analysis complete in {elapsed}. No evidence-backed vulnerabilities were persisted "\n            f"from this passive assessment. {len(artifacts)} evidence item"\n            f"{' was' if len(artifacts) == 1 else 's were'} retained for review."\n        )\n    else:\n        top = _top_finding(payload) or {}\n        severity = _text(top.get("severity") or "informational").lower()\n        title = _text(top.get("title") or "Evidence-backed security observation")\n        label = "one issue" if count == 1 else f"{count} issues"\n        copy = (\n            f"Analysis complete in {elapsed}. I found {label}. The leading {severity} finding is: "\n            f"{title}. Review the evidence and remediation guidance below."\n        )\n    note = _text(payload.get("analysis_note"))\n    return f"{copy} {note}".strip()\n\n\ndef next_step_reply(payload: dict[str, Any]) -> str:\n    state = _text(payload.get("state")).casefold()\n    if payload.get("approval"):\n        return (\n            "Review the displayed target, port, passive templates and limits, then confirm the exact "\n            "plan. No scanner traffic starts before that confirmation."\n        )\n    if state in {"queued", "running", "executing", "evaluating"}:\n        return (\n            "No action is required right now. The governed assessment is still running, and I will "\n            "surface the final evidence-backed result when it completes."\n        )\n    if state == "completed":\n        findings = payload.get("findings")\n        count = len(findings) if isinstance(findings, list) else 0\n        if count:\n            return (\n                "Open the evidence, verify the affected service, apply the recommended control, then "\n                "request a bounded remediation retest."\n            )\n        return (\n            "Review the tested coverage and technical details. Expand the profile or scope only when "\n            "the additional checks are explicitly authorised."\n        )\n    reason = _text(payload.get("blocking_reason"))\n    if state in _TERMINAL_STATES:\n        return f"Resolve the recorded blocking condition before retrying. {reason}".strip()\n    return "Provide an authorised target so I can prepare the passive assessment plan."\n\n\ndef status_reply(payload: dict[str, Any]) -> str:\n    step = _text(payload.get("current_step")) or "The current assessment state is available below."\n    elapsed = _text(payload.get("elapsed_label"))\n    progress = _text(payload.get("check_progress"))\n    pieces = [step]\n    if progress:\n        pieces.append(progress)\n    if elapsed:\n        pieces.append(f"Elapsed time: {elapsed}.")\n    return " ".join(pieces)\n\n\ndef results_reply(payload: dict[str, Any]) -> str:\n    if payload.get("terminal"):\n        return final_result_reply(payload)\n    return (\n        f"The assessment is not finished yet. {status_reply(payload)} Findings are shown only after "\n        "they are persisted and verified."\n    )\n\n\ndef contextual_chat_reply(\n    text: str,\n    payload: dict[str, Any] | None,\n    fallback: str | None,\n) -> str:\n    lowered = " ".join(text.casefold().split())\n    if payload:\n        if re.search(r"\\b(link|url|address|target)\\b", lowered):\n            target = _text(payload.get("target"))\n            if target:\n                return f"The authoritative target for the current assessment is {target}."\n        if "approval" in lowered:\n            if payload.get("approval"):\n                return "The exact passive plan is waiting for your confirmation below."\n            return f"The current approval state is {_text(payload.get('approval_state')) or 'not required'}."\n        return (\n            f"I am tracking the current assessment for {_text(payload.get('target'))}. "\n            f"{_text(payload.get('current_step'))} You can ask for status, results, evidence or the "\n            "next step."\n        )\n    return fallback or (\n        "Paste an authorised http or https target. I will check scope, prepare the passive plan, "\n        "pause for confirmation and report progress in this conversation."\n    )\n\n\ndef reply_for_intent(intent: str, payload: dict[str, Any]) -> str:\n    if intent == "status":\n        return status_reply(payload)\n    if intent == "results":\n        return results_reply(payload)\n    if intent == "next_step":\n        return next_step_reply(payload)\n    return contextual_chat_reply("", payload, None)\n\n\ndef enrich_run_payload(\n    payload: dict[str, Any],\n    *,\n    raw_events: list[object],\n    template_count: int = 0,\n) -> dict[str, Any]:\n    result = dict(payload)\n    state = _text(result.get("state")).casefold()\n    terminal = bool(result.get("terminal") or state in _TERMINAL_STATES)\n    result["terminal"] = terminal\n    result["events"] = public_events(raw_events)[-30:]\n    result["analysis_note"] = _analysis_note(raw_events)\n    elapsed = _elapsed_seconds(result)\n    result["elapsed_seconds"] = elapsed\n    result["elapsed_label"] = _duration(elapsed)\n\n    stage_index, default_step = _STAGE.get(state, (1, "Preparing the governed assessment…"))\n    if state in _TERMINAL_STATES and state != "completed":\n        reason = _text(result.get("blocking_reason"))\n        default_step = f"Assessment stopped: {reason}" if reason else "Assessment stopped."\n        stage_index = _STAGE_TOTAL\n    events = result["events"]\n    latest = events[-1] if events else None\n    latest_summary = _event_summary(latest) if latest else ""\n    current_step = default_step\n    if latest_summary and state not in {"awaiting_approval", "completed"} and state not in _TERMINAL_STATES:\n        current_step = latest_summary\n    result["current_step"] = current_step\n    result["progress_label"] = f"Step {stage_index} of {_STAGE_TOTAL}"\n    result["progress_percent"] = round((stage_index / _STAGE_TOTAL) * 100)\n\n    if template_count > 0:\n        if state == "completed":\n            result["check_progress"] = (\n                f"{template_count} of {template_count} reviewed checks completed."\n            )\n        elif state in {"queued", "running", "executing", "evaluating"}:\n            result["check_progress"] = f"Running {template_count} reviewed passive checks."\n        else:\n            result["check_progress"] = f"{template_count} reviewed passive checks are planned."\n    else:\n        result["check_progress"] = ""\n    result["next_action"] = next_step_reply(result)\n    result["final_message"] = final_result_reply(result) if terminal else None\n    return result\n''',
)

# ---------------------------------------------------------------------------
# Server-owned authoritative conversation state and deterministic commands.
# ---------------------------------------------------------------------------
replace_once(
    "vulnhunter/web/conversational_views.py",
    "from vulnhunter.approvals.store import ApprovalStoreError\n",
    "from vulnhunter.approvals.store import ApprovalConflictError, ApprovalStoreError\n",
)
replace_once(
    "vulnhunter/web/conversational_views.py",
    '''from vulnhunter.web.conversation_service import (\n    canonical_target,\n    groq_runtime_status,\n    interpret_request,\n)\n''',
    '''from vulnhunter.web.conversation_service import (\n    canonical_target,\n    groq_runtime_status,\n    interpret_request,\n)\nfrom vulnhunter.web.conversation_state import (\n    contextual_chat_reply,\n    enrich_run_payload,\n    reply_for_intent,\n    results_reply,\n    status_reply,\n)\n''',
)
replace_once(
    "vulnhunter/web/conversational_views.py",
    "from vulnhunter.web.services import (\n",
    "from vulnhunter.web.inline_confirmation_store import InlineConfirmationStore\nfrom vulnhunter.web.services import (\n",
)
replace_once(
    "vulnhunter/web/conversational_views.py",
    '''def _append_message(\n''',
    '''def _normalize_message_copy(content: str) -> str:\n    lines = [" ".join(line.split()) for line in content.splitlines()]\n    return "\\n".join(line for line in lines if line).strip()\n\n\ndef _append_message(\n''',
)
replace_once(
    "vulnhunter/web/conversational_views.py",
    '        "content": " ".join(content.split()),\n',
    '        "content": _normalize_message_copy(content),\n',
)
replace_once(
    "vulnhunter/web/conversational_views.py",
    '''def _enum_value(value: object) -> str:\n''',
    '''def _confirmation_store() -> InlineConfirmationStore:\n    store = InlineConfirmationStore(Path(settings.VULNHUNTER_APPROVAL_DATABASE))\n    store.initialize()\n    return store\n\n\ndef _latest_visible_run(actor: object, target: str | None = None):\n    try:\n        summaries = list(product_service().list_agent_runs())\n    except ProductServiceError:\n        return None\n    summaries.sort(key=lambda item: item.updated_at, reverse=True)\n    canonical = canonical_target(target) if target else None\n    for summary in summaries:\n        if not run_visible_to_actor(summary, actor):\n            continue\n        try:\n            detail = product_service().get_agent_run(str(summary.run_id))\n        except ProductServiceError:\n            continue\n        if canonical:\n            detail_target = canonical_target(\n                str(getattr(detail, "scope_summary", None) or getattr(detail, "objective", ""))\n            )\n            if detail_target != canonical:\n                continue\n        return detail\n    return None\n\n\ndef _authoritative_run(\n    state: dict[str, object],\n    actor: object,\n    *,\n    target: str | None = None,\n):\n    run_id = state.get("run_id")\n    if isinstance(run_id, str) and run_id:\n        try:\n            current = _visible_run(run_id, actor)\n        except Http404:\n            current = None\n        if current is not None:\n            if not target:\n                return current\n            current_target = canonical_target(\n                str(getattr(current, "scope_summary", None) or getattr(current, "objective", ""))\n            )\n            if current_target == canonical_target(target):\n                return current\n    return _latest_visible_run(actor, target=target)\n\n\ndef _sync_state_from_run(\n    request: HttpRequest,\n    state: dict[str, object],\n    run: object,\n) -> dict[str, object]:\n    updated = dict(state)\n    updated["run_id"] = str(run.run_id)\n    target = str(getattr(run, "scope_summary", None) or getattr(run, "objective", ""))\n    if canonical_target(target):\n        updated["target"] = canonical_target(target)\n    profile = str(getattr(run, "risk_classification", "") or "")\n    if profile:\n        updated["profile"] = profile\n    authorization_id = getattr(run, "authorization_id", None)\n    if authorization_id:\n        updated["authorization_id"] = str(authorization_id)\n    _save_state(request, updated)\n    return updated\n\n\ndef _confirm_active_run(\n    run: object,\n    *,\n    actor_id: str,\n    reason: str,\n    request_id: str | None = None,\n    submitted_plan_digest: str | None = None,\n):\n    pending = _pending_for_run(str(run.run_id))\n    if pending is None:\n        raise ApprovalConflictError("No current exact passive plan is waiting for confirmation.")\n    if request_id and pending.request_id != request_id:\n        raise ApprovalConflictError("The displayed confirmation request is stale.")\n    command_plan = getattr(run, "command_plan_summary", {})\n    plan = command_plan if isinstance(command_plan, Mapping) else {}\n    profile = str(plan.get("exact_profile") or "")\n    authoritative_digest = str(plan.get("plan_digest") or "")\n    if profile != "passive":\n        raise ApprovalConflictError(\n            "Inline confirmation is limited to the reviewed passive profile."\n        )\n    if not authoritative_digest:\n        raise ApprovalConflictError("The authoritative command-plan digest is unavailable.")\n    if submitted_plan_digest and submitted_plan_digest != authoritative_digest:\n        raise ApprovalConflictError("The displayed command plan is stale or has been modified.")\n    workflow = AssessmentWorkflowService.from_settings()\n    workflow.validate_approval_binding(\n        request=pending,\n        submitted_plan_digest=authoritative_digest,\n    )\n    confirmed = _confirmation_store().confirm_exact_passive_plan(\n        request_id=pending.request_id,\n        actor_id=actor_id,\n        action_manifest_sha256=authoritative_digest,\n        profile=profile,\n        reason=reason,\n    )\n    workflow.record_approval_decision(request=confirmed, actor_id=actor_id)\n    return product_service().get_agent_run(str(run.run_id))\n\n\ndef _repeat_scan_requested(text: str) -> bool:\n    lowered = " ".join(text.casefold().split())\n    return any(term in lowered for term in ("scan again", "run again", "rescan", "re-scan"))\n\n\ndef _enum_value(value: object) -> str:\n''',
)
regex_once(
    "vulnhunter/web/conversational_views.py",
    r"def _run_payload\(run: object\) -> dict\[str, object\]:.*?\n\n\ndef _visible_run",
    '''def _run_payload(run: object) -> dict[str, object]:\n    run_id = str(run.run_id)\n    try:\n        timeline = activity_payload(run_id, after_sequence=0)\n    except (OSError, ProductServiceError, RuntimeError, ValueError):\n        timeline = {"events": [], "terminal": False, "last_sequence": 0}\n    raw_events = timeline.get("events", []) if isinstance(timeline, dict) else []\n    if not isinstance(raw_events, list):\n        raw_events = []\n    findings = tuple(getattr(run, "findings", ()) or ())\n    artifacts = tuple(getattr(run, "artifacts", ()) or ())\n    current_state = str(\n        getattr(run, "workflow_state", None) or getattr(run, "current_state", "unknown")\n    )\n    terminal = current_state in {\n        "completed",\n        "failed",\n        "cancelled",\n        "blocked",\n        "denied",\n        "timed_out",\n        "readiness_blocked",\n        "execution_blocked",\n    }\n    command_plan = getattr(run, "command_plan_summary", {})\n    plan = command_plan if isinstance(command_plan, Mapping) else {}\n    template_hashes = plan.get("template_manifest_hashes", ())\n    if not isinstance(template_hashes, (list, tuple)):\n        template_hashes = ()\n    payload: dict[str, object] = {\n        "run_id": run_id,\n        "state": current_state,\n        "task_state": str(getattr(run, "current_state", current_state)),\n        "approval_state": _enum_value(getattr(run, "approval_state", "not_required")),\n        "execution_state": str(getattr(run, "execution_state", "not_started")),\n        "target": str(getattr(run, "scope_summary", getattr(run, "objective", ""))),\n        "profile": str(getattr(run, "risk_classification", "passive")),\n        "scanner": str(getattr(run, "requested_tool", "nuclei")),\n        "created_at": run.created_at.isoformat(),\n        "updated_at": run.updated_at.isoformat(),\n        "terminal": terminal,\n        "blocking_reason": getattr(run, "execution_blocking_reason", None),\n        "evaluation_result": getattr(run, "evaluation_result", None),\n        "findings": [_safe_finding(item) for item in findings],\n        "artifacts": [_safe_artifact(item) for item in artifacts],\n        "last_sequence": (\n            timeline.get("last_sequence", 0) if isinstance(timeline, dict) else 0\n        ),\n        "approval": _approval_payload(run),\n        "detail_url": reverse("web-scan-run-detail", kwargs={"run_id": run_id}),\n        "findings_url": reverse("web-findings-overview"),\n    }\n    return enrich_run_payload(\n        payload,\n        raw_events=raw_events,\n        template_count=len(template_hashes),\n    )\n\n\ndef _visible_run''',
)
replace_once(
    "vulnhunter/web/conversational_views.py",
    '''def _recent_runs(actor: object) -> tuple[dict[str, object], ...]:\n    try:\n        runs = product_service().list_agent_runs()\n    except ProductServiceError:\n        return ()\n    visible = [run for run in runs if run_visible_to_actor(run, actor)]\n    visible.sort(key=lambda item: item.updated_at, reverse=True)\n    return tuple(_run_payload(run) for run in visible[:12])\n''',
    '''def _recent_runs(actor: object) -> tuple[dict[str, object], ...]:\n    try:\n        runs = product_service().list_agent_runs()\n    except ProductServiceError:\n        return ()\n    visible = [run for run in runs if run_visible_to_actor(run, actor)]\n    visible.sort(key=lambda item: item.updated_at, reverse=True)\n    details: list[dict[str, object]] = []\n    for summary in visible[:12]:\n        try:\n            details.append(_run_payload(product_service().get_agent_run(str(summary.run_id))))\n        except ProductServiceError:\n            continue\n    return tuple(details)\n''',
)
replace_once(
    "vulnhunter/web/conversational_views.py",
    '''    state = _state(request)\n    active_run = None\n    run_id = state.get("run_id")\n    if isinstance(run_id, str) and run_id:\n        try:\n            active_run = _run_payload(_visible_run(run_id, actor))\n        except Http404:\n            state.pop("run_id", None)\n            _save_state(request, state)\n''',
    '''    state = _state(request)\n    authoritative = _authoritative_run(state, actor)\n    active_run = _run_payload(authoritative) if authoritative is not None else None\n    if authoritative is not None:\n        state = _sync_state_from_run(request, state, authoritative)\n''',
)

new_message_view = r'''@cache_control(private=True, no_store=True)
@login_required
@require_POST
def message_view(request: HttpRequest) -> JsonResponse:
    try:
        actor = _actor(request, "scan.create")
    except WebPermissionDenied as exc:
        return JsonResponse({"detail": str(exc)}, status=403)
    text = request.POST.get("message", "").strip()
    if not text or len(text) > 4_000:
        return JsonResponse(
            {"detail": "Enter a message between 1 and 4,000 characters."},
            status=400,
        )

    _append_message(request, role="user", content=text)
    state = _state(request)
    workflow = AssessmentWorkflowService.from_settings()
    try:
        choices = workflow.list_authorizations(
            identity_id=actor.governance_identity.reviewer_id,
            username=request.user.get_username(),
        )
    except (OSError, RuntimeError, ValueError) as exc:
        message = _append_message(
            request,
            role="assistant",
            kind="error",
            content=f"The authorization service is unavailable: {exc}",
        )
        return JsonResponse({"message": message}, status=503)

    profiles = tuple(sorted({profile for item in choices for profile in item.approved_profiles}))
    context = tuple(
        (str(item.get("role", "")), str(item.get("content", "")))
        for item in _messages(request)[-8:]
        if isinstance(item, dict)
    )
    interpreted = interpret_request(
        text,
        available_profiles=profiles,
        conversation_context=context,
    )
    stored_target = state.get("target")
    target_hint = _target_for_request(
        intent=interpreted.intent,
        interpreted_target=interpreted.target,
        stored_target=stored_target,
    )
    active = _authoritative_run(
        state,
        actor,
        target=target_hint if interpreted.intent in {"scan", "authorize"} else None,
    )
    active_payload = _run_payload(active) if active is not None else None
    if active is not None:
        state = _sync_state_from_run(request, state, active)

    if interpreted.intent in {"status", "results", "next_step"}:
        if active_payload is None:
            copy = (
                "No assessment is active yet. Paste an authorised http or https target to prepare "
                "a passive plan."
            )
            message = _append_message(request, role="assistant", kind="status", content=copy)
            return JsonResponse({"message": message})
        message = _append_message(
            request,
            role="assistant",
            kind="result" if interpreted.intent == "results" else "status",
            content=reply_for_intent(interpreted.intent, active_payload),
            metadata={"run_id": active_payload["run_id"]},
        )
        return JsonResponse({"message": message, "run": active_payload})

    if interpreted.intent == "approve":
        if active is None or active_payload is None:
            message = _append_message(
                request,
                role="assistant",
                kind="question",
                content="There is no active plan waiting for confirmation.",
            )
            return JsonResponse({"message": message})
        if active_payload.get("terminal"):
            message = _append_message(
                request,
                role="assistant",
                kind="result",
                content=results_reply(active_payload),
            )
            return JsonResponse({"message": message, "run": active_payload})
        try:
            refreshed = _confirm_active_run(
                active,
                actor_id=actor.governance_identity.reviewer_id,
                reason="Confirmed in the conversation for this exact authorised passive plan.",
            )
        except (ApprovalConflictError, ApprovalStoreError, AssessmentWorkflowError) as exc:
            message = _append_message(
                request,
                role="assistant",
                kind="error",
                content=str(exc),
            )
            return JsonResponse({"message": message}, status=409)
        state = _sync_state_from_run(request, state, refreshed)
        payload = _run_payload(refreshed)
        copy = (
            "Approved. Starting the governed assessment now. The compact live status below will "
            "update as the scanner and verification stages progress."
        )
        message = _append_message(
            request,
            role="assistant",
            kind="status",
            content=copy,
            metadata={"run_id": payload["run_id"]},
        )
        return JsonResponse({"message": message, "run": payload})

    if interpreted.intent == "cancel":
        if active is None or active_payload is None:
            message = _append_message(
                request,
                role="assistant",
                kind="status",
                content="There is no active assessment to cancel.",
            )
            return JsonResponse({"message": message})
        if active_payload.get("terminal"):
            message = _append_message(
                request,
                role="assistant",
                kind="status",
                content="That assessment is already finished, so there is no running work to cancel.",
            )
            return JsonResponse({"message": message, "run": active_payload})
        try:
            stop_agent_run(
                request.user,
                run_id=str(active.run_id),
                reason="Cancelled from chat workspace",
            )
        except WebCapabilityUnavailable as exc:
            message = _append_message(
                request,
                role="assistant",
                kind="error",
                content=str(exc),
            )
            return JsonResponse({"message": message}, status=409)
        refreshed = _visible_run(str(active.run_id), actor)
        payload = _run_payload(refreshed)
        message = _append_message(
            request,
            role="assistant",
            kind="status",
            content="Cancellation requested. No additional scanner work will be started.",
        )
        return JsonResponse({"message": message, "run": payload})

    if interpreted.intent not in {"scan", "authorize"}:
        message = _append_message(
            request,
            role="assistant",
            content=contextual_chat_reply(
                text,
                active_payload,
                interpreted.assistant_copy,
            ),
            metadata={"provider": interpreted.provider},
        )
        response: dict[str, object] = {"message": message}
        if active_payload is not None:
            response["run"] = active_payload
        return JsonResponse(response)

    target = target_hint
    if target is None:
        suggestions = [item.approved_targets[0] for item in choices if item.approved_targets]
        message = _append_message(
            request,
            role="assistant",
            kind="question",
            content=(
                "Paste the full http or https target. I will identify the path and port, check "
                "authorization and prepare the passive plan."
            ),
            metadata={
                "suggestions": [
                    {"label": value, "message": f"Scan {value} using the passive profile"}
                    for value in suggestions[:4]
                ]
            },
        )
        return JsonResponse({"message": message})

    canonical = canonical_target(target)
    if not canonical:
        message = _append_message(
            request,
            role="assistant",
            kind="error",
            content="That target is not a valid http or https URL.",
        )
        return JsonResponse({"message": message}, status=400)

    existing = _latest_visible_run(actor, target=canonical)
    if existing is not None and not _repeat_scan_requested(text) and interpreted.intent == "scan":
        payload = _run_payload(existing)
        state = _sync_state_from_run(request, state, existing)
        if payload.get("terminal"):
            copy = (
                f"A completed assessment already exists for {canonical}. {results_reply(payload)} "
                "Say ‘scan again’ only when you intentionally want a new authorised run."
            )
            kind = "result"
        else:
            copy = (
                f"The assessment for {canonical} is already active. {status_reply(payload)}"
            )
            kind = "status"
        message = _append_message(
            request,
            role="assistant",
            kind=kind,
            content=copy,
            metadata={
                "suggestions": [
                    {"label": "Show results", "message": "Show me the results"},
                    {"label": "Scan again", "message": f"Scan {canonical} again"},
                ]
            },
        )
        return JsonResponse({"message": message, "run": payload})

    matched = None
    for item in choices:
        if any(canonical_target(value) == canonical for value in item.approved_targets):
            matched = item
            break

    if matched is None and interpreted.intent == "authorize":
        try:
            _actor(request, "scan.create", "authorization.create")
            prepare_conversational_authorization(
                target_url=canonical,
                evidence_reference=interpreted.evidence_reference,
                identity_id=actor.governance_identity.reviewer_id,
                username=request.user.get_username(),
            )
            choices = workflow.list_authorizations(
                identity_id=actor.governance_identity.reviewer_id,
                username=request.user.get_username(),
            )
        except WebPermissionDenied as exc:
            message = _append_message(request, role="assistant", kind="error", content=str(exc))
            return JsonResponse({"message": message}, status=403)
        except (ConversationalAuthorizationError, OSError, RuntimeError, ValueError) as exc:
            state.update({"target": canonical, "profile": interpreted.profile or "passive"})
            _save_state(request, state)
            message = _append_message(
                request,
                role="assistant",
                kind="authorization_required",
                content=str(exc),
                metadata={
                    "suggestions": [
                        {
                            "label": "Add authorization evidence",
                            "message": (
                                "Authorize this target. Evidence: "
                                "<contract, ticket, or bug-bounty scope reference>"
                            ),
                        }
                    ]
                },
            )
            return JsonResponse({"message": message})
        for item in choices:
            if any(canonical_target(value) == canonical for value in item.approved_targets):
                matched = item
                break

    if matched is None:
        parsed_target = urlsplit(canonical)
        requested_port = parsed_target.port or (443 if parsed_target.scheme == "https" else 80)
        state.update({"target": canonical, "profile": interpreted.profile or "passive"})
        _save_state(request, state)
        message = _append_message(
            request,
            role="assistant",
            kind="authorization_required",
            content=(
                f"I recognised {canonical} on port {requested_port}, but no active authorization "
                "covers that exact URL and port. Authorize it in this conversation to continue. "
                "Public websites require a contract, ticket or bug-bounty scope reference."
            ),
            metadata={
                "suggestions": [
                    {
                        "label": "Authorize this target",
                        "message": (
                            "Authorize this target. Evidence: "
                            "<contract, ticket, or bug-bounty scope reference>"
                        ),
                    }
                ],
                "target": canonical,
                "port": requested_port,
            },
        )
        return JsonResponse({"message": message})

    stored_profile = state.get("profile")
    profile = interpreted.profile or (stored_profile if isinstance(stored_profile, str) else None)
    if profile not in matched.approved_profiles:
        profile = "passive" if "passive" in matched.approved_profiles else None
    if profile is None:
        message = _append_message(
            request,
            role="assistant",
            kind="question",
            content="Which authorised assessment profile should I use? Passive is recommended first.",
            metadata={
                "suggestions": [
                    {"label": value.title(), "message": f"Use the {value} profile for {canonical}"}
                    for value in matched.approved_profiles
                ]
            },
        )
        state.update({"target": canonical, "authorization_id": matched.authorization_id})
        _save_state(request, state)
        return JsonResponse({"message": message})

    parsed = urlsplit(canonical)
    protocol = parsed.scheme
    port = interpreted.port or parsed.port or (443 if parsed.scheme == "https" else 80)
    if protocol not in matched.approved_protocols or port not in matched.approved_ports:
        message = _append_message(
            request,
            role="assistant",
            kind="authorization_required",
            content=(
                f"Port {port} is valid for HTTP/HTTPS, but the current authorization does not "
                "include it. Authorize the exact URL and port before continuing."
            ),
        )
        return JsonResponse({"message": message})

    try:
        result = workflow.create_assessment(
            authorization_id=matched.authorization_id,
            target=canonical,
            protocol=protocol,
            port=port,
            profile=profile,
            identity_id=actor.governance_identity.reviewer_id,
            username=request.user.get_username(),
        )
    except (AssessmentWorkflowError, OSError, RuntimeError, ValueError) as exc:
        message = _append_message(
            request,
            role="assistant",
            kind="error",
            content=str(exc),
        )
        return JsonResponse({"message": message}, status=409)

    run = product_service().get_agent_run(result.task.task_id)
    state = {
        "run_id": result.task.task_id,
        "target": canonical,
        "profile": profile,
        "authorization_id": matched.authorization_id,
    }
    _save_state(request, state)
    message = _append_message(
        request,
        role="assistant",
        kind="plan",
        content=(
            f"I found the active authorised target:\n{canonical}\n\n"
            "Checking authorisation… completed.\n"
            "Building the exact passive Nuclei plan… completed.\n\n"
            "Review and confirm the plan below. No scanner traffic starts before confirmation."
        ),
        metadata={"run_id": result.task.task_id},
    )
    return JsonResponse({"message": message, "run": _run_payload(run)}, status=201)
'''
regex_once(
    "vulnhunter/web/conversational_views.py",
    r"@cache_control\(private=True, no_store=True\)\n@login_required\n@require_POST\ndef message_view\(request: HttpRequest\) -> JsonResponse:.*?\n\n\n@cache_control\(private=True, no_store=True\)\n@login_required\n@require_GET\ndef status_view",
    new_message_view
    + "\n\n\n@cache_control(private=True, no_store=True)\n@login_required\n@require_GET\ndef status_view",
)

# Use the same authoritative confirmation helper for the button endpoint.
replace_once(
    "vulnhunter/web/conversation_approval_views.py",
    '''from vulnhunter.web.conversational_views import (\n    _actor,\n    _append_message,\n    _run_payload,\n    _visible_run,\n)\n''',
    '''from vulnhunter.web.conversational_views import (\n    _actor,\n    _append_message,\n    _confirm_active_run,\n    _run_payload,\n    _visible_run,\n)\n''',
)
regex_once(
    "vulnhunter/web/conversation_approval_views.py",
    r"    identity_id = actor\.governance_identity\.reviewer_id\n    try:.*?\n    message = _append_message\(",
    '''    identity_id = actor.governance_identity.reviewer_id\n    try:\n        store = _confirmation_store()\n        pending = store.get(request_id)\n        run = _visible_run(pending.run_id, actor)\n        refreshed = _confirm_active_run(\n            run,\n            actor_id=identity_id,\n            reason=reason,\n            request_id=request_id,\n            submitted_plan_digest=plan_digest,\n        )\n    except ApprovalNotFoundError as exc:\n        return JsonResponse({"detail": str(exc)}, status=404)\n    except (ApprovalStoreError, AssessmentWorkflowError) as exc:\n        return JsonResponse({"detail": str(exc)}, status=409)\n\n    message = _append_message(''',
)

# ---------------------------------------------------------------------------
# Compact live renderer. All conversational answers now come from the server.
# ---------------------------------------------------------------------------
regex_once(
    "vulnhunter/web/static/web/conversation.js",
    r"  const renderStages = \(card, run\) => \{.*?\n  \};\n\n  const renderSummary",
    '''  const renderStages = (card, run) => {\n    const track = card.querySelector("[data-run-stages]");\n    track.replaceChildren();\n    const row = document.createElement("div");\n    row.className = `vh-run-stage-current ${run.terminal ? "is-complete" : "is-active"}`;\n    const marker = document.createElement("span");\n    marker.className = "vh-run-stage-marker";\n    marker.textContent = run.terminal ? "✓" : "•";\n    const body = document.createElement("div");\n    const eyebrow = document.createElement("small");\n    eyebrow.textContent = text(run.progress_label || "Assessment progress");\n    const strong = document.createElement("strong");\n    strong.textContent = text(run.current_step || "Preparing the governed assessment…");\n    const paragraph = document.createElement("p");\n    paragraph.textContent = text(run.check_progress || run.next_action || "");\n    body.append(eyebrow, strong, paragraph);\n    const duration = document.createElement("time");\n    duration.dataset.runStageElapsed = "true";\n    duration.textContent = text(run.elapsed_label || formatDuration(elapsedFrom(run.created_at)));\n    row.append(marker, body, duration);\n    const meter = document.createElement("div");\n    meter.className = "vh-run-progress-meter";\n    const fill = document.createElement("span");\n    fill.style.width = `${Math.max(4, Number(run.progress_percent || 0))}%`;\n    meter.append(fill);\n    track.append(row, meter);\n  };\n\n  const renderSummary''',
)
replace_once(
    "vulnhunter/web/static/web/conversation.js",
    '''    } else if (run.terminal) {\n      container.append(emptyBlock("No independent result recorded", "Review the assessment activity and saved evidence."));\n    }\n''',
    '''    } else if (run.analysis_note) {\n      container.append(emptyBlock("Deterministic evidence summary", run.analysis_note));\n    } else if (run.terminal) {\n      container.append(emptyBlock("Verification complete", "Review the persisted findings and evidence."));\n    }\n''',
)
replace_once(
    "vulnhunter/web/static/web/conversation.js",
    '''    const rules = {\n      summary: Boolean(run.terminal),\n      progress: events.length > 0,\n      findings: findings.length > 0 || Boolean(run.terminal),\n      evidence: artifacts.length > 0,\n      verification: Boolean(run.evaluation_result) || Boolean(run.terminal),\n      guidance: findings.length > 0,\n      technical: true,\n    };\n''',
    '''    const rules = {\n      summary: Boolean(run.terminal),\n      progress: false,\n      findings: findings.length > 0 || Boolean(run.terminal),\n      evidence: artifacts.length > 0,\n      verification: Boolean(run.evaluation_result) || Boolean(run.analysis_note),\n      guidance: findings.length > 0,\n      technical: true,\n    };\n''',
)
replace_once(
    "vulnhunter/web/static/web/conversation.js",
    '''      blocking_reason: run.blocking_reason,\n      terminal: run.terminal,\n''',
    '''      blocking_reason: run.blocking_reason,\n      current_step: run.current_step,\n      final_message: run.final_message,\n      terminal: run.terminal,\n''',
)
regex_once(
    "vulnhunter/web/static/web/conversation.js",
    r"  const announceRunProgress = \(previous, next\) => \{.*?\n  \};",
    '''  const announceRunProgress = (previous, next) => {\n    const previousState = text(previous?.state);\n    const nextState = text(next?.state);\n    if (previousState === nextState && !next.terminal) return;\n    const key = `${text(next.run_id)}:${nextState}:${next.terminal ? "terminal" : "live"}`;\n    if (announcedEvents.has(key)) return;\n    announcedEvents.add(key);\n    const copy = next.terminal ? next.final_message : next.current_step;\n    if (!copy) return;\n    appendMessage(\n      {\n        role: "assistant",\n        kind: next.terminal ? "result" : "status",\n        content: copy,\n        timestamp: next.updated_at || new Date().toISOString(),\n      },\n      { animate: true, forceScroll: false },\n    );\n  };''',
)
regex_once(
    "vulnhunter/web/static/web/conversation.js",
    r"  const contextualReply = \(value\) => \{.*?\n  const openHistory",
    '''  const openHistory''',
)
replace_once(
    "vulnhunter/web/static/web/conversation.js",
    '''    const localReply = contextualReply(value);\n    if (localReply) {\n      await respondLocally(localReply);\n      return;\n    }\n\n''',
    "",
)
replace_once(
    "vulnhunter/web/static/web/conversation.js",
    '''    if (liveCopy) liveCopy.textContent = eventSummary(latest);\n''',
    '''    if (liveCopy) liveCopy.textContent = text(run.current_step || eventSummary(latest));\n''',
)

# ---------------------------------------------------------------------------
# Chat-first template language and compact result presentation.
# ---------------------------------------------------------------------------
replace_once(
    "vulnhunter/web/templates/web/conversation.html",
    '''      <span class="vh-runtime-chip{% if groq.configured %} is-ready{% else %} is-warning{% endif %}"><i></i><strong>{{ groq.label }}</strong><small>{{ groq.model }}</small></span>\n''',
    '''      <span class="vh-runtime-chip is-ready"><i></i><strong>{% if groq.configured %}AI conversation ready{% else %}Reliable command mode{% endif %}</strong><small>{% if groq.configured %}Natural explanations enabled{% else %}Core assessment workflow available{% endif %}</small></span>\n''',
)
replace_once(
    "vulnhunter/web/templates/web/conversation.html",
    '''      <dl class="vh-inline-approval-facts">\n        <div><dt>Target</dt><dd data-approval-target></dd></div>\n        <div><dt>Port</dt><dd data-approval-port></dd></div>\n        <div><dt>Profile</dt><dd data-approval-profile></dd></div>\n        <div><dt>Scanner</dt><dd data-approval-scanner></dd></div>\n        <div><dt>Templates</dt><dd data-approval-templates></dd></div>\n        <div><dt>Limits</dt><dd data-approval-limits></dd></div>\n        <div><dt>Plan digest</dt><dd><code data-approval-digest></code></dd></div>\n      </dl>\n''',
    '''      <dl class="vh-inline-approval-facts">\n        <div><dt>Target</dt><dd data-approval-target></dd></div>\n        <div><dt>Port</dt><dd data-approval-port></dd></div>\n        <div><dt>Profile</dt><dd data-approval-profile></dd></div>\n        <div><dt>Scanner</dt><dd data-approval-scanner></dd></div>\n        <div><dt>Checks</dt><dd data-approval-templates></dd></div>\n        <div><dt>Limits</dt><dd data-approval-limits></dd></div>\n      </dl>\n      <details class="vh-approval-technical"><summary>Technical plan identity</summary><code data-approval-digest></code></details>\n''',
)
replace_once(
    "vulnhunter/web/templates/web/conversation.html",
    '''      <a data-run-detail-link>Open complete assessment</a>\n      <a data-findings-link>Saved findings</a>\n''',
    '''      <a data-findings-link>View evidence and findings</a>\n      <a data-run-detail-link>View technical details</a>\n''',
)

# CSS overrides: current status first, details collapsed and terminal-only.
with (ROOT / "vulnhunter/web/static/web/conversation-layout.css").open("a", encoding="utf-8") as handle:
    handle.write(
        '''\n\n/* Chat-first assessment card: one live status, terminal details on demand. */\n.vh-conversation-body .vh-run-card {\n  width: min(100%, 700px);\n  border-color: rgba(79, 140, 255, .22);\n}\n\n.vh-conversation-body .vh-run-summary-grid {\n  display: none !important;\n}\n\n.vh-conversation-body .vh-run-live-copy {\n  white-space: normal;\n}\n\n.vh-conversation-body .vh-run-card:not(.is-completed):not(.is-failed):not(.is-cancelled):not(.is-blocked):not(.is-denied):not(.is-readiness_blocked):not(.is-execution_blocked) .vh-run-disclosures,\n.vh-conversation-body .vh-run-card:not(.is-completed):not(.is-failed):not(.is-cancelled):not(.is-blocked):not(.is-denied):not(.is-readiness_blocked):not(.is-execution_blocked) .vh-run-card-footer {\n  display: none;\n}\n\n.vh-conversation-body .vh-run-disclosures details[data-section="progress"] {\n  display: none !important;\n}\n\n.vh-approval-technical {\n  margin: 10px 0 14px;\n  color: var(--vh-muted);\n}\n\n.vh-approval-technical summary {\n  cursor: pointer;\n  font-size: 11px;\n  font-weight: 750;\n}\n\n.vh-approval-technical code {\n  display: block;\n  margin-top: 8px;\n  overflow-wrap: anywhere;\n  font-size: 9px;\n}\n'''
    )

# ---------------------------------------------------------------------------
# Deterministic browser E2E fixtures: real chat/approval/polling, simulated worker.
# ---------------------------------------------------------------------------
write(
    "tests/ui/prepare_conversation_e2e.py",
    '''#!/usr/bin/env python3\n"""Prepare an exact private authorization for browser conversation acceptance."""\n\nfrom __future__ import annotations\n\nimport json\nimport os\nfrom datetime import UTC, datetime, timedelta\nfrom pathlib import Path\n\nos.environ.setdefault("DJANGO_SETTINGS_MODULE", "vulnhunter.web.settings")\n\nimport django\n\ndjango.setup()\n\nfrom django.conf import settings\n\nfrom vulnhunter.authorization.models import AuthorizationLimits\nfrom vulnhunter.authorization.service import issue_authorization\nfrom vulnhunter.authorization.store import AuthorizationStore\nfrom vulnhunter.scope import validate_target\nfrom vulnhunter.web.assessment_workflow import bind_nuclei_authorization\n\n\ndef main() -> int:\n    target = validate_target(\n        "http://10.0.11.34:8010/",\n        resolver=lambda _hostname: ("10.0.11.34",),\n    )\n    now = datetime.now(UTC)\n    store = AuthorizationStore.from_path(Path(settings.VULNHUNTER_AUTHORIZATION_DATABASE))\n    store.initialize()\n    record = issue_authorization(\n        store,\n        target,\n        owner="admin-a",\n        approved_by="browser-e2e-owner",\n        purpose="Deterministic browser acceptance for the governed conversation workflow.",\n        evidence_reference="browser-e2e-private-target",\n        expires_at=now + timedelta(hours=2),\n        limits=AuthorizationLimits(\n            maximum_pages=2,\n            maximum_depth=0,\n            maximum_requests=10,\n            minimum_request_delay_seconds=1,\n        ),\n        now=now,\n    )\n    bind_nuclei_authorization(\n        store,\n        authorization_id=record.authorization_id,\n        approved_profiles=("passive",),\n        private_network_approved=True,\n        recorded_by="admin-a",\n        approval_basis="Browser E2E exact passive target confirmation.",\n        now=now,\n    )\n    readiness = Path(settings.VULNHUNTER_NUCLEI_READINESS_REPORT)\n    readiness.parent.mkdir(parents=True, exist_ok=True)\n    readiness.write_text(\n        json.dumps(\n            {\n                "ready": True,\n                "installed": True,\n                "expected_engine": "v3.8.0",\n                "expected_templates": "v10.4.5",\n                "engine_pin_matches": True,\n                "templates_pin_matches": True,\n                "execution_enabled": True,\n                "reason": "Deterministic browser acceptance readiness.",\n            },\n            indent=2,\n        )\n        + "\\n",\n        encoding="utf-8",\n    )\n    key = Path(settings.VULNHUNTER_NUCLEI_WORKER_SIGNING_KEY_FILE)\n    key.parent.mkdir(parents=True, exist_ok=True)\n    key.write_bytes(b"browser-e2e-worker-signing-key-2026")\n    key.chmod(0o600)\n    print(record.authorization_id)\n    return 0\n\n\nif __name__ == "__main__":\n    raise SystemExit(main())\n''',
)
write(
    "tests/ui/complete_conversation_run.py",
    '''#!/usr/bin/env python3\n"""Simulate the isolated worker transitions after a real browser approval."""\n\nfrom __future__ import annotations\n\nimport argparse\nimport os\nimport time\nfrom datetime import UTC, datetime\nfrom pathlib import Path\n\nos.environ.setdefault("DJANGO_SETTINGS_MODULE", "vulnhunter.web.settings")\n\nimport django\n\ndjango.setup()\n\nfrom django.conf import settings\n\nfrom vulnhunter.agent.models import TaskStatus\nfrom vulnhunter.agent.store import AgentStore\nfrom vulnhunter.agent_activity.service import AgentActivityService\nfrom vulnhunter.agent_activity.store import AppendOnlyActivityStore\nfrom vulnhunter.evidence import EvidenceStore, FindingStatus\n\n\ndef transition(\n    store: AgentStore,\n    activity: AgentActivityService,\n    run_id: str,\n    *,\n    workflow_state: str,\n    status: TaskStatus,\n    event_type: str,\n    summary: str,\n) -> None:\n    current = store.get_task(run_id)\n    workflow = dict(current.memory.get("assessment_workflow", {}))\n    updated = current.evolved(\n        status=status,\n        paused_reason=None,\n        memory={\n            **current.memory,\n            "assessment_workflow": {\n                **workflow,\n                "workflow_state": workflow_state,\n                "approval_state": "approved",\n                "execution_state": workflow_state,\n                "blocking_reason": None,\n            },\n        },\n        final_summary=(\n            "One informational passive finding was verified."\n            if workflow_state == "completed"\n            else current.final_summary\n        ),\n    )\n    store.save_task(updated, expected_revision=current.revision)\n    store.append_event(run_id, event_type, {"summary": summary})\n    activity.record_transition(\n        run_id=run_id,\n        timestamp=datetime.now(UTC),\n        event_type=event_type,\n        summary=summary,\n        run_state=workflow_state,\n        source="browser_e2e_worker",\n    )\n\n\ndef main() -> int:\n    parser = argparse.ArgumentParser()\n    parser.add_argument("--run-id", required=True)\n    args = parser.parse_args()\n    store = AgentStore(Path(settings.VULNHUNTER_AGENT_DATABASE))\n    activity = AgentActivityService(\n        AppendOnlyActivityStore(Path(settings.VULNHUNTER_AGENT_ACTIVITY_ROOT))\n    )\n    transition(\n        store,\n        activity,\n        args.run_id,\n        workflow_state="running",\n        status=TaskStatus.RUNNING,\n        event_type="scanner_started",\n        summary="Running passive checks…",\n    )\n    time.sleep(1.6)\n    transition(\n        store,\n        activity,\n        args.run_id,\n        workflow_state="evaluating",\n        status=TaskStatus.RUNNING,\n        event_type="verification_started",\n        summary="Verifying one possible finding…",\n    )\n    evidence_root = Path(settings.VULNHUNTER_SECURITY_EVIDENCE_ROOT)\n    evidence_root.mkdir(parents=True, exist_ok=True)\n    artifact = evidence_root / f"{args.run_id}-headers.json"\n    artifact.write_text('{"header":"x-content-type-options","value":"missing"}\\n', encoding="utf-8")\n    task = store.get_task(args.run_id)\n    workflow = dict(task.memory.get("assessment_workflow", {}))\n    plan_digest = str(workflow.get("plan_digest") or "a" * 64)\n    EvidenceStore(evidence_root).append(\n        evidence_id=f"finding-{args.run_id}",\n        campaign_id=f"campaign-{args.run_id}",\n        run_id=args.run_id,\n        action_manifest_sha256=plan_digest,\n        tool_id="nuclei",\n        target_reference="http://10.0.11.34:8010/",\n        finding_status=FindingStatus.VALIDATED,\n        title="Missing X-Content-Type-Options header",\n        severity="info",\n        confidence="high",\n        recorded_by="browser-e2e-worker",\n        artifact_path=artifact,\n        metadata={},\n    )\n    time.sleep(1.6)\n    transition(\n        store,\n        activity,\n        args.run_id,\n        workflow_state="completed",\n        status=TaskStatus.COMPLETED,\n        event_type="run_completed",\n        summary="Analysis complete.",\n    )\n    return 0\n\n\nif __name__ == "__main__":\n    raise SystemExit(main())\n''',
)
write(
    "tests/ui/conversation_e2e.cjs",
    '''const { execFile } = require("child_process");\nconst { promisify } = require("util");\nconst { chromium } = require("playwright");\n\nconst execFileAsync = promisify(execFile);\nconst baseUrl = process.env.VULNHUNTER_UI_BASE_URL || "http://127.0.0.1:8767";\nconst username = "visual-admin";\nconst password = "Vh-Visual-Audit-2026!";\n\n(async () => {\n  const browser = await chromium.launch({ headless: true });\n  const page = await browser.newPage({ viewport: { width: 1280, height: 820 } });\n  const consoleErrors = [];\n  page.on("console", (message) => {\n    if (message.type() === "error") consoleErrors.push(message.text());\n  });\n  await page.goto(`${baseUrl}/login/`, { waitUntil: "networkidle" });\n  await page.getByLabel("Username").fill(username);\n  await page.getByLabel("Password").fill(password);\n  await Promise.all([\n    page.waitForURL(`${baseUrl}/`),\n    page.getByRole("button", { name: /sign in securely/i }).click(),\n  ]);\n  const input = page.locator("[data-conversation-input]");\n  await input.fill("Scan http://10.0.11.34:8010/ using the passive profile");\n  await page.locator("[data-conversation-send]").click();\n  await page.getByText(/Review and confirm the plan below/i).waitFor({ timeout: 15000 });\n  await page.locator("[data-inline-approval]").waitFor({ state: "visible", timeout: 15000 });\n  const runId = await page.locator("[data-run-card]").getAttribute("data-run-id");\n  if (!runId) throw new Error("The conversation did not expose an authoritative run id");\n  await page.locator("[data-approval-confirm]").click();\n  await page.getByText(/Approved\. Starting the governed assessment/i).waitFor({ timeout: 15000 });\n  const worker = execFileAsync("python", [\n    "tests/ui/complete_conversation_run.py",\n    "--run-id",\n    runId,\n  ]);\n  await page.getByText(/Running passive checks/i).waitFor({ timeout: 15000 });\n  await page.getByText(/Verifying one possible finding/i).waitFor({ timeout: 15000 });\n  await page.getByText(/Analysis complete in/i).waitFor({ timeout: 20000 });\n  await worker;\n\n  await input.fill("Show me the results");\n  await page.locator("[data-conversation-send]").click();\n  const results = page.locator(".vh-chat-message.is-assistant .vh-message-copy").last();\n  await results.waitFor({ timeout: 10000 });\n  const resultsCopy = await results.textContent();\n  if (!resultsCopy || !resultsCopy.includes("Missing X-Content-Type-Options")) {\n    throw new Error(`Results reply was not evidence-specific: ${resultsCopy}`);\n  }\n\n  await input.fill("Next step");\n  await page.locator("[data-conversation-send]").click();\n  const next = page.locator(".vh-chat-message.is-assistant .vh-message-copy").last();\n  await next.waitFor({ timeout: 10000 });\n  const nextCopy = await next.textContent();\n  if (!nextCopy || nextCopy === resultsCopy || !/evidence|remediation|retest/i.test(nextCopy)) {\n    throw new Error(`Next-step reply was not distinct and actionable: ${nextCopy}`);\n  }\n\n  const technicalOpen = await page.locator('details[data-section="technical"]').evaluate(\n    (element) => element.open,\n  );\n  if (technicalOpen) throw new Error("Technical details must remain collapsed by default");\n  if (consoleErrors.length) throw new Error(`Browser console errors: ${consoleErrors.join(" | ")}`);\n  await browser.close();\n  console.log(JSON.stringify({ runId, resultsCopy, nextCopy }));\n})().catch((error) => {\n  console.error(error);\n  process.exitCode = 1;\n});\n''',
)

# ---------------------------------------------------------------------------
# Unit coverage for commands, state projection and the authorization wiring bug.
# ---------------------------------------------------------------------------
write(
    "tests/unit/test_conversation_core_redesign.py",
    '''from __future__ import annotations\n\nfrom datetime import UTC, datetime, timedelta\n\nfrom vulnhunter.web.conversation_service import deterministic_intent\nfrom vulnhunter.web.conversation_state import enrich_run_payload, reply_for_intent\nfrom vulnhunter.web.conversational_views import _normalize_message_copy\n\n\ndef base_payload(**updates):\n    now = datetime.now(UTC)\n    payload = {\n        "run_id": "assessment-test",\n        "state": "running",\n        "target": "http://10.0.11.34:8010/",\n        "profile": "passive",\n        "created_at": (now - timedelta(seconds=12)).isoformat(),\n        "updated_at": now.isoformat(),\n        "terminal": False,\n        "approval": None,\n        "approval_state": "approved",\n        "blocking_reason": None,\n        "findings": [],\n        "artifacts": [],\n    }\n    payload.update(updates)\n    return payload\n\n\ndef test_deterministic_commands_are_distinct():\n    assert deterministic_intent("Confirm") == "approve"\n    assert deterministic_intent("Show me the results") == "results"\n    assert deterministic_intent("Next step") == "next_step"\n    assert deterministic_intent("What is happening?") == "status"\n    assert deterministic_intent("Cancel it") == "cancel"\n\n\ndef test_status_results_and_next_step_do_not_share_canned_copy():\n    payload = enrich_run_payload(\n        base_payload(),\n        raw_events=[\n            {\n                "event_type": "scanner_started",\n                "summary": "Running passive checks…",\n                "sequence": 1,\n            }\n        ],\n        template_count=7,\n    )\n    status = reply_for_intent("status", payload)\n    results = reply_for_intent("results", payload)\n    next_step = reply_for_intent("next_step", payload)\n    assert len({status, results, next_step}) == 3\n    assert "Running 7 reviewed passive checks" in status\n    assert "not finished" in results\n    assert "No action is required" in next_step\n\n\ndef test_completed_projection_filters_provider_failures_and_returns_evidence_summary():\n    payload = enrich_run_payload(\n        base_payload(\n            state="completed",\n            terminal=True,\n            findings=[\n                {\n                    "title": "Missing X-Content-Type-Options header",\n                    "severity": "info",\n                }\n            ],\n            artifacts=[{"filename": "headers.json"}],\n        ),\n        raw_events=[\n            {\n                "event_type": "provider_notice",\n                "summary": "Advisory reasoning abstained: provider stage unavailable",\n                "sequence": 1,\n            },\n            {\n                "event_type": "run_completed",\n                "summary": "Analysis complete.",\n                "sequence": 2,\n            },\n        ],\n        template_count=7,\n    )\n    assert len(payload["events"]) == 1\n    assert "provider stage unavailable" not in payload["final_message"].lower()\n    assert "Missing X-Content-Type-Options" in payload["final_message"]\n    assert "deterministic verification" in payload["analysis_note"]\n\n\ndef test_message_copy_preserves_progressive_lines():\n    copy = _normalize_message_copy(\n        "Target:\\nhttp://10.0.11.34:8010/\\n\\nChecking authorisation… completed"\n    )\n    assert copy == (\n        "Target:\\nhttp://10.0.11.34:8010/\\nChecking authorisation… completed"\n    )\n''',
)

# Update existing static experience assertions.
replace_once(
    "tests/unit/test_conversation_experience.py",
    '''    assert "Checking the active workspace" in script\n    assert "The controlled target for the active assessment is" in script\n    assert "announceRunProgress" in script\n    assert "confirmedRuns" in script\n''',
    '''    assert "announceRunProgress" in script\n    assert "next.final_message" in script\n    assert "run.current_step" in script\n    assert "contextualReply" not in script\n    assert "confirmedRuns" in script\n''',
)

# Quality workflows: lint/test the new core and run a real browser chat lifecycle.
replace_once(
    ".github/workflows/conversation-quality.yml",
    '''            vulnhunter/web/conversation_service.py \\\n            vulnhunter/web/conversational_authorization.py \\\n            vulnhunter/web/conversational_views.py \\\n''',
    '''            vulnhunter/web/conversation_service.py \\\n            vulnhunter/web/conversation_state.py \\\n            vulnhunter/web/conversational_authorization.py \\\n            vulnhunter/web/conversational_views.py \\\n''',
)
replace_once(
    ".github/workflows/conversation-quality.yml",
    '''            tests/unit/test_chat_runtime_reply.py \\\n            tests/unit/test_conversational_url_targets.py \\\n''',
    '''            tests/unit/test_chat_runtime_reply.py \\\n            tests/unit/test_conversation_core_redesign.py \\\n            tests/unit/test_conversational_url_targets.py \\\n''',
)
replace_once(
    ".github/workflows/conversation-quality.yml",
    '''            tests/unit/test_chat_runtime_reply.py \\\n            tests/unit/test_conversational_url_targets.py \\\n            tests/unit/test_conversation_experience.py \\\n''',
    '''            tests/unit/test_chat_runtime_reply.py \\\n            tests/unit/test_conversation_core_redesign.py \\\n            tests/unit/test_conversational_url_targets.py \\\n            tests/unit/test_conversation_experience.py \\\n''',
)
replace_once(
    ".github/workflows/quality.yml",
    '      VULNHUNTER_INTELLIGENCE_ENABLED: "false"\n',
    '''      VULNHUNTER_INTELLIGENCE_ENABLED: "false"\n      VULNHUNTER_NUCLEI_READINESS_REPORT: /tmp/vh-ui/nuclei-readiness.json\n      VULNHUNTER_NUCLEI_PILOT_ENQUEUE_ENABLED: "true"\n      VULNHUNTER_NUCLEI_WORKER_SIGNING_KEY_FILE: /tmp/vh-ui/worker-signing.key\n      VULNHUNTER_NUCLEI_WORKER_SPOOL_ROOT: /tmp/vh-ui/worker-spool\n''',
)
replace_once(
    ".github/workflows/quality.yml",
    '''          node --check .playwright-validate.cjs\n''',
    '''          node --check .playwright-validate.cjs\n          node --check tests/ui/conversation_e2e.cjs\n''',
)
replace_once(
    ".github/workflows/quality.yml",
    '''          python tests/ui/prepare_visual_audit.py\n''',
    '''          python tests/ui/prepare_visual_audit.py\n          python tests/ui/prepare_conversation_e2e.py\n''',
)
replace_once(
    ".github/workflows/quality.yml",
    '''      - name: Capture and validate responsive product UI\n        run: node .playwright-validate.cjs\n''',
    '''      - name: Run conversational browser lifecycle\n        run: node tests/ui/conversation_e2e.cjs\n\n      - name: Capture and validate responsive product UI\n        run: node .playwright-validate.cjs\n''',
)

print("Applied authoritative conversational core redesign.")
