"""Read-only, redacted workspace context exposed to advisory models."""

from __future__ import annotations

import json
from collections.abc import Mapping

from vulnhunter.security import redact_text
from vulnhunter.web.conversation_threads import thread_summary


def _bounded(value: object, *, depth: int = 0) -> object:
    if depth > 5:
        return "[TRUNCATED]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return redact_text(value)[:2_000]
    if isinstance(value, Mapping):
        blocked = {"cookie", "authorization", "token", "secret", "password", "raw"}
        return {
            str(key)[:100]: _bounded(item, depth=depth + 1)
            for key, item in list(value.items())[:80]
            if not any(term in str(key).casefold() for term in blocked)
        }
    if isinstance(value, (list, tuple)):
        return [_bounded(item, depth=depth + 1) for item in value[:80]]
    return redact_text(str(value))[:1_000]


def build_safe_tool_context(
    request: object,
    *,
    active_run: dict[str, object] | None = None,
) -> str:
    """Return bounded persisted status, evidence summaries, APK plan, and uploads."""

    thread = getattr(request, "vulnhunter_thread", None)
    session = request.session
    mobile = session.get("vulnhunter_conversation_mobile_plan", {})
    uploads = session.get("vulnhunter_conversation_apk_uploads", {})
    state = session.get("vulnhunter_conversation_state", {})
    payload = {
        "workspace": thread_summary(thread) if thread is not None else {},
        "selected_assessment": active_run or {},
        "stored_state": state if isinstance(state, dict) else {},
        "mobile_analysis": mobile if isinstance(mobile, dict) else {},
        "uploads": uploads if isinstance(uploads, dict) else {},
    }
    encoded = json.dumps(_bounded(payload), sort_keys=True, separators=(",", ":"))
    return encoded[:24_000]
