from __future__ import annotations

import logging
import sqlite3

from django.conf import settings
from django.http import JsonResponse

from vulnhunter.web.observability import RequestCorrelationMiddleware, safe_route_name

logger = logging.getLogger(__name__)

_SESSION_STATE = "vulnhunter_conversation_state"
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


def _restore_latest_non_terminal_run(request) -> None:
    """Reconnect a fresh authenticated root session to its latest visible live run."""

    if request.method != "GET" or request.path != "/":
        return
    if not getattr(request.user, "is_authenticated", False):
        return
    if getattr(request, "vulnhunter_thread", None) is not None:
        return
    raw_state = request.session.get(_SESSION_STATE, {})
    state = dict(raw_state) if isinstance(raw_state, dict) else {}
    if isinstance(state.get("run_id"), str) and state["run_id"]:
        return

    from vulnhunter.product import ProductServiceError
    from vulnhunter.web.services import (
        WebPermissionDenied,
        authorized_actor,
        product_service,
        run_visible_to_actor,
    )

    try:
        actor = authorized_actor(request.user, required_actions=("scan.create", "scan.read"))
        summaries = list(product_service().list_agent_runs())
    except (
        WebPermissionDenied,
        ProductServiceError,
        OSError,
        RuntimeError,
        ValueError,
        sqlite3.Error,
    ):
        return

    summaries.sort(key=lambda item: item.updated_at, reverse=True)
    for summary in summaries:
        if not run_visible_to_actor(summary, actor):
            continue
        try:
            run = product_service().get_agent_run(str(summary.run_id))
        except (ProductServiceError, OSError, RuntimeError, ValueError, sqlite3.Error):
            continue
        current_state = str(
            getattr(run, "workflow_state", None) or getattr(run, "current_state", "unknown")
        )
        if current_state in _TERMINAL_STATES:
            continue
        target = str(getattr(run, "scope_summary", None) or getattr(run, "objective", ""))
        profile = str(getattr(run, "risk_classification", "") or "")
        authorization_id = getattr(run, "authorization_id", None)
        restored = {"run_id": str(run.run_id)}
        if target:
            restored["target"] = target
        if profile:
            restored["profile"] = profile
        if authorization_id:
            restored["authorization_id"] = str(authorization_id)
        request.session[_SESSION_STATE] = restored
        request.session.modified = True
        return


def _refresh_specialist_workspaces(request) -> None:
    """Project specialist worker state before the selected chat is rendered."""

    if request.method != "GET" or request.path != "/":
        return
    if getattr(request, "vulnhunter_thread", None) is None:
        return
    from vulnhunter.web.active_validation_conversation_state import (
        current_active_validation_plan,
        record_active_validation_event,
    )
    from vulnhunter.web.remediation_conversation_state import (
        current_remediation_plan,
        record_remediation_event,
    )
    from vulnhunter.web.retest_conversation_state import (
        current_retest_plan,
        record_retest_event,
    )
    from vulnhunter.web.source_hunt_conversation_state import (
        current_source_hunt_plan,
        record_source_hunt_event,
    )

    try:
        source_plan = current_source_hunt_plan(request)
        if source_plan is not None:
            record_source_hunt_event(request, source_plan)
    except (OSError, RuntimeError, ValueError):
        logger.exception("Source Hunt workspace refresh failed safely")

    try:
        validation_plan = current_active_validation_plan(request)
        if validation_plan is not None:
            record_active_validation_event(request, validation_plan)
    except (OSError, RuntimeError, ValueError):
        logger.exception("Active Validation workspace refresh failed safely")

    try:
        remediation_plan = current_remediation_plan(request)
        if remediation_plan is not None:
            record_remediation_event(request, remediation_plan)
    except (OSError, RuntimeError, ValueError, sqlite3.Error):
        logger.exception("Remediation workspace refresh failed safely")

    try:
        retest_plan = current_retest_plan(request)
        if retest_plan is not None:
            record_retest_event(request, retest_plan)
    except (OSError, RuntimeError, ValueError, sqlite3.Error):
        logger.exception("Governed retest workspace refresh failed safely")


class ConversationThreadMiddleware:
    """Select a durable workspace and isolate its legacy session-backed state."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        thread_requested = bool(
            request.GET.get("thread")
            or (request.method == "POST" and request.POST.get("thread_id"))
            or request.headers.get("X-VulnHunter-Thread")
        )
        source_hunt_selected = request.path == "/source-hunt/" and thread_requested
        finding_workspace_selected = (
            request.path.startswith("/findings/")
            and any(marker in request.path for marker in ("/remediation/", "/retest/"))
            and thread_requested
        )
        is_workspace_path = (
            request.path == "/"
            or request.path.startswith("/workspace/")
            or source_hunt_selected
            or finding_workspace_selected
        )
        if is_workspace_path and getattr(request.user, "is_authenticated", False):
            from vulnhunter.web.conversation_threads import (
                ConversationThreadNotFound,
                ThreadSessionProxy,
                resolve_thread,
            )

            base_session = request.session
            try:
                thread = resolve_thread(request)
            except ConversationThreadNotFound as exc:
                if (
                    request.path.startswith("/workspace/")
                    or request.path == "/source-hunt/"
                    or finding_workspace_selected
                    or "application/json" in request.headers.get("Accept", "")
                ):
                    return JsonResponse({"detail": str(exc)}, status=404)
                thread = None
            if thread is not None:
                request.vulnhunter_base_session = base_session
                request.vulnhunter_thread = thread
                request.session = ThreadSessionProxy(base_session, thread)
                _refresh_specialist_workspaces(request)
        return self.get_response(request)


class ContentSecurityPolicyMiddleware:
    """Attach CSP headers, correlate requests, restore live context, and keep API failures JSON."""

    def __init__(self, get_response):
        self.get_response = RequestCorrelationMiddleware(get_response)

    def __call__(self, request):
        _restore_latest_non_terminal_run(request)
        response = self.get_response(request)
        response.setdefault("Content-Security-Policy", settings.VULNHUNTER_CSP)
        return response

    def process_exception(self, request, exception):
        accepts_json = "application/json" in request.headers.get("Accept", "")
        if not accepts_json or not request.path.startswith("/workspace/"):
            return None
        logger.exception(
            "Workspace request failed request_id=%s method=%s route=%s",
            getattr(request, "vulnhunter_request_id", "unavailable"),
            request.method,
            safe_route_name(request),
            exc_info=exception,
        )
        response = JsonResponse(
            {
                "detail": (
                    "VulnHunter could not complete this request. "
                    "The server recorded the failure; retry after refreshing the workspace."
                )
            },
            status=500,
        )
        response["Cache-Control"] = "private, no-store, max-age=0"
        response.setdefault("Content-Security-Policy", settings.VULNHUNTER_CSP)
        return response
