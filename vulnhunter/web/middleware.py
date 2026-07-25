from __future__ import annotations

import logging
import sqlite3

from django.conf import settings
from django.http import JsonResponse

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


class ContentSecurityPolicyMiddleware:
    """Attach CSP headers, restore live context, and keep API failures JSON."""

    def __init__(self, get_response):
        self.get_response = get_response

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
            "Workspace request failed: %s %s",
            request.method,
            request.path,
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
