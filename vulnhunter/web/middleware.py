from __future__ import annotations

import logging

from django.conf import settings
from django.http import JsonResponse

logger = logging.getLogger(__name__)


class ContentSecurityPolicyMiddleware:
    """Attach CSP headers and keep workspace API failures machine-readable."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
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
