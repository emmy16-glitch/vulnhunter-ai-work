from __future__ import annotations

from django.conf import settings


class ContentSecurityPolicyMiddleware:
    """Attach a restrictive same-origin CSP for the local web surface."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response.setdefault("Content-Security-Policy", settings.VULNHUNTER_CSP)
        return response
