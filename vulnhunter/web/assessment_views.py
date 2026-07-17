from __future__ import annotations

from django.contrib import messages
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect
from django.views.decorators.cache import cache_control
from django.views.decorators.http import require_http_methods

from vulnhunter.web import operations_views

_ALLOWED_SCANNER_ENGINES = {"automatic", "nuclei"}


@cache_control(private=True, no_store=True)
@require_http_methods(["GET", "POST"])
def new_assessment_view(request: HttpRequest) -> HttpResponse:
    """Validate the scanner choice before using the existing governed workflow."""

    if request.method == "POST":
        requested_engine = request.POST.get("scanner_engine", "automatic").strip().lower()
        if requested_engine not in _ALLOWED_SCANNER_ENGINES:
            messages.error(request, "The selected scanner is not available.")
            return redirect("web-new-scan")
    return operations_views.new_scan_view(request)
