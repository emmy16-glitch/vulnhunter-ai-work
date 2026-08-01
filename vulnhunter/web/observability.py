from __future__ import annotations

import json
import logging
import re
import time
from collections.abc import Callable
from uuid import uuid4

from django.http import HttpRequest, HttpResponse

logger = logging.getLogger("vulnhunter.web.requests")

_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{7,63}$")
_REQUEST_ID_HEADER = "X-Request-ID"


def trusted_request_id(value: str | None) -> str:
    """Return a safe caller correlation ID or generate a new opaque value."""

    candidate = (value or "").strip()
    if _REQUEST_ID_PATTERN.fullmatch(candidate):
        return candidate
    return uuid4().hex


def safe_route_name(request: HttpRequest) -> str:
    """Return the configured route name without recording raw paths or query strings."""

    match = getattr(request, "resolver_match", None)
    route_name = getattr(match, "url_name", None)
    if isinstance(route_name, str) and route_name:
        return route_name[:96]
    return "unmatched"


def request_log_record(
    request: HttpRequest,
    *,
    request_id: str,
    status_code: int,
    duration_ms: int,
    outcome: str = "completed",
) -> dict[str, object]:
    """Build the intentionally small, non-sensitive HTTP completion record."""

    return {
        "duration_ms": max(0, int(duration_ms)),
        "event": "http_request",
        "method": request.method[:12],
        "outcome": outcome,
        "request_id": request_id,
        "route": safe_route_name(request),
        "status": int(status_code),
    }


def _write_record(record: dict[str, object], *, level: int) -> None:
    logger.log(level, json.dumps(record, separators=(",", ":"), sort_keys=True))


class RequestCorrelationMiddleware:
    """Attach a trusted request ID and emit one redacted structured completion log."""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        request_id = trusted_request_id(request.headers.get(_REQUEST_ID_HEADER))
        request.vulnhunter_request_id = request_id
        started = time.monotonic()
        try:
            response = self.get_response(request)
        except Exception:
            duration_ms = round((time.monotonic() - started) * 1000)
            _write_record(
                request_log_record(
                    request,
                    request_id=request_id,
                    status_code=500,
                    duration_ms=duration_ms,
                    outcome="exception",
                ),
                level=logging.ERROR,
            )
            raise

        duration_ms = round((time.monotonic() - started) * 1000)
        response[_REQUEST_ID_HEADER] = request_id
        _write_record(
            request_log_record(
                request,
                request_id=request_id,
                status_code=response.status_code,
                duration_ms=duration_ms,
            ),
            level=logging.INFO if response.status_code < 500 else logging.ERROR,
        )
        return response
