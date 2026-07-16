"""Server-sent event surfaces for live assessment activity."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime

from django.contrib.auth.decorators import login_required
from django.http import Http404, HttpRequest, JsonResponse, StreamingHttpResponse
from django.views.decorators.cache import cache_control
from django.views.decorators.http import require_GET

from vulnhunter.product import ProductServiceError
from vulnhunter.web.services import (
    WebPermissionDenied,
    activity_payload,
    authorized_actor,
    product_service,
    run_visible_to_actor,
)


def _after_sequence_or_error(request: HttpRequest) -> int:
    """Resolve the newest valid sequence from SSE or query metadata."""

    values: list[int] = []
    for raw_value in (
        request.GET.get("after_sequence"),
        request.headers.get("Last-Event-ID"),
    ):
        if raw_value in {None, ""}:
            continue
        try:
            value = int(raw_value)
        except (TypeError, ValueError) as exc:
            raise ValueError("after_sequence and Last-Event-ID must be integers") from exc
        if value < 0:
            raise ValueError("activity sequence must be non-negative")
        values.append(value)
    return max(values, default=0)


def _event_stream(*, sequence: int, payload: dict[str, object]) -> Iterator[str]:
    """Serialize one bounded SSE snapshot; EventSource reconnects automatically."""

    encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True, default=str)
    yield "retry: 1500\n"
    yield f"id: {sequence}\n"
    yield "event: activity\n"
    for line in encoded.splitlines() or ("",):
        yield f"data: {line}\n"
    yield "\n"


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def agent_activity_stream_view(request: HttpRequest, run_id: str):
    """Return a redacted live activity snapshot as a server-sent event."""

    try:
        actor = authorized_actor(request.user, required_actions=("audit.read", "scan.read"))
    except WebPermissionDenied:
        return JsonResponse({"detail": "forbidden"}, status=403)

    try:
        after_sequence = _after_sequence_or_error(request)
    except ValueError as exc:
        return JsonResponse({"detail": str(exc)}, status=400)

    try:
        run = product_service().get_agent_run(run_id)
    except ProductServiceError as exc:
        raise Http404(str(exc)) from exc
    if not run_visible_to_actor(run, actor):
        raise Http404("Assessment run does not exist.")

    payload = activity_payload(run_id, after_sequence=after_sequence)
    elapsed_seconds = max(0, int((datetime.now(UTC) - run.created_at).total_seconds()))
    payload.update(
        {
            "run_id": run.run_id,
            "run_state": run.current_state,
            "approval_state": run.approval_state.value,
            "execution_state": run.execution_state,
            "workflow_state": getattr(run, "workflow_state", None),
            "execution_enabled": getattr(run, "execution_enabled", False),
            "execution_blocking_reason": getattr(run, "execution_blocking_reason", None),
            "readiness": getattr(run, "readiness", {}),
            "evaluation_result": run.evaluation_result,
            "elapsed_seconds": elapsed_seconds,
            "updated_at": run.updated_at.isoformat(),
        }
    )
    sequence = int(payload.get("last_sequence", after_sequence))
    response = StreamingHttpResponse(
        _event_stream(sequence=sequence, payload=payload),
        content_type="text/event-stream; charset=utf-8",
    )
    response["Cache-Control"] = "private, no-cache, no-store, must-revalidate"
    response["X-Accel-Buffering"] = "no"
    return response
