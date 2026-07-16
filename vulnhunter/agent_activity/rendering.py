"""Safe framework-neutral HTML rendering for the activity timeline."""

from __future__ import annotations

from html import escape

from vulnhunter.agent_activity.models import (
    ActivityEvent,
    ActivityFeedSnapshot,
)


def _event_html(event: ActivityEvent) -> str:
    timestamp = escape(event.timestamp.isoformat())
    event_type = escape(event.event_type.replace("_", " ").title())
    summary = escape(event.summary)
    state = escape(event.run_state.replace("_", " ").title())
    audit = (
        f'<span class="vh-activity-audit">Audit: {escape(event.audit_reference)}</span>'
        if event.audit_reference
        else ""
    )
    return (
        '<li class="vh-activity-event" '
        f'data-sequence="{event.sequence}" data-event-id="{escape(event.event_id)}">'
        '<div class="vh-activity-marker" aria-hidden="true"></div>'
        '<div class="vh-activity-content">'
        f'<time datetime="{timestamp}">{timestamp}</time>'
        f'<div class="vh-activity-title">{event_type}</div>'
        f"<p>{summary}</p>"
        '<div class="vh-activity-meta">'
        f"<span>State: {state}</span>{audit}"
        "</div></div></li>"
    )


def render_activity_timeline(
    snapshot: ActivityFeedSnapshot,
    *,
    endpoint: str | None = None,
    poll_interval_ms: int = 1_500,
) -> str:
    """Render a safe embeddable timeline without executing event content."""
    if not 500 <= poll_interval_ms <= 60_000:
        raise ValueError("poll_interval_ms must be between 500 and 60000")
    event_markup = "".join(_event_html(event) for event in snapshot.events)
    empty_hidden = " hidden" if snapshot.events else ""
    endpoint_attr = escape(endpoint or "", quote=True)
    state = escape(snapshot.run_state or "No activity")
    terminal = "true" if snapshot.terminal else "false"
    return (
        '<section class="vh-activity-timeline" '
        f'data-endpoint="{endpoint_attr}" '
        f'data-after-sequence="{snapshot.last_sequence}" '
        f'data-poll-interval-ms="{poll_interval_ms}" '
        f'data-terminal="{terminal}" '
        'aria-labelledby="vh-activity-heading">'
        '<header class="vh-activity-header">'
        '<div><h2 id="vh-activity-heading">Live agent activity</h2>'
        "<p>Safe operational events only. Hidden reasoning and secrets are not "
        "shown.</p>"
        "</div>"
        '<div class="vh-activity-controls">'
        f'<span class="vh-activity-state" aria-live="polite">{state}</span>'
        '<button type="button" data-action="toggle-autoscroll" '
        'aria-pressed="false">Pause live view</button>'
        "</div></header>"
        f'<p class="vh-activity-empty"{empty_hidden}>'
        "No activity has been recorded yet.</p>"
        '<p class="vh-activity-connection" data-connection-state '
        'aria-live="polite" hidden></p>'
        f'<ol class="vh-activity-events">{event_markup}</ol>'
        '<button type="button" class="vh-activity-new-events" '
        'data-action="show-new-events" hidden>New activity below</button>'
        "</section>"
    )
