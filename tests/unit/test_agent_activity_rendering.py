"""Safe rendering and polling-asset tests for the activity timeline."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from vulnhunter.agent_activity.models import (
    ActivityEvent,
    ActivityFeedSnapshot,
)
from vulnhunter.agent_activity.rendering import render_activity_timeline


def _event() -> ActivityEvent:
    return ActivityEvent(
        run_id="run-example",
        timestamp=datetime(2026, 7, 10, tzinfo=UTC),
        event_type="tool_progress",
        summary='<script>alert("x")</script> evidence remains data',
        run_state="executing",
        source="tool",
        event_id="evt_" + "a" * 24,
        sequence=1,
        previous_event_sha256=None,
        event_sha256="a" * 64,
    )


def test_rendering_escapes_untrusted_event_content() -> None:
    snapshot = ActivityFeedSnapshot(
        run_id="run-example",
        events=(_event(),),
        after_sequence=0,
        last_sequence=1,
        run_state="executing",
        terminal=False,
    )
    html = render_activity_timeline(
        snapshot,
        endpoint="/agent/runs/run-example/events",
    )
    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html
    assert "Hidden reasoning and secrets are not shown" in html


def test_polling_script_uses_text_content_and_never_inner_html() -> None:
    script = Path("vulnhunter/agent_activity/assets/activity_timeline.js").read_text(
        encoding="utf-8"
    )
    assert ".textContent" in script
    assert "innerHTML" not in script
    assert "after_sequence" in script
    assert 'credentials: "same-origin"' in script


def test_responsive_styles_prevent_horizontal_overflow() -> None:
    styles = Path("vulnhunter/agent_activity/assets/activity_timeline.css").read_text(
        encoding="utf-8"
    )
    assert "min-width: 0" in styles
    assert "overflow-wrap: anywhere" in styles
    assert "@media" in styles
