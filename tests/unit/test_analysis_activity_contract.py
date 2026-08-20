from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STATIC = ROOT / "vulnhunter" / "web" / "static" / "web"
TEMPLATE = ROOT / "vulnhunter" / "web" / "templates" / "web" / "conversation.html"


def test_activity_panel_is_provider_neutral_and_cursor_based() -> None:
    script = (STATIC / "analysis-activity.js").read_text(encoding="utf-8")
    template = TEMPLATE.read_text(encoding="utf-8")

    assert "new WebSocket" in script
    assert "realtime_ticket_url" in script
    assert "after_sequence: cursor" in script
    assert "last_sequence" in script
    assert "queued" in script
    assert "running" in script
    assert "completed" in script
    assert "blocked" in script
    assert "failed" in script
    assert "provider" not in script.casefold()
    assert "chain-of-thought" not in script.casefold()
    assert "hidden reasoning" in template.casefold()
    assert "data-analysis-activity" in template


def test_activity_panel_uses_safe_text_nodes_for_operational_copy() -> None:
    script = (STATIC / "analysis-activity.js").read_text(encoding="utf-8")

    assert "textContent" in script
    assert "innerHTML" not in script
    assert "raw stdout" not in script.casefold()
    assert "api_key" not in script.casefold()
