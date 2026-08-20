from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_browser_intelligence_has_a_real_style_owner_loaded_by_conversation():
    template = (
        ROOT / "vulnhunter/web/templates/web/conversation.html"
    ).read_text(encoding="utf-8")
    stylesheet = ROOT / "vulnhunter/web/static/web/browser-intelligence.css"

    assert stylesheet.exists()
    assert "web/browser-intelligence.css" in template
    styles = stylesheet.read_text(encoding="utf-8")
    assert ".vh-browser-intelligence-panel" in styles
    assert ".vh-browser-intelligence-sessions" in styles
    assert ".vh-browser-intelligence-card" in styles
    assert "@media (max-width: 767px)" in styles


def test_live_browser_sessions_leave_the_empty_setup_panel_and_enter_the_feed():
    script = (
        ROOT / "vulnhunter/web/static/web/conversation-browser-intelligence.js"
    ).read_text(encoding="utf-8")
    template = (
        ROOT / "vulnhunter/web/templates/web/conversation.html"
    ).read_text(encoding="utf-8")

    assert "data-browser-intelligence-sessions" in template
    assert "sessions.closest('[data-conversation-empty]')" in script
    assert "sessions.classList.add('vh-browser-intelligence-sessions')" in script
    assert "feed.append(sessions)" in script
    assert "sessions.prepend(card)" in script
    assert "data-browser-intelligence-card" in template


def test_browser_intelligence_remains_governed_and_evidence_backed():
    script = (
        ROOT / "vulnhunter/web/static/web/conversation-browser-intelligence.js"
    ).read_text(encoding="utf-8")

    assert "authorization_id" in script
    assert "workspace_id" in script
    assert "credentials: 'same-origin'" in script
    assert "X-CSRFToken" in script
    assert "take_screenshot" in script
    assert "report.report_sha256" in script
    assert "Open private screenshot evidence" in script
