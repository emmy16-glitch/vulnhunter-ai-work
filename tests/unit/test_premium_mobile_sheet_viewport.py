from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PREMIUM_CSS = ROOT / "vulnhunter/web/static/web/premium-interaction.css"
INSPECTOR_JS = ROOT / "vulnhunter/web/static/web/conversation-mobile-inspector.js"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_mobile_sheet_tracks_dynamic_viewport_and_safe_areas() -> None:
    css = _text(PREMIUM_CSS)

    assert "html.vh-mobile-sheet-open .vh-analysis-inspector" in css
    assert "height: 100dvh" in css
    assert "max-height: 100dvh" in css
    assert "env(safe-area-inset-top)" in css
    assert "env(safe-area-inset-bottom)" in css
    assert "scroll-padding-bottom" in css


def test_mobile_sheet_keeps_touch_targets_at_shared_minimum() -> None:
    css = _text(PREMIUM_CSS)

    assert ".vh-analysis-inspector-close" in css
    assert ".vh-mobile-workspace-nav button" in css
    assert "min-width: var(--vh-interaction-target-min)" in css
    assert "min-height: var(--vh-interaction-target-min)" in css


def test_mobile_sheet_handles_short_landscape_without_hiding_content() -> None:
    css = _text(PREMIUM_CSS)

    assert "(max-height: 520px) and (orientation: landscape)" in css
    assert ".vh-analysis-inspector-header" in css
    assert ".vh-analysis-panel" in css


def test_android_back_and_focus_return_remain_owned_by_inspector_controller() -> None:
    javascript = _text(INSPECTOR_JS)

    assert "window.history.pushState({ vhAssessmentSheet: true }" in javascript
    assert 'window.addEventListener("popstate"' in javascript
    assert 'event.key === "Escape"' in javascript
    assert "state.returnFocus" in javascript
    assert "state.returnFocus.focus()" in javascript
    assert 'document.documentElement.classList.add("vh-mobile-sheet-open")' in javascript
    assert 'document.documentElement.classList.remove("vh-mobile-sheet-open")' in javascript
