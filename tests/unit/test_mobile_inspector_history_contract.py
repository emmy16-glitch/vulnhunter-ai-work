from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STATIC = ROOT / "vulnhunter" / "web" / "static" / "web"
SCRIPT = STATIC / "conversation-mobile-inspector.js"
OPEN_BRIDGE = STATIC / "conversation-mobile-deferred-tools.js"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_mobile_inspector_open_and_close_create_native_back_history() -> None:
    script = _text(SCRIPT)
    for token in (
        "sheetHistoryActive",
        'window.history.pushState({ vhAssessmentSheet: true }, "")',
        "window.history.back();",
        'window.addEventListener("popstate"',
        "hideInspector({ fromHistory: true })",
    ):
        assert token in script


def test_mobile_inspector_history_is_local_to_the_contextual_sheet() -> None:
    script = _text(SCRIPT)
    assert "if (pushHistory && !state.sheetHistoryActive)" in script
    assert "if (isMobile() && state.sheetHistoryActive && !fromHistory)" in script
    assert "state.sheetHistoryActive = false" in script
    assert "assessment=" not in script
    assert "inspector=" not in script


def test_visible_open_details_control_delegates_without_restoring_bottom_navigation() -> None:
    bridge = _text(OPEN_BRIDGE)
    assert 'event.target.closest?.("[data-analysis-inspector-open]")' in bridge
    assert 'querySelector("[data-analysis-inspector-controller]")' in bridge
    assert "inspectorController.click()" in bridge
    assert "restoreInspectorFocus" in bridge
    assert "data-mobile-nav-destination" not in bridge
