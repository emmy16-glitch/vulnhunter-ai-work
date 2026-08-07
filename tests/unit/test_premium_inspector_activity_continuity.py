from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ACTIVITY_JS = ROOT / "vulnhunter/web/static/web/activity.js"
ACTIVITY_CSS = ROOT / "vulnhunter/web/static/web/activity.css"
INSPECTOR_JS = ROOT / "vulnhunter/web/static/web/conversation-mobile-inspector.js"
INSPECTOR_CSS = ROOT / "vulnhunter/web/static/web/conversation-mobile-inspector.css"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_activity_stream_never_invents_percentage_progress() -> None:
    javascript = _text(ACTIVITY_JS)

    assert "function progressFor" not in javascript
    assert "workflowProgress" not in javascript
    assert "progressFill.style.width" not in javascript
    assert "aria-valuenow" not in javascript
    assert "EventSource connected to backend state" in javascript


def test_only_new_activity_rows_receive_arrival_emphasis() -> None:
    javascript = _text(ACTIVITY_JS)
    css = _text(ACTIVITY_CSS)

    assert 'eventNode(event, { isNew: true })' in javascript
    assert 'node.classList.remove("is-new")' in javascript
    assert ".vh-activity-event.is-new" in css
    assert "vh-activity-arrival" in css
    assert "var(--vh-motion-duration-standard" in css
    assert "@media (prefers-reduced-motion: reduce)" in css


def test_inspector_preserves_backend_owned_measured_stage_progress() -> None:
    javascript = _text(INSPECTOR_JS)

    assert "taskCard.stage_progress?.completed" in javascript
    assert "taskCard.stage_progress?.total" in javascript
    assert "persisted stages complete" in javascript
    assert "Math.round((completed / total) * 100)" in javascript
    assert "elapsed_seconds" not in javascript


def test_mobile_inspector_keeps_existing_back_focus_and_reduced_motion_contracts() -> None:
    javascript = _text(INSPECTOR_JS)
    css = _text(INSPECTOR_CSS)

    assert "state.returnFocus" in javascript
    assert "window.history.pushState" in javascript
    assert 'window.addEventListener("popstate"' in javascript
    assert 'event.key === "Escape"' in javascript
    assert "vh-mobile-sheet-open" in javascript
    assert "@media (prefers-reduced-motion: reduce)" in css
    assert ".vh-inspector-tool.is-running .vh-inspector-tool-marker" in css
