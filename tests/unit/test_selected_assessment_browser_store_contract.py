from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "vulnhunter" / "web" / "static" / "web" / "workspace-state.js"


def _script() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def test_browser_store_accepts_only_matching_authoritative_projection_and_task_card():
    script = _script()
    assert "payload?.assessment_projection" in script
    assert "payload?.task_card || projection?.task_card" in script
    assert "taskCard?.assessment_id" in script
    assert "return null" in script


def test_browser_store_replaces_atomically_and_returns_defensive_snapshots():
    script = _script()
    assert "let snapshot = null" in script
    assert "snapshot = clone(next)" in script
    assert "getSnapshot()" in script
    assert "return clone(snapshot)" in script
    assert "structuredClone" in script
    assert "Object.freeze" in script


def test_browser_store_is_driven_only_by_authoritative_projection_and_reset_events():
    script = _script()
    assert 'document.addEventListener("vh:mobile-projection"' in script
    assert 'document.addEventListener("vh:mobile-reset"' in script
    assert 'new CustomEvent("vh:selected-assessment-change"' in script
    assert "MutationObserver" not in script
    assert "runFromDom" not in script
    assert "run?.progress_percent" not in script
    assert "querySelector(\"[data-run-card]\")" not in script


def test_browser_store_does_not_mutate_inspector_or_navigation_ui():
    script = _script()
    for forbidden in (
        "data-inspector-state",
        "data-inspector-progress-value",
        "data-state-authorization",
        "data-state-scope",
        "data-state-approval",
        "data-state-active",
        "classList.add(\"is-open\")",
    ):
        assert forbidden not in script
