from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "vulnhunter" / "web" / "static" / "web" / "workspace-state.js"
INSPECTOR = ROOT / "vulnhunter" / "web" / "templates" / "web" / "_mobile_analysis_inspector.html"


def _script() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def _inspector() -> str:
    return INSPECTOR.read_text(encoding="utf-8")


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


def test_browser_store_exposes_one_direct_authoritative_state_interface():
    script = _script()
    assert "replace(payload)" in script
    assert "clear()" in script
    assert "subscribe(listener)" in script
    assert 'new CustomEvent("vh:selected-assessment-change"' in script
    assert 'new CustomEvent("vh:selected-assessment-store-ready"' in script
    assert '"vh:mobile-projection"' not in script
    assert '"vh:mobile-reset"' not in script
    assert "MutationObserver" not in script
    assert "runFromDom" not in script
    assert "run?.progress_percent" not in script
    assert 'querySelector("[data-run-card]")' not in script


def test_browser_store_isolates_subscriber_failures_before_dispatching_change_event():
    script = _script()
    assert "listeners.forEach((listener) => {" in script
    assert "try {" in script
    assert "listener(clone(snapshot));" in script
    assert "reportListenerFailure(error);" in script
    assert "window.setTimeout(() => {" in script
    assert 'new CustomEvent("vh:selected-assessment-change"' in script


def test_browser_store_does_not_mutate_inspector_or_navigation_ui():
    script = _script()
    for forbidden in (
        "data-inspector-state",
        "data-inspector-progress-value",
        "data-state-authorization",
        "data-state-scope",
        "data-state-approval",
        "data-state-active",
        'classList.add("is-open")',
    ):
        assert forbidden not in script


def test_unselected_inspector_does_not_present_zero_counts_or_pending_identity_as_data():
    inspector = _inspector()
    assert ">Not selected<" in inspector
    assert ">Select an assessment<" in inspector
    assert ">Not available<" in inspector
    assert 'aria-label="Finding count unavailable">—<' in inspector
    assert 'aria-label="Evidence count unavailable">—<' in inspector
    assert 'aria-label="Evidence-link count unavailable">—<' in inspector
    assert ">No active assessment<" not in inspector
    assert ">Pending<" not in inspector
    assert "data-inspector-findings-count>0<" not in inspector
    assert "data-inspector-artifacts-count>0<" not in inspector
    assert "data-inspector-graph-count>0<" not in inspector
